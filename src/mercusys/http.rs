use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{cookie::Jar, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;

use super::api_device_list::DeviceListResponse;
use super::api_login_keys::{AuthKeysResp, LoginKeysResp, LoginResp, MercusysEncryptedResponse};
use super::api_logout::LogoutResponse;
use super::api_reboot::{RebootMacAddress, RebootRequestBody, RebootResponse};
use super::crypto::{rsa_encrypt, PayloadManager};

pub struct MercusysHTTP {
    logging_enabled: bool,

    client: Client,
    base_url: Url,
    pub stok: String,
    pub session: PayloadManager,
}

impl MercusysHTTP {
    pub fn new(base_url: Url) -> MercusysHTTP {
        use reqwest::header;
        let mut headers = header::HeaderMap::new();
        let referrer = base_url.join("/webpages/index.html").unwrap().to_string();
        headers.insert(
            "Referer",
            header::HeaderValue::from_str(referrer.as_str()).unwrap(),
        );
        headers.insert(
            "X-Requested-With",
            header::HeaderValue::from_static("XMLHttpRequest"),
        );

        let builder = Client::builder()
            .user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0")
            .default_headers(headers)
            .cookie_provider(Jar::default().into());

        MercusysHTTP {
            base_url,
            logging_enabled: false,
            client: builder.build().unwrap(),
            stok: "".into(),
            session: PayloadManager::new(),
        }
    }

    pub fn set_logging_enabled(&mut self, enabled: bool) {
        self.logging_enabled = enabled;
        self.session.set_logging_enabled(enabled);
    }

    pub fn req<T: Serialize + ?Sized>(
        &mut self,
        path: &str,
        form: &str,
        data: &T,
    ) -> Result<Response, reqwest::Error> {
        let path = format!("/cgi-bin/luci/;stok={}{}", self.stok, path);
        let mut url = self.base_url.join(path.as_str()).unwrap();
        url.query_pairs_mut().append_pair("form", form);
        self.client.post(url).json(&data).send()
    }

    pub fn req_encrypted<R: DeserializeOwned, T: Serialize + ?Sized>(
        &mut self,
        path: &str,
        form: &str,
        data: &T,
    ) -> Result<R, reqwest::Error> {
        let path = format!("/cgi-bin/luci/;stok={}{}", self.stok, path);
        let mut url = self.base_url.join(path.as_str()).unwrap();
        url.query_pairs_mut().append_pair("form", form);

        if self.logging_enabled {
            eprintln!("req data: {}", serde_json::to_string(&data).unwrap());
        }

        // There should be a better way to check if we are logging in,
        //   but it works... so whatever...
        let is_login_request = form == "login";

        let response = self
            .client
            .post(url)
            // Yes we are posting form data.
            .form(&self.session.encrypt_payload_json(data, is_login_request))
            // ... with content-type application/json.
            .headers({
                let mut headers = HeaderMap::new();
                headers.insert("Content-Type", HeaderValue::from_static("application/json"));
                headers
            })
            .send()?;

        let data = {
            let response_data = response.json::<MercusysEncryptedResponse>()?;

            self.session
                .decrypt_response::<R>(response_data.data.as_str())
                .unwrap() // FIXME: handle error gracefully
        };

        Ok(data)
    }

    /// Use "admin" for username if unsure.
    pub fn login(&mut self, username: &str, password: &str) {
        self.session = PayloadManager::new();
        self.session.set_logging_enabled(self.logging_enabled);
        self.session.gen_aes_key();
        self.session.set_login_hash(username, password);

        let encrypted_password = {
            let password_key_resp = self
                .req("/login", "keys", &json!({"operation":"read"}))
                .unwrap()
                .json::<LoginKeysResp>()
                .unwrap();

            let rsa_n = password_key_resp.result.password[0].as_str();
            let rsa_e = password_key_resp.result.password[1].as_str();
            rsa_encrypt(password, rsa_n, rsa_e)
        };

        {
            let auth_key_resp = self
                .req("/login", "auth", &json!({"operation":"read"}))
                .unwrap()
                .json::<AuthKeysResp>()
                .unwrap();

            self.session.set_seq(auth_key_resp.result.seq);

            let session_rsa_n = auth_key_resp.result.key[0].as_str();
            let session_rsa_e = auth_key_resp.result.key[1].as_str();
            self.session.set_rsa_key(session_rsa_n, session_rsa_e);
        }

        // Now we can login...
        let login_result: LoginResp = self
            .req_encrypted(
                "/login",
                "login",
                &json!({
                    "params":{
                        "password": encrypted_password
                    },
                    "operation":"login"
                }),
            )
            .unwrap();
        self.stok = login_result.result.stok;
    }

    pub fn get_device_list(&mut self) -> DeviceListResponse {
        self.req_encrypted("/admin/device", "device_list", &json!({"operation":"read"}))
            .unwrap()
    }

    pub fn reboot_whole_mesh(&mut self) -> RebootResponse {
        let devices = self.get_device_list();

        let macs: Vec<RebootMacAddress> = devices
            .result
            .device_list
            .iter()
            .map(|device| RebootMacAddress {
                mac: device.mac.clone(),
            })
            .collect();
        let body = RebootRequestBody {
            params: super::api_reboot::RebootRequestParam {
                mac_address_list: macs,
            },
            operation: "reboot".into(),
        };

        self.req_encrypted("/admin/device", "system", &body)
            .unwrap()
    }

    pub fn logout(&mut self) -> bool {
        let resp: LogoutResponse = self
            .req_encrypted("/admin/system", "logout", &json!({"operation":"logout"}))
            .unwrap();

        if resp.success {
            self.stok = "".into();
            self.session = PayloadManager::new();
            self.session.set_logging_enabled(self.logging_enabled);
        }

        resp.success
    }
}
