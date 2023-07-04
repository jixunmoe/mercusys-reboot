use std::str;

use base64::{engine::general_purpose, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{
    aes::{aes_128_cbc_decrypt, aes_128_cbc_encrypt},
    rsa_encrypt,
};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedPayload {
    sign: String,
    data: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadManager {
    logging_enabled: bool,

    /// Sequence number, like a nonce?
    /// Provided by the router.
    seq: i64,

    /// md5(username + password)
    hash: String,

    // Sign/crypto related
    rsa_key_n: String,
    rsa_key_e: String,
    aes_key: String,
    aes_iv: String,
}

impl PayloadManager {
    pub fn new() -> Self {
        PayloadManager {
            logging_enabled: false,

            seq: 0,
            aes_key: "".into(),
            aes_iv: "".into(),
            hash: "".into(), // md5(username + password)
            rsa_key_e: "".into(),
            rsa_key_n: "".into(),
        }
    }

    pub fn set_logging_enabled(&mut self, enabled: bool) {
        self.logging_enabled = enabled;
    }

    pub fn gen_aes_key(&mut self) {
        // Server side issue:
        //   If `AES_KEY_MAX` is greater or equal to 5999_9999_9999_9999, the
        //   router will refuse and terminate with "403 Forbidden".
        const AES_KEY_MIN: u64 = 1000_0000_0000_0000_u64;
        const AES_KEY_MAX: u64 = 5999_9999_9999_9998_u64;

        if cfg!(feature = "no_rand") {
            self.aes_key = format!("{}", AES_KEY_MAX);
            self.aes_iv = format!("{}", AES_KEY_MAX);
        } else {
            use rand::Rng;

            let mut rng = rand::thread_rng();
            let digits_range = AES_KEY_MIN..=AES_KEY_MAX;
            self.aes_key = format!("{}", rng.gen_range(digits_range.clone()));
            self.aes_iv = format!("{}", rng.gen_range(digits_range));
        }
    }

    #[allow(dead_code)]
    pub fn set_aes_key(&mut self, aes_key: &str, aes_iv: &str) {
        self.aes_key = aes_key.into();
        self.aes_iv = aes_iv.into();
    }

    pub fn set_rsa_key(&mut self, rsa_n: &str, rsa_e: &str) {
        self.rsa_key_n = rsa_n.into();
        self.rsa_key_e = rsa_e.into();
    }

    pub fn set_seq(&mut self, seq: i64) {
        self.seq = seq;
    }

    pub fn set_hash(&mut self, hash: &str) {
        self.hash = hash.into();
    }

    pub fn set_login_hash(&mut self, username: &str, password: &str) {
        let digest = md5::compute(format!("{}{}", username, password).as_bytes());
        self.set_hash(format!("{:x}", digest).as_str());
    }

    pub fn sign(&self, data_len: i64, is_login: bool) -> String {
        // Login payload require aes key to be part of the signature.
        // Other payload does not, but it seems to work as well.
        // Just following what the client JavaScript was doing here...
        let r = if is_login {
            format!(
                "k={}&i={}&h={}&s={}",
                self.aes_key,
                self.aes_iv,
                self.hash,
                data_len + self.seq
            )
        } else {
            format!("h={}&s={}", self.hash, data_len + self.seq)
        };

        return r
            .chars()
            .collect::<Vec<char>>()
            .chunks(53)
            .map(|chunk| {
                rsa_encrypt(
                    chunk.iter().collect::<String>().as_str(),
                    &self.rsa_key_n,
                    &self.rsa_key_e,
                )
            })
            .collect::<String>();
    }

    pub fn encrypt_payload(&self, payload: &str, is_login: bool) -> SignedPayload {
        let data = aes_128_cbc_encrypt(payload, &self.aes_key, &self.aes_iv);
        let data = general_purpose::STANDARD.encode(data);

        let sign = self.sign(data.as_bytes().len() as i64, is_login);

        SignedPayload { data, sign }
    }

    #[inline]
    pub fn encrypt_payload_json<T: Serialize + ?Sized>(
        &self,
        payload: &T,
        is_login: bool,
    ) -> SignedPayload {
        self.encrypt_payload(serde_json::to_string(payload).unwrap().as_str(), is_login)
    }

    pub fn decrypt_response<T: DeserializeOwned>(&self, data: &str) -> Option<T> {
        let data = general_purpose::STANDARD.decode(data).ok()?;
        let data = aes_128_cbc_decrypt(data, &self.aes_key, &self.aes_iv);
        if self.logging_enabled {
            eprintln!("resp: {}", str::from_utf8(&data).unwrap());
        }
        serde_json::from_slice::<T>(&data).ok()
    }
}

#[cfg(test)]
fn make_dummy_pm() -> PayloadManager {
    let mut pm = PayloadManager::new();
    pm.set_seq(12345);
    pm.aes_key = "1111111111111111".into();
    pm.aes_iv = "2222222222222222".into();
    pm.set_login_hash("admin", "$3cr3T");
    pm.set_rsa_key("C4E3F7212602E1E396C0B6623CF11D26204ACE3E7D26685E037AD2507DCE82FC28F2D5F8A67FC3AFAB89A6D818D1F4C28CFA548418BD9F8E7426789A67E73E41", "010001");
    pm
}

#[test]
fn sign_test() {
    let pm = make_dummy_pm();

    let expected = "3b1dd868a55bfef12ffab063b6c20bcf736f96145c1c9017e8614cc9a391c1d9bf2b3ccbe7e5aaa5e84fbcaff0eca073b516c7ca4f6060ec7363992586d74dc294d049ba4e939dd81229108468c5182411f655f2fc8019807d062090c74861fb1837fb6473a775918bf1c3a19ecb404d88bea74c91cee1e738360b9e06f1a723";
    let actual = pm.sign(pm.seq, true);

    assert_eq!(expected, actual);
}

#[test]
fn encrypt_payload_test() {
    let pm = make_dummy_pm();

    let expected = SignedPayload {
        data: "GXrwa96SCV1LMFAIwt+tQ/HSp8/w1WuMG2mtXxMH5mE=".into(),
        sign: "3b1dd868a55bfef12ffab063b6c20bcf736f96145c1c9017e8614cc9a391c1d9bf2b3ccbe7e5aaa5e84fbcaff0eca073b516c7ca4f6060ec7363992586d74dc2341bfb9552e88fb75cd6331bab49f314d71afc58d9d9b7ff712f664c720a32d34d9378bceb6d0687f239147880652785128936c6766158d3fd4ee039c45c1488".into(),
    };
    let actual = pm.encrypt_payload(r#"{"hello":"world"}"#, true);

    assert_eq!(expected, actual);
}
