use serde::{Deserialize, Serialize};

use super::api_response::MercusysAPIResponse;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercusysEncryptedResponse {
    #[serde(default)]
    pub data: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginKeysRespResult {
    #[serde(default)]
    pub username: String,

    #[serde(default)]
    pub password: Vec<String>, // [rsa_n, rsa_e]
}
pub type LoginKeysResp = MercusysAPIResponse<LoginKeysRespResult>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthKeysRespResult {
    #[serde(default)]
    pub key: Vec<String>,

    #[serde(default)]
    pub seq: i64,
}
pub type AuthKeysResp = MercusysAPIResponse<AuthKeysRespResult>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginRespResult {
    #[serde(default)]
    pub stok: String,
}
pub type LoginResp = MercusysAPIResponse<LoginRespResult>;
