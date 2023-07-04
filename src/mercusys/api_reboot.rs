use serde::{Deserialize, Serialize};

use super::api_response::MercusysAPIResponse;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RebootRequestBody {
    pub params: RebootRequestParam,

    /// Always "reboot"
    pub operation: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RebootRequestParam {
    #[serde(rename = "mac_list")]
    pub mac_address_list: Vec<RebootMacAddress>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RebootMacAddress {
    pub mac: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RebootResponseResult {
    #[serde(default)]
    pub reboot_time: i64,
}
pub type RebootResponse = MercusysAPIResponse<RebootResponseResult>;
