use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercusysAPIResponse<T> {
    #[serde(default)]
    pub result: T,

    #[serde(default)]
    pub error_code: i64,
    #[serde(default, rename = "msg")]
    pub error_message: i64,

    #[serde(default = "default_true")]
    pub success: bool,
}
