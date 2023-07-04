use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogoutResponse {
    #[serde(default)]
    pub success: bool,
}
