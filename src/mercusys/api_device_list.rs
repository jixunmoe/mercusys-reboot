use serde::{Deserialize, Serialize};

use super::api_response::MercusysAPIResponse;

pub type DeviceListResponse = MercusysAPIResponse<DeviceListResult>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceListResult {
    #[serde(default)]
    pub device_list: Vec<SingleDeviceItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SingleDeviceItem {
    #[serde(default)]
    pub nand_flash: bool,
    #[serde(default)]
    pub owner_transfer: Option<bool>,
    #[serde(default)]
    pub device_ip: String,
    #[serde(default)]
    pub previous: String,
    #[serde(default)]
    pub bssid_5g: String,
    #[serde(default)]
    pub parent_device_id: Option<String>,
    #[serde(default)]
    pub software_ver: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub bssid_sta_5g: String,
    #[serde(default)]
    pub bssid_2g: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub product_level: i64,
    #[serde(default)]
    pub hardware_ver: String,
    #[serde(default)]
    pub inet_status: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub oem_id: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub set_gateway_support: bool,
    #[serde(default)]
    pub inet_error_msg: String,
    #[serde(default)]
    pub connection_type: Option<Vec<String>>,
    #[serde(default)]
    pub bssid_sta_2g: String,
    #[serde(default)]
    pub support_plc: bool,
    #[serde(default)]
    pub group_status: String,
    #[serde(default)]
    pub port_count: Option<i64>,
    #[serde(default)]
    pub signal_level: SignalLevel,
    #[serde(default)]
    pub device_model: String,
    #[serde(default)]
    pub oversized_firmware: bool,
    #[serde(default)]
    pub speed_get_support: Option<bool>,
    #[serde(default)]
    pub hw_id: String,
    #[serde(default)]
    pub device_type: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalLevel {
    #[serde(default)]
    pub band2_4: String,
    #[serde(default)]
    pub band5: String,
}
