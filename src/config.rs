use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default = "default_buffer_offset")]
    pub buffer_offset: usize,
    #[serde(default = "default_queue_size")]
    pub queue_size: usize,
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,
    #[serde(default)]
    pub services: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub protocol_detectors: HashMap<String, ProtocolDefinition>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub api: ApiConfig,
}

fn default_buffer_size() -> usize {
    1500
}

fn default_buffer_offset() -> usize {
    64
}

fn default_queue_size() -> usize {
    10240
}

fn default_worker_count() -> usize {
    4
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_output", rename = "output_path")]
    pub _output_path: String,
    #[serde(default, rename = "caller")]
    pub _caller: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "console".to_string()
}

fn default_output() -> String {
    "stdout".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub h5_files_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComponentConfig {
    #[serde(default, rename = "type")]
    pub _type: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default)]
    pub timeout: u64,
    #[serde(default)]
    pub replace_old_mapping: bool,
    #[serde(default)]
    pub forwarders: Vec<String>,
    #[serde(default)]
    pub reconnect_interval: u64,
    #[serde(default)]
    pub connection_check_time: u64,
    #[serde(default)]
    pub detour: Vec<String>,
    #[serde(default)]
    pub send_keepalive: Option<bool>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub broadcast_mode: Option<bool>,
    #[serde(default)]
    pub no_delay: Option<bool>,
    #[serde(default)]
    pub send_timeout: u64,
    #[serde(default)]
    pub recv_buffer_size: usize,
    #[serde(default)]
    pub send_buffer_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterComponentConfig {
    #[serde(default, rename = "type")]
    pub _type: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub detour: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub detour_miss: Vec<String>,
    #[serde(default)]
    pub use_proto_detectors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoadBalancerDetourRule {
    pub rule: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoadBalancerComponentConfig {
    #[serde(default, rename = "type")]
    pub _type: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub detour: Vec<LoadBalancerDetourRule>,
    #[serde(default)]
    pub miss: Vec<String>,
    #[serde(default = "default_window_size")]
    pub window_size: u32,
    #[serde(default, rename = "enable_cache")]
    pub _enable_cache: bool,
}

fn default_window_size() -> u32 {
    10
}

#[derive(Debug, Clone, Deserialize)]
pub struct IPRouteComponentConfig {
    #[serde(default, rename = "type")]
    pub _type: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub rules: Vec<LoadBalancerDetourRule>,
    #[serde(default)]
    pub detour_miss: Vec<String>,
    #[serde(default)]
    pub geoip_mmdb: String,
    #[serde(default)]
    pub geoip_url: String,
    #[serde(default)]
    pub geoip_update_interval: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub enable_encryption: bool,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
    #[serde(default = "default_auth_timeout")]
    pub auth_timeout: u64,
    #[serde(default = "default_delay_window")]
    pub delay_window_size: usize,
}

fn default_heartbeat_interval() -> u64 {
    30
}

fn default_auth_timeout() -> u64 {
    30
}

fn default_delay_window() -> usize {
    10
}

#[derive(Debug, Clone, Deserialize)]
pub struct LengthMatch {
    #[serde(default)]
    pub min: usize,
    #[serde(default)]
    pub max: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignatureRule {
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub bytes: String,
    #[serde(default)]
    pub mask: String,
    #[serde(default)]
    pub contains: String,
    #[serde(default)]
    pub hex: bool,
    #[serde(default)]
    pub length: Option<LengthMatch>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolDefinition {
    #[serde(default)]
    pub signatures: Vec<SignatureRule>,
    #[serde(default)]
    pub match_logic: String,
    #[serde(default, rename = "description")]
    pub _description: String,
    #[serde(default, rename = "priority")]
    pub _priority: i32,
}
