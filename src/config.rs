use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct SerialConfig {
    pub port: String
}

#[derive(Debug, Deserialize)]
pub struct IotCoreConfig {
    pub device_id: String,
    pub private_key: String,
    pub project_id: String,
    pub registry_name: String,
    pub registry_region: String,
    pub ca_certs: String,
    pub token_lifetime: u64
}

impl IotCoreConfig {
    pub fn as_iotcore_client_id(&self) -> String {
        let client_id = format!("projects/{}/locations/{}/registries/{}/devices/{}",
            self.project_id,
            self.registry_region,
            self.registry_name,
            self.device_id);
        
        client_id
    }

    pub fn as_iotcore_client_topic(&self) -> String {
        let topic = format!("/devices/{}/events", self.device_id);

        topic
    }
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub serial: SerialConfig,
    pub iotcore: IotCoreConfig
}

pub fn read_config(config_file_path: &str) -> Result<AppConfig, std::io::Error> {
    // read the config file
    info!("Using config file: {}", config_file_path);
    let config_toml = fs::read_to_string(config_file_path)?;
    let config: AppConfig = toml::from_str(&config_toml)?;

    Ok(config)
}

// eof
