use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use crate::lib::iotcore::IotCoreTopicTypeKind;

#[derive(Debug, Serialize, Deserialize)]
pub struct SerialConfig {
    pub port: String
}

#[derive(Debug, Serialize, Deserialize)]
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

    pub fn as_iotcore_client_topic(&self, msgtype: IotCoreTopicTypeKind, subfolder: Option<String>) -> String {
        let topic = format!("/devices/{}/{}", self.device_id, msgtype.value(subfolder));
        topic
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub serial: SerialConfig,
    pub iotcore: IotCoreConfig
}

impl AppConfig {
    pub fn build(deviceid: &str, port: &str, cafile: &Path, prikey: &Path, project_id: &str, registry_name: &str, registry_region: &str) -> AppConfig {
        AppConfig {
            serial: SerialConfig {
                port: port.to_string()
            },
            iotcore: IotCoreConfig {
                device_id: deviceid.to_string(),
                private_key: prikey.display().to_string(),
                project_id: project_id.to_string(),
                registry_name: registry_name.to_string(),
                registry_region: registry_region.to_string(),
                ca_certs: cafile.display().to_string(),
                token_lifetime: 3600
            }
        }
    }

    pub fn read_config(config_file_path: &str) -> Result<AppConfig, std::io::Error> {
        // read the config file
        info!("Using config file: {}", config_file_path);
        let config_toml = fs::read_to_string(config_file_path)?;
        let config: AppConfig = toml::from_str(&config_toml)?;
    
        Ok(config)
    }

    pub fn write_config(&self, config_file_path: &Path) -> Result<(), std::io::Error> {
        debug!("Writing new config file: {}", config_file_path.display());
        fs::write(config_file_path, toml::to_string(&self).unwrap())?;
        Ok(())
    }
}

// eof
