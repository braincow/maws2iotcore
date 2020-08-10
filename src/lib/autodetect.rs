use resolve::{DnsConfig, DnsResolver};
use resolve::record::{Srv, Txt};
use serde::Deserialize;
use std::str;
use base64::decode;
use crate::lib::error::MawsToIotCoreError;

type AutoDetectError = MawsToIotCoreError;

#[derive(Debug, Deserialize)]
pub struct RegistryConfig {
    pub project: String,
    pub name: String,
    pub region: String
}

pub struct AutoDetectedConfig {
    pub mqtt_url: String,
    pub ca_url: String,
    pub registry_config: RegistryConfig
}

impl AutoDetectedConfig {
    pub fn build(domain: &str) -> Result<AutoDetectedConfig, AutoDetectError> {
        let config = match DnsConfig::load_default() {
            Ok(config) => config,
            Err(error) => return Err(AutoDetectError::new(&format!("Unable to create DNS resolver configuration: {}", error.to_string())))
        };
        let resolver = match DnsResolver::new(config) {
            Ok(resolver) => resolver,
            Err(error) => return Err(AutoDetectError::new(&format!("Unable to create DNS resolver: {}", error.to_string())))
        };

        // query SRV record to detect IoT core broker address and port
        let mqtt_srv_record_name = format!("_mqtt._tcp.{}.", domain);
        debug!("Querying MQTT SRV record: {}", mqtt_srv_record_name);
        let mqtt_srv_record = match resolver.resolve_record::<Srv>(&mqtt_srv_record_name) {
            Ok(records) => records,
            Err(error) => return Err(AutoDetectError::new(&format!("Error on querying for '{}': {}", mqtt_srv_record_name, error.to_string())))
        };
        debug!("MQTT SRV record(s): {:?}", mqtt_srv_record);
        let mqtt_url = match mqtt_srv_record.first() {
            Some(srv) => format!("ssl://{}:{}", srv.target, srv.port),
            None => return Err(AutoDetectError::new(&format!("DNS SRV record '{}' did not resolve to a value.", mqtt_srv_record_name)))
        };

        // query TXT record to gain CA root certificates
        let ca_txt_record_name = format!("_ca.{}.", domain);
        debug!("Querying CA TXT record: {}", ca_txt_record_name);
        let ca_txt_record = match resolver.resolve_record::<Txt>(&ca_txt_record_name) {
            Ok(records) => records,
            Err(error) => return Err(AutoDetectError::new(&format!("Error on querying for '{}': {}", ca_txt_record_name, error.to_string())))
        };
        debug!("CA TXT record(s): {:?}", ca_txt_record);
        let ca_url: String = match ca_txt_record.first() {
            Some(ca) => str::from_utf8(&ca.data).unwrap().to_string(),
            None => return Err(AutoDetectError::new(&format!("DNS TXT record '{}' did not resolve to a value.", mqtt_srv_record_name)))
        };

        // query TXT record for JSON payload that explains location of IoT core registry
        let registry_txt_record_name = format!("_registry.{}.", domain);
        debug!("Querying REGISTRY TXT record: {}", registry_txt_record_name);
        let registry_txt_record = match resolver.resolve_record::<Txt>(&registry_txt_record_name) {
            Ok(records) => records,
            Err(error) => return Err(AutoDetectError::new(&format!("Error on querying for '{}': {}", registry_txt_record_name, error.to_string())))
        };
        debug!("REGISTRY TXT record(s): {:?}", registry_txt_record);
        let mut registry_config_data: String = match registry_txt_record.first() {
            Some(registry) => str::from_utf8(&registry.data).unwrap().to_string(),
            None => return Err(AutoDetectError::new(&format!("DNS TXT record '{}' did not resolve to a value.", mqtt_srv_record_name)))
        };
        debug!("BASE64 encoded REGISTRY TXT record: {:?}", registry_config_data);
        registry_config_data = match decode(&registry_config_data) {
            Ok(data) => str::from_utf8(&data).unwrap().to_string(),
            Err(error) => return Err(AutoDetectError::new(&format!("Error while base64 decoding registry configuration: {}", error.to_string())))
        };
        debug!("BASE64 decoded REGISTRY TXT record: {:?}", registry_config_data);
        let registry_config: RegistryConfig = match serde_json::from_str(&registry_config_data) {
            Ok(config) => config,
            Err(error) => return Err(AutoDetectError::new(&format!("Error while deserializing registry configuration: {}", error.to_string())))
        };

        Ok(AutoDetectedConfig{
            mqtt_url: mqtt_url,
            ca_url: ca_url,
            registry_config: registry_config
        })
    }
}

// eof