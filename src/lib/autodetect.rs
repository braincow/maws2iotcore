use resolve::{DnsConfig, DnsResolver};
use resolve::record::{Srv, Txt};
use serde::Deserialize;
use std::str;
use base64::decode;
use std::{net::SocketAddr, net::ToSocketAddrs};
use crate::lib::error::MawsToIotCoreError;

type AutoDetectedConfigError = MawsToIotCoreError;

#[derive(Debug)]
struct MqttServiceInfo {
    hostname: String,
    port: u16
}

#[derive(Debug, Deserialize)]
pub struct RegistryConfig {
    pub project: String,
    pub name: String,
    pub region: String
}

pub struct AutoDetectedConfig {
    pub mqtt_sockaddr: SocketAddr,
    pub mqtt_hostname: String,
    pub mqtt_port: u16,
    pub ca_url: String,
    pub registry_config: RegistryConfig
}

impl AutoDetectedConfig {
    pub fn as_iotcore_client_id(&self, device_id: &String) -> String {
        let client_id = format!("projects/{}/locations/{}/registries/{}/devices/{}",
            self.registry_config.project,
            self.registry_config.region,
            self.registry_config.name,
            device_id);
        
        client_id
    }

    pub fn build(domain: &str) -> Result<AutoDetectedConfig, AutoDetectedConfigError> {
        let config = match DnsConfig::load_default() {
            Ok(config) => config,
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Unable to create DNS resolver configuration: {}", error.to_string())))
        };
        let resolver = match DnsResolver::new(config) {
            Ok(resolver) => resolver,
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Unable to create DNS resolver: {}", error.to_string())))
        };

        // query SRV record to detect IoT core broker address and port
        let mqtt_srv_record_name = format!("_mqtt._tcp.{}.", domain);
        debug!("Querying MQTT SRV record: {}", mqtt_srv_record_name);
        let mqtt_srv_record = match resolver.resolve_record::<Srv>(&mqtt_srv_record_name) {
            Ok(records) => records,
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Error on querying for '{}': {}", mqtt_srv_record_name, error.to_string())))
        };
        debug!("MQTT SRV record(s): {:?}", mqtt_srv_record);
        let mqtt_info = match mqtt_srv_record.first() {
            Some(srv) => MqttServiceInfo {hostname: srv.target.trim_end_matches(".").to_string(), port: srv.port},
            None => return Err(AutoDetectedConfigError::new(&format!("DNS SRV record '{}' did not resolve to a value.", mqtt_srv_record_name)))
        };
        let mqtt_sockaddr: SocketAddr = match format!("{}:{}", mqtt_info.hostname, mqtt_info.port).to_socket_addrs() {
            Ok(addr) => addr.clone().next().unwrap(),
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Error while creating socket address from '{:?}': {}", mqtt_info, error)))
        };

        // query TXT record to gain CA root certificates
        let ca_txt_record_name = format!("_ca.{}.", domain);
        debug!("Querying CA TXT record: {}", ca_txt_record_name);
        let ca_txt_record = match resolver.resolve_record::<Txt>(&ca_txt_record_name) {
            Ok(records) => records,
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Error on querying for '{}': {}", ca_txt_record_name, error.to_string())))
        };
        debug!("CA TXT record(s): {:?}", ca_txt_record);
        let ca_url: String = match ca_txt_record.first() {
            Some(ca) => str::from_utf8(&ca.data).unwrap().to_string(),
            None => return Err(AutoDetectedConfigError::new(&format!("DNS TXT record '{}' did not resolve to a value.", mqtt_srv_record_name)))
        };

        // query TXT record for JSON payload that explains location of IoT core registry
        let registry_txt_record_name = format!("_registry.{}.", domain);
        debug!("Querying REGISTRY TXT record: {}", registry_txt_record_name);
        let registry_txt_record = match resolver.resolve_record::<Txt>(&registry_txt_record_name) {
            Ok(records) => records,
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Error on querying for '{}': {}", registry_txt_record_name, error.to_string())))
        };
        debug!("REGISTRY TXT record(s): {:?}", registry_txt_record);
        let mut registry_config_data: String = match registry_txt_record.first() {
            Some(registry) => str::from_utf8(&registry.data).unwrap().to_string(),
            None => return Err(AutoDetectedConfigError::new(&format!("DNS TXT record '{}' did not resolve to a value.", mqtt_srv_record_name)))
        };
        debug!("BASE64 encoded REGISTRY TXT record: {:?}", registry_config_data);
        registry_config_data = match decode(&registry_config_data) {
            Ok(data) => str::from_utf8(&data).unwrap().to_string(),
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Error while base64 decoding registry configuration: {}", error.to_string())))
        };
        debug!("BASE64 decoded REGISTRY TXT record: {:?}", registry_config_data);
        let registry_config: RegistryConfig = match serde_json::from_str(&registry_config_data) {
            Ok(config) => config,
            Err(error) => return Err(AutoDetectedConfigError::new(&format!("Error while deserializing registry configuration: {}", error.to_string())))
        };

        Ok(AutoDetectedConfig{
            mqtt_sockaddr: mqtt_sockaddr,
            mqtt_hostname: mqtt_info.hostname,
            mqtt_port: mqtt_info.port,
            ca_url: ca_url,
            registry_config: registry_config
        })
    }
}

// eof