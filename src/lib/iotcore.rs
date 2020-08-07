#![feature(async_closure)]

use actix::prelude::*;
use std::path::Path;
use paho_mqtt as mqtt;
use serde::Deserialize;
use std::error::Error;
use std::{str, fmt};
use actix::Addr;
use crate::lib::config::AppConfig;
use crate::lib::jwt::IotCoreAuthToken;
use crate::lib::maws::MAWSMessageKind;
use crate::lib::logger::LoggerActor;

#[derive(Debug, Deserialize)]
struct IotCoreCommand {
    command: String
}

#[derive(Debug, Deserialize)]
struct IotCoreSerialConfig {
    port: String
}

#[derive(Debug, Deserialize)]
struct IotCoreTCPConfig {
    host: String,
    port: u64
}

#[derive(Debug, Deserialize)]
struct IotCorePropertiesConfig {
    relay_messages: Vec<String>
}

#[derive(Debug, Deserialize)]
struct IotCoreLoggerConfig {
    r#type: String,
    serial: IotCoreSerialConfig,
    tcp: IotCoreTCPConfig,
    autostart: bool
}

#[derive(Debug, Deserialize)]
struct IotCoreConfig {
    logger: IotCoreLoggerConfig,
    iotcore: IotCorePropertiesConfig
}

#[derive(Debug)]
pub enum IotCoreCNCMessageKind {
    CONFIG(IotCoreConfig),
    COMMAND(IotCoreCommand)
}

impl IotCoreCNCMessageKind {
    pub fn parse_from_mqtt_message(message: &paho_mqtt::message::Message) -> Result<IotCoreCNCMessageKind, serde_json::Error> {
        let parsed: IotCoreConfig = serde_json::from_str(&message.payload_str().to_string())?;
        Ok(IotCoreCNCMessageKind::CONFIG(parsed))
    }
}

impl Message for IotCoreCNCMessageKind {
    type Result = bool;
}

impl IotCoreConfig {
    fn from_json_string(json_string: String) -> Result<IotCoreConfig, serde_json::Error> {
        let config: IotCoreConfig = serde_json::from_str(&json_string)?;
        Ok(config)
    }
}

#[derive(Debug)]
pub struct IotCoreTopicError {
    details: String
}

impl IotCoreTopicError {
    fn new(msg: &str) -> IotCoreTopicError {
        IotCoreTopicError {
            details: msg.to_string()
        }
    }
}

impl fmt::Display for IotCoreTopicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for IotCoreTopicError {
    fn description(&self) -> &str {
        &self.details
    }
}

pub enum IotCoreTopicType {
    EVENT,
    CONFIG,
    COMMAND
}

impl IotCoreTopicType {
    pub fn value(&self) -> String {
        match *self {
            IotCoreTopicType::EVENT => "events".to_string(),
            IotCoreTopicType::CONFIG => "config".to_string(),
            IotCoreTopicType::COMMAND => "commands/#".to_string()
        }
    }

    pub fn from_str(source_string: &String) -> Result<IotCoreTopicType, IotCoreTopicError> {
        let string_parts = source_string.split("/").into_iter().map(|x| x.trim()).collect::<Vec<&str>>();

        if string_parts.len() != 4 {
            // expecting splitted string to be of length four
            return Err(IotCoreTopicError::new("Unable to properly split the topic string."))
        }

        if IotCoreTopicType::EVENT.value() == string_parts[3] {
            return Ok(IotCoreTopicType::EVENT)
        } else if IotCoreTopicType::CONFIG.value() == string_parts[3] {
            return Ok(IotCoreTopicType::CONFIG)
        } else if IotCoreTopicType::COMMAND.value() == string_parts[3] {
            return Ok(IotCoreTopicType::COMMAND)
        } else {
            return Err(IotCoreTopicError::new("Unrecognized topic in input string."))
        }
    }

    pub fn from_message(message: &paho_mqtt::message::Message) -> Result<IotCoreTopicType, IotCoreTopicError> {
        Ok(IotCoreTopicType::from_str(&message.topic().to_string())?)
    }
}

pub struct IotCoreClient {
    subscribe_to_topics: [String; 2],
    ssl_opts: mqtt::SslOptions,
    conn_opts: mqtt::ConnectOptions,
    client: mqtt::async_client::AsyncClient,
    jwt_token_factory: IotCoreAuthToken,
    logger_addr: Addr<LoggerActor>
}

impl IotCoreClient {
    pub fn build(config: &AppConfig, logger: Addr<LoggerActor>) -> Result<IotCoreClient, Box<dyn std::error::Error>> {
        let create_opts = mqtt::CreateOptionsBuilder::new()
            .client_id(config.iotcore.as_iotcore_client_id())
            .mqtt_version(mqtt::types::MQTT_VERSION_3_1_1)
            .server_uri("ssl://mqtt.googleapis.com:8883")
            .persistence(mqtt::PersistenceType::None)
            .finalize();

        let cli = mqtt::AsyncClient::new(create_opts)?;

        let ssl_options = match mqtt::SslOptionsBuilder::new()
            .ssl_version(mqtt::SslVersion::Tls_1_2)
            .trust_store(Path::new(&config.iotcore.ca_certs).to_path_buf()) {
                Ok(options) => options.finalize(),
                Err(error) => return Err(Box::new(error))
        };

        let jwt_token_factory = IotCoreAuthToken::build(&config);
        let jwt_token = jwt_token_factory.issue_new()?;
        let conn_opts = mqtt::ConnectOptionsBuilder::new()
            .user_name("not_used")
            .password(jwt_token)
            .ssl_options(ssl_options.clone())
            .finalize();

        let subscribe_to_topics = [ config.iotcore.as_iotcore_client_topic(IotCoreTopicType::CONFIG), config.iotcore.as_iotcore_client_topic(IotCoreTopicType::COMMAND) ];

        Ok(IotCoreClient {
            ssl_opts: ssl_options,
            conn_opts: conn_opts,
            client: cli,
            jwt_token_factory: jwt_token_factory,
            subscribe_to_topics: subscribe_to_topics,
            logger_addr: logger
        })
    }
/*
    fn parse_cnc_message(&self, msg: mqtt::Message) {

    }
*/
    async fn subscribe(&mut self) -> Result<(), mqtt::Error> {
        // note the array of QOS arguments, there is one QOS for each subscribed topic. in our case two
        trace!("Subscribing to command and control channels in IoT core service");
        self.client.subscribe_many(&self.subscribe_to_topics, &[ mqtt::QOS_1, mqtt::QOS_1] ).await?;

        let logger_addr = self.logger_addr.clone();

        self.client.set_message_callback(async move |_cli, msg| {
            debug!("{:?}", msg);
            match msg {
                Some(msg) => {
                    // so far only config is implemented
                    logger_addr.send(IotCoreCNCMessageKind::parse_from_mqtt_message(&msg).unwrap()).await;
                },
                None => {}
            }
        }.await);

        Ok(())
    }

    pub async fn connect(&mut self) -> Result<(), mqtt::Error> {
        // connect
        self.client.connect(self.conn_opts.clone()).await?;
        info!("Connected to IoT core service");

        self.subscribe().await?;

        Ok(())
    }

    pub async fn disconnect(&self) -> Result<(), mqtt::Error> {
        if self.client.is_connected() {
            self.client.disconnect(None);
            info!("Disconnected from IoT core service");
        } else {
            debug!("Iot Core MQTT client is not connected. Skipping disconnect.");
        }

        Ok(())
    }

    async fn rebuild(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.disconnect().await?; // disconnect first if there is a connection open

        let jwt_token = self.jwt_token_factory.renew()?;

        self.conn_opts = mqtt::ConnectOptionsBuilder::new()
            .user_name("not_used")
            .password(jwt_token)
            .ssl_options(self.ssl_opts.clone())
            .finalize();

        Ok(())
    }

    pub async fn send_message(&mut self, topic: &String, message: &MAWSMessageKind, qos: i32) -> Result<(), Box<dyn std::error::Error>> {
        let mqtt_msg = mqtt::Message::new(topic, message.as_json(), qos);

        if !self.jwt_token_factory.is_valid(60) || !self.client.is_connected() {
            warn!("JWT token has/is about to expire or we have no connection. Initiating reconnect.");
            self.rebuild().await?;
            self.connect().await?; // and connect after updating the conn_opts structure. (we have a new jwt token essentially)
        }

        self.client.publish(mqtt_msg).await?;
        Ok(())
    }
}

// eof
