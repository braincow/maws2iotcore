use actix::prelude::*;
use actix_mqtt_client::{QualityOfService, PublishMessage, ErrorMessage, MqttClient, MqttOptions};
use tokio::io::split;
use tokio::net::TcpStream;
use native_tls::TlsConnector;
use tokio::time::{delay_until, Instant};
use std::{
    str,
    time::Duration,
    path::Path
};
use serde::Deserialize;
use addr::Email;
use crate::lib::logger::LoggerActor;
use crate::lib::autodetect::AutoDetectedConfig;
use crate::lib::error::MawsToIotCoreError;
use crate::lib::jwt::IotCoreAuthToken;

// ------------------------- IoT Core CNC message types ------------------------- //

#[derive(Debug, Deserialize)]
pub struct IotCoreCommand {
    command: String
}

impl IotCoreCommand {
    fn from_json_string(json_string: &String) -> Result<IotCoreCommand, serde_json::Error> {
        let command: IotCoreCommand = serde_json::from_str(&json_string)?;
        Ok(command)
    }
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
pub struct IotCoreConfig {
    logger: IotCoreLoggerConfig,
    iotcore: IotCorePropertiesConfig
}

#[derive(Debug)]
pub enum IotCoreCNCMessageKind {
    CONFIG(IotCoreConfig),
    COMMAND(IotCoreCommand)
}

impl IotCoreCNCMessageKind {
    pub fn parse_from_mqtt_message(message: &PublishMessage) -> Result<Option<IotCoreCNCMessageKind>, IotCoreCNCMessageError> {
        let mut parsed = None;

        let topic = match IotCoreTopicTypeKind::from_str(&message.topic_name) {
            Ok(topic) => topic,
            Err(error) => return Err(IotCoreCNCMessageError::new(&format!("Error while parsing CNC config messages topic '{}': {}", message.topic_name, error)))
        };

        let payload_string = match str::from_utf8(&message.payload) {
            Ok(payload) => payload.to_string(),
            Err(error) => return Err(IotCoreCNCMessageError::new(&format!("Malformed payload UTF8 bytearray on CNC message: {}", error)))
        };

        match topic {
            IotCoreTopicTypeKind::CONFIG => {
                match IotCoreConfig::from_json_string(&payload_string) {
                    Ok(msg) => parsed = Some(IotCoreCNCMessageKind::CONFIG(msg)),
                    Err(error) => {
                        return Err(IotCoreCNCMessageError::new(&format!("Error while parsing CNC config message: {}", error)));
                    }
                };
            },
            IotCoreTopicTypeKind::COMMAND => {
                match IotCoreCommand::from_json_string(&payload_string) {
                    Ok(msg) => parsed = Some(IotCoreCNCMessageKind::COMMAND(msg)),
                    Err(error) => {
                        return Err(IotCoreCNCMessageError::new(&format!("Error while parsing CNC command message: {}", error)));
                    }
                };
            },
            IotCoreTopicTypeKind::EVENT => warn!("I'm not supposed to receive EVENT type messages through CNC channels! Disgarding message.")
        };

        Ok(parsed)
    }
}

impl Message for IotCoreCNCMessageKind {
    type Result = bool;
}

impl IotCoreConfig {
    fn from_json_string(json_string: &String) -> Result<IotCoreConfig, serde_json::Error> {
        let config: IotCoreConfig = serde_json::from_str(&json_string)?;
        Ok(config)
    }
}

type IotCoreCNCMessageError = MawsToIotCoreError;

// ------------------------- IoT Core CNC message types end --------------------- //

// ------------------------- IoT Core CNC topic types ------------------------- //

type IotCoreTopicError = MawsToIotCoreError;

pub enum IotCoreTopicTypeKind {
    EVENT,
    CONFIG,
    COMMAND
}

impl IotCoreTopicTypeKind {
    pub fn value(&self, sub_folder: Option<String>) -> String {
        match *self {
            IotCoreTopicTypeKind::EVENT => "events".to_string(),
            IotCoreTopicTypeKind::CONFIG => "config".to_string(),
            IotCoreTopicTypeKind::COMMAND => {
                match sub_folder {
                    None => "commands/#".to_string(),
                    Some(folder) => format!("commands/{}", folder)
                }
            }
        }
    }

    pub fn from_str(source_string: &String) -> Result<IotCoreTopicTypeKind, IotCoreTopicError> {
        let string_parts = source_string.split("/").into_iter().map(|x| x.trim()).collect::<Vec<&str>>();

        if string_parts.len() < 4 || string_parts.len() > 5 {
            // expecting splitted string to be of length four or five
            return Err(IotCoreTopicError::new(&format!("Unable to properly split the topic string '{}' since it has {} parts.", source_string, string_parts.len())))
        }

        let mut topic = string_parts[3].to_string();

        let mut sub_folder = None;
        if string_parts.len() == 5 {
            sub_folder = Some(string_parts[4].to_string());
        }

        let mut topic_with_subfolder = topic.clone();
        if sub_folder.is_some() {
            topic_with_subfolder = format!("{}/{}", topic.clone(), sub_folder.clone().unwrap());
        } else {
            // @TODO: this is an ugly way to do this. fix later.
            if topic == "commands" {
                topic_with_subfolder = format!("{}/#", topic.clone());
            }
        }

        if topic_with_subfolder != topic {
            topic = topic_with_subfolder;
        }

        if IotCoreTopicTypeKind::EVENT.value(sub_folder.clone()) == topic {
            return Ok(IotCoreTopicTypeKind::EVENT)
        } else if IotCoreTopicTypeKind::CONFIG.value(sub_folder.clone()) == topic {
            return Ok(IotCoreTopicTypeKind::CONFIG)
        } else if IotCoreTopicTypeKind::COMMAND.value(sub_folder.clone()) == topic {
            return Ok(IotCoreTopicTypeKind::COMMAND)
        } else {
            return Err(IotCoreTopicError::new(&format!("Unrecognized parsed topic '{}' in '{}'", string_parts[3], source_string)))
        }
    }
}

// ------------------------- IoT Core CNC topic types end --------------------- //

// ------------------------- IoT Core client starts --------------------------- //

pub struct UpdateLoggerActorAddressMessage {
    pub logger_address: Addr<LoggerActor>
}

impl Message for UpdateLoggerActorAddressMessage {
    type Result = bool;
}

pub struct ErrorActor;

impl actix::Actor for ErrorActor {
    type Context = Context<Self>;
}

impl actix::Handler<ErrorMessage> for ErrorActor {
    type Result = ();

    fn handle(&mut self, error: ErrorMessage, _: &mut Self::Context) -> Self::Result {
        error!("Got an error: {}", error.0);
    }
}

pub struct MessageActor;

impl actix::Actor for MessageActor {
    type Context = Context<Self>;
}

impl actix::Handler<PublishMessage> for MessageActor {
    type Result = ();

    fn handle(&mut self, msg: PublishMessage, _: &mut Self::Context,) -> Self::Result {
        trace!(
            "Got message: id:{}, topic: {}, payload: {:?}",
            msg.id,
            msg.topic_name,
            msg.payload
        );

        // @TODO: fix unwrap
        let cnc_message = IotCoreCNCMessageKind::parse_from_mqtt_message(&msg).unwrap();
    }
}

type IotCoreClientError = MawsToIotCoreError;

pub struct IotCoreClient {
    client: MqttClient,
    jwt_token_factory: IotCoreAuthToken,
    device_id: String
}

impl IotCoreClient {

    async fn subscribe(&mut self, topic: IotCoreTopicTypeKind, subfolder: Option<String>) -> Result<(), std::io::Error> {
        let topic = format!("/devices/{}/{}", self.device_id, topic.value(subfolder));
        self.client.subscribe(topic.clone(), QualityOfService::Level2).await?;

        trace!("Subscribed to topic {}", topic.clone());
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<(), std::io::Error> {
        // initiate connect
        self.client.connect().await?;

        // Waiting for the client to be connected
        while !self.client.is_connected().await? {
            let delay_time = Instant::now() + Duration::new(1, 0);
            delay_until(delay_time).await;
        }
        trace!("MQTT connected");
        
        // subscribe to CNC channels
        self.subscribe(IotCoreTopicTypeKind::CONFIG, None).await?;
        self.subscribe(IotCoreTopicTypeKind::COMMAND, None).await?;

        Ok(())
    }

    pub async fn build(autodetected_config: &AutoDetectedConfig, keypath: &Path, device_id: &Email) -> Result<IotCoreClient, IotCoreClientError> {
        let jwt_token_factory = IotCoreAuthToken::build(&autodetected_config.registry_config.project, keypath);
        let jwt_token = match jwt_token_factory.issue_new() {
            Ok(jwt_token) => jwt_token,
            Err(error) => return Err(IotCoreClientError::new(&format!("Error while issuing initial JWT token: {}", error)))
        };

        let tcp_stream = match TcpStream::connect(autodetected_config.mqtt_sockaddr).await {
            Ok(stream) => stream,
            Err(error) => return Err(IotCoreClientError::new(&format!("Error while connecting to '{}': {}", autodetected_config.mqtt_sockaddr, error)))
        };

        let inner_cx = match TlsConnector::builder()
                .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
                .build() {
            Ok(cx) => cx,
            Err(error) => return Err(IotCoreClientError::new(&format!("Unable to build TLS context: {}", error)))
        };
        let outer_cx = tokio_native_tls::TlsConnector::from(inner_cx);
        let tls_stream = match outer_cx.connect(&autodetected_config.mqtt_hostname, tcp_stream).await  {
            Ok(stream) => stream,
            Err(error) => return Err(IotCoreClientError::new(&format!("Unable to establish TLS connection: {}", error)))
        };

        trace!("{:?}", tls_stream);
        trace!("TLS stream connected to {}", autodetected_config.mqtt_sockaddr);
        let (reader, writer) = split(tls_stream);

        let mut options = MqttOptions::default();
        options.user_name = Some(device_id.user().to_string());
        options.password = Some(jwt_token);

        let client = MqttClient::new(
            reader, writer,
            device_id.user().to_string(),
            options,
            MessageActor.start().recipient(),
            ErrorActor.start().recipient(),
            None,
        );

        Ok(IotCoreClient{
            client: client,
            jwt_token_factory: jwt_token_factory,
            device_id: device_id.user().to_string()
        })
    }
}

// ------------------------- IoT Core client ends --------------------------- //

/*
use actix::prelude::*;
use std::path::Path;
use paho_mqtt as mqtt;
use serde::Deserialize;
use std::str;
use actix::Addr;
use futures::{stream::StreamExt, executor::block_on};
use crate::lib::jwt::IotCoreAuthToken;
use crate::lib::maws::MAWSMessageKind;
use crate::lib::logger::LoggerActor;
use crate::lib::error::MawsToIotCoreError;
use crate::lib::autodetect::AutoDetectedConfig;

// -------------------------- new type of code ---------------------------------- //

pub struct UpdateLoggerActorAddressMessage {
    pub logger_address: Addr<LoggerActor>
}

impl Message for UpdateLoggerActorAddressMessage {
    type Result = bool;
}

pub struct IotCoreActor {
    iotcore_client: IotCoreClient,
}

impl IotCoreActor {
    pub fn build(client_id: &String, autodetected_config: &AutoDetectedConfig, cacertpath: &Path, certpath: &Path, keypath: &Path) -> Result<IotCoreActor, IotCoreClientError> {
        // create the IotCore MQTT client and connect
        let iotcore_client = IotCoreClient::build(client_id, autodetected_config, cacertpath, certpath, keypath)?;
        Ok(IotCoreActor{
            iotcore_client: iotcore_client
        })
    }
}

impl Actor for IotCoreActor {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Context<Self>) {
        // do an initial connection, we reconnect during message send if this fails
        match block_on(async {
            self.iotcore_client.connect().await?;
            // Explicit return type for the async block
            Ok::<(), mqtt::Error>(())
        }) {
            Ok(_) => {},
            Err(error) => warn!("Unable to initially connect to Iot Core service: {}", error)
        }
    }
}

impl Handler<UpdateLoggerActorAddressMessage> for IotCoreActor {
    type Result = bool;

    fn handle(&mut self, msg: UpdateLoggerActorAddressMessage, _: &mut Context<Self>) -> Self::Result {
        self.iotcore_client.logger_address = Some(msg.logger_address);
        
        true
    }
}

impl Handler<MAWSMessageKind> for IotCoreActor {
    type Result = bool;

    fn handle(&mut self, msg: MAWSMessageKind, _: &mut Context<Self>) -> Self::Result {
        trace!("actix result handle for iotcoreactor::mawsmessagekind activated for: {:?}", msg);

        true
    }
}

// --------------------------- new code stops ---------------------------------- //

// ------------------------- IoT Core CNC message types ------------------------- //

#[derive(Debug, Deserialize)]
pub struct IotCoreCommand {
    command: String
}

impl IotCoreCommand {
    fn from_json_string(json_string: &String) -> Result<IotCoreCommand, serde_json::Error> {
        let command: IotCoreCommand = serde_json::from_str(&json_string)?;
        Ok(command)
    }
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
pub struct IotCoreConfig {
    logger: IotCoreLoggerConfig,
    iotcore: IotCorePropertiesConfig
}

#[derive(Debug)]
pub enum IotCoreCNCMessageKind {
    CONFIG(IotCoreConfig),
    COMMAND(IotCoreCommand)
}

impl IotCoreCNCMessageKind {
    pub fn parse_from_mqtt_message(message: &paho_mqtt::message::Message) -> Result<Option<IotCoreCNCMessageKind>, IotCoreCNCMessageError> {
        let mut parsed = None;

        let topic = match IotCoreTopicTypeKind::from_message(&message) {
            Ok(msg) => msg,
            Err(error) => {
                return Err(IotCoreCNCMessageError::new(&format!("Error while parsing CNC topic: {}", error)));
            }
        };
        match topic {
            IotCoreTopicTypeKind::CONFIG => {
                match IotCoreConfig::from_json_string(&message.payload_str().to_string()) {
                    Ok(msg) => parsed = Some(IotCoreCNCMessageKind::CONFIG(msg)),
                    Err(error) => {
                        return Err(IotCoreCNCMessageError::new(&format!("Error while parsing CNC config message: {}", error)));
                    }
                };
            },
            IotCoreTopicTypeKind::COMMAND => {
                match IotCoreCommand::from_json_string(&message.payload_str().to_string()) {
                    Ok(msg) => parsed = Some(IotCoreCNCMessageKind::COMMAND(msg)),
                    Err(error) => {
                        return Err(IotCoreCNCMessageError::new(&format!("Error while parsing CNC command message: {}", error)));
                    }
                };
            },
            IotCoreTopicTypeKind::EVENT => warn!("I'm not supposed to receive EVENT type messages through CNC channels! Disgarding message.")
        };

        Ok(parsed)
    }
}

impl Message for IotCoreCNCMessageKind {
    type Result = bool;
}

impl IotCoreConfig {
    fn from_json_string(json_string: &String) -> Result<IotCoreConfig, serde_json::Error> {
        let config: IotCoreConfig = serde_json::from_str(&json_string)?;
        Ok(config)
    }
}

type IotCoreCNCMessageError = MawsToIotCoreError;

// ------------------------- IoT Core CNC message types end --------------------- //

// ------------------------- IoT Core CNC topic types ------------------------- //

type IotCoreTopicError = MawsToIotCoreError;

pub enum IotCoreTopicTypeKind {
    EVENT,
    CONFIG,
    COMMAND
}

impl IotCoreTopicTypeKind {
    pub fn value(&self, sub_folder: Option<String>) -> String {
        match *self {
            IotCoreTopicTypeKind::EVENT => "events".to_string(),
            IotCoreTopicTypeKind::CONFIG => "config".to_string(),
            IotCoreTopicTypeKind::COMMAND => {
                match sub_folder {
                    None => "commands/#".to_string(),
                    Some(folder) => format!("commands/{}", folder)
                }
            }
        }
    }

    pub fn from_str(source_string: &String) -> Result<IotCoreTopicTypeKind, IotCoreTopicError> {
        let string_parts = source_string.split("/").into_iter().map(|x| x.trim()).collect::<Vec<&str>>();

        if string_parts.len() < 4 || string_parts.len() > 5 {
            // expecting splitted string to be of length four or five
            return Err(IotCoreTopicError::new(&format!("Unable to properly split the topic string '{}' since it has {} parts.", source_string, string_parts.len())))
        }

        let mut topic = string_parts[3].to_string();

        let mut sub_folder = None;
        if string_parts.len() == 5 {
            sub_folder = Some(string_parts[4].to_string());
        }

        let mut topic_with_subfolder = topic.clone();
        if sub_folder.is_some() {
            topic_with_subfolder = format!("{}/{}", topic.clone(), sub_folder.clone().unwrap());
        } else {
            // @TODO: this is an ugly way to do this. fix later.
            if topic == "commands" {
                topic_with_subfolder = format!("{}/#", topic.clone());
            }
        }

        if topic_with_subfolder != topic {
            topic = topic_with_subfolder;
        }

        if IotCoreTopicTypeKind::EVENT.value(sub_folder.clone()) == topic {
            return Ok(IotCoreTopicTypeKind::EVENT)
        } else if IotCoreTopicTypeKind::CONFIG.value(sub_folder.clone()) == topic {
            return Ok(IotCoreTopicTypeKind::CONFIG)
        } else if IotCoreTopicTypeKind::COMMAND.value(sub_folder.clone()) == topic {
            return Ok(IotCoreTopicTypeKind::COMMAND)
        } else {
            return Err(IotCoreTopicError::new(&format!("Unrecognized parsed topic '{}' in '{}'", string_parts[3], source_string)))
        }
    }

    pub fn from_message(message: &paho_mqtt::message::Message) -> Result<IotCoreTopicTypeKind, IotCoreTopicError> {
        Ok(IotCoreTopicTypeKind::from_str(&message.topic().to_string())?)
    }
}

// ------------------------- IoT Core CNC topic types end --------------------- //

type IotCoreClientError = MawsToIotCoreError;

pub struct IotCoreClient {
    subscribe_to_topics: [String; 2],
    ssl_opts: mqtt::SslOptions,
    conn_opts: mqtt::ConnectOptions,
    client: mqtt::async_client::AsyncClient,
    jwt_token_factory: IotCoreAuthToken,
    logger_address: Option<Addr<LoggerActor>>
}

impl IotCoreClient {
    pub fn build(device_id: &String, autodetected_config: &AutoDetectedConfig, cacertpath: &Path, certpath: &Path, keypath: &Path) -> Result<IotCoreClient, IotCoreClientError> {
        let create_opts = mqtt::CreateOptionsBuilder::new()
            .client_id(device_id)
            .mqtt_version(mqtt::types::MQTT_VERSION_3_1_1)
            .server_uri(autodetected_config.mqtt_url.clone())
            .persistence(mqtt::PersistenceType::None)
            .finalize();

        let cli = match mqtt::AsyncClient::new(create_opts) {
            Ok(cli) => cli,
            Err(error) => return Err(IotCoreClientError::new(&format!("Error while init mqtt client: {}", error)))
        };

        let ssl_options = match mqtt::SslOptionsBuilder::new()
            .ssl_version(mqtt::SslVersion::Tls_1_2)
            .trust_store(cacertpath) {
                Ok(options) => options.finalize(),
                Err(error) => return Err(IotCoreClientError::new(&format!("Error while init mqtt ssl options: {}", error)))
        };

        let jwt_token_factory = IotCoreAuthToken::build(&autodetected_config.registry_config.project, keypath);
        let jwt_token = match jwt_token_factory.issue_new() {
            Ok(jwt_token) => jwt_token,
            Err(error) => return Err(IotCoreClientError::new(&format!("Error while issuing JWT token: {}", error)))
        };
        let conn_opts = mqtt::ConnectOptionsBuilder::new()
            .user_name(device_id) // not really used, can be anything
            .password(jwt_token)
            .ssl_options(ssl_options.clone())
            .finalize();

        let subscribe_to_topics = [
            format!("/devices/{}/{}", device_id, IotCoreTopicTypeKind::CONFIG.value(None)),
            format!("/devices/{}/{}", device_id, IotCoreTopicTypeKind::COMMAND.value(None))
            // config.iotcore.as_iotcore_client_topic(IotCoreTopicTypeKind::CONFIG, None),
            // config.iotcore.as_iotcore_client_topic(IotCoreTopicTypeKind::COMMAND, None)
            ];

        Ok(IotCoreClient {
            ssl_opts: ssl_options,
            conn_opts: conn_opts,
            client: cli,
            jwt_token_factory: jwt_token_factory,
            subscribe_to_topics: subscribe_to_topics,
            logger_address: None
        })
    }

    async fn subscribe(&mut self) -> Result<(), mqtt::Error> {
        let mut mqtt_stream = self.client.get_stream(64);

        let logger_addr = self.logger_address.clone().unwrap();

        // @TODO fix disconnect with handle
        let _handle = tokio::spawn(async move {
            while let Some(msg_opt) = mqtt_stream.next().await {
                match msg_opt {
                    Some(msg) => {
                        let cncmsg = match IotCoreCNCMessageKind::parse_from_mqtt_message(&msg) {
                            Ok(cncmsg) => cncmsg,
                            Err(error) => {
                                error!("Error on parsing MQTT cnc message: {}", error);
                                continue;
                            }
                        };
                        match cncmsg {
                            Some(cnc_message) => {
                                match logger_addr.send(cnc_message).await {
                                    Ok(_) => {},
                                    Err(error) => {
                                        error!("Error while communicating with logger actor: {}", error);
                                        continue;
                                    }
                                }
                            },
                            None => warn!("None CNC message.")
                        };
                    },
                    None => warn!("None CNC message.")
                }
            }
        });

        // note the array of QOS arguments, there is one QOS for each subscribed topic. in our case two
        trace!("Subscribing to command and control channels in IoT core service");
        self.client.subscribe_many(&self.subscribe_to_topics, &[ mqtt::QOS_1, mqtt::QOS_1] ).await?;

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
*/