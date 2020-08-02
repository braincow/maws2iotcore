use std::path::Path;
use paho_mqtt as mqtt;
use crate::lib::config::AppConfig;
use crate::lib::jwt::IotCoreAuthToken;
use crate::lib::maws::MAWSMessageKind;

pub enum IotCoreTopicType {
    EVENT,
    CONFIG,
    CMD
}

impl IotCoreTopicType {
    pub fn value(&self) -> String {
        match *self {
            IotCoreTopicType::EVENT => "events".to_string(),
            IotCoreTopicType::CONFIG => "config".to_string(),
            IotCoreTopicType::CMD => "commands/#".to_string()
        }
    }
}

pub struct IotCoreClient {
    ssl_opts: mqtt::SslOptions,
    conn_opts: mqtt::ConnectOptions,
    client: mqtt::async_client::AsyncClient,
    jwt_token_factory: IotCoreAuthToken
}

impl IotCoreClient {
    pub fn build(config: &AppConfig) -> Result<IotCoreClient, Box<dyn std::error::Error>> {
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

        Ok(IotCoreClient {
            ssl_opts: ssl_options,
            conn_opts: conn_opts,
            client: cli,
            jwt_token_factory: jwt_token_factory
        })
    }

    pub async fn connect(&self) -> Result<(), mqtt::Error> {
        self.client.connect(self.conn_opts.clone()).await?;
        info!("Connected to IoT core service");
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
