use std::path::Path;
use paho_mqtt as mqtt;
use crate::config::AppConfig;

pub async fn connect_to_iotcore(config: &AppConfig, jwt_token: &String) -> Result<paho_mqtt::async_client::AsyncClient, mqtt::Error> {
    // connect to iotcore mqtt server cluster
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
            Err(error) => return Err(error)
    };

    let conn_opts = mqtt::ConnectOptionsBuilder::new()
        .user_name("not_used")
        .password(jwt_token)
        .ssl_options(ssl_options)
        .finalize();

    match cli.connect(conn_opts).await {
        Ok(_) => {},
        Err(error) => return Err(error)
    };

    Ok(cli)
}

// eof
