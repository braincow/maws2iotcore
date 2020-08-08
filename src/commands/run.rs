use actix::prelude::*;
use futures::stream::StreamExt;
use tokio_util::codec::Decoder;
use crate::lib::config::AppConfig;
use crate::lib::linecodec::LineCodec;
use crate::lib::iotcore::{IotCoreClient, IotCoreTopicType};
use crate::lib::logger::LoggerActor;

pub async fn run_subcommand(config_file: &str) {
    // read configuration
    let config = match AppConfig::read_config(config_file) {
        Ok(config) => config,
        Err(error) => {
            error!("Unable to open the config file: {}", error);
            std::process::exit(exitcode::CONFIG);
        }
    };

    let logger = LoggerActor.start();

    // create the IotCore MQTT client and connect
    let mut iotcore_client = match IotCoreClient::build(&config, logger) {
        Ok(client) => client,
        Err(error) => {
            error!("Unable to build Iot Core client: {}", error);
            std::process::exit(exitcode::CANTCREAT);
        }
    };
    match iotcore_client.connect().await {
        Ok(_) => {},
        Err(error) => {
            warn!("Unable to initially connect to Iot Core service: {}", error);
        }
    };

    // open the configured serial port
    let settings = tokio_serial::SerialPortSettings::default();
    let mut port = match tokio_serial::Serial::from_path(config.serial.port.clone(), &settings) {
        Ok(port) => port,
        Err(error) => {
            error!("Unable to open serial port: {}", error);
            std::process::exit(exitcode::IOERR);
        }
    };
    info!("Expecting MAWS messages from: {}", config.serial.port);

    #[cfg(unix)]
    match port.set_exclusive(false) {
        Ok(_) =>
            debug!("Unix port exclusivity set to false."),
        Err(error) => {
            error!("Unable to set UNIX serial port exclusivity to false: {}", error);
            std::process::exit(exitcode::IOERR);
        }
    }

    let mut reader = LineCodec.framed(port);

    while let Some(message_result) = reader.next().await {
        let message = match message_result {
            Ok(message) => message,
            Err(error) => {
                error!("Failed to read data over the serial line: {}", error);
                std::process::exit(exitcode::IOERR);
            }
        };
        debug!("{:?}", message);

        match iotcore_client.send_message(&config.iotcore.as_iotcore_client_topic(IotCoreTopicType::EVENT, None), &message, paho_mqtt::QOS_1).await {
            Ok(_) => {},
            Err(error) => {
                error!("Unable to send a message to IoT core MQTT broker: {}", error);
            }
        };
    }
}
