use actix::prelude::*;
use futures::stream::StreamExt;
use tokio_util::codec::Decoder;
use crate::lib::linecodec::LineCodec;
use crate::lib::iotcore::IotCoreTopicTypeKind;
use crate::lib::iotcore::{IotCoreCNCMessageKind, IotCoreConfig, MessageActor};

pub struct UpdateIotCoreActorAddressMessage {
    pub iotcore_address: Addr<MessageActor>
}

impl Message for UpdateIotCoreActorAddressMessage {
    type Result = bool;
}

pub struct LoggerActor {
    iotcore_config: Option<IotCoreConfig>,
    iotcore_address: Option<Addr<MessageActor>>
}

impl LoggerActor {
    pub fn build() -> LoggerActor {
        LoggerActor {
            iotcore_config: None,
            iotcore_address: None
        }
    }
}

impl Actor for LoggerActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
/*
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

            match iotcore_client.send_message(&config.iotcore.as_iotcore_client_topic(IotCoreTopicTypeKind::EVENT, None), &message, paho_mqtt::QOS_1).await {
                Ok(_) => {},
                Err(error) => {
                    error!("Unable to send a message to IoT core MQTT broker: {}", error);
                }
            };
        }
*/
    }
}

impl Handler<UpdateIotCoreActorAddressMessage> for LoggerActor {
    type Result = bool;

    fn handle(&mut self, msg: UpdateIotCoreActorAddressMessage, _: &mut Context<Self>) -> Self::Result {
        self.iotcore_address = Some(msg.iotcore_address);
        
        true
    }
}

impl Handler<IotCoreCNCMessageKind> for LoggerActor {
    type Result = bool;

    fn handle(&mut self, msg: IotCoreCNCMessageKind, _: &mut Context<Self>) -> Self::Result {
        trace!("actix result handle for loggeractor::iotcorecncmessage received: {:?}", msg);

        match msg {
            IotCoreCNCMessageKind::CONFIG(msg) => self.iotcore_config = Some(msg),
            IotCoreCNCMessageKind::COMMAND(msg) => trace!("CNC message command not implemented: {:?}", msg)
        };

        true
    }
}

// eof