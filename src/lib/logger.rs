use actix::prelude::*;
use crate::lib::iotcore::{IotCoreConfig, IotCoreCNCMessageKind};
use crate::lib::config::AppConfig;
use crate::lib::autodetect::AutoDetectedConfig;

pub struct LoggerActor {
    pub auto_config: Option<AutoDetectedConfig>,
    pub app_config: Option<AppConfig>,
    pub iot_config: Option<IotCoreConfig>
}

impl Actor for LoggerActor {
    type Context = Context<Self>;
}

impl Handler<IotCoreCNCMessageKind> for LoggerActor {
    type Result = bool;

    fn handle(&mut self, msg: IotCoreCNCMessageKind, _: &mut Context<Self>) -> Self::Result {
        trace!("actix result handle for iotcorecncmessage received: {:?}", msg);

        match msg {
            IotCoreCNCMessageKind::CONFIG(msg) => self.iot_config = Some(msg),
            IotCoreCNCMessageKind::COMMAND(msg) => trace!("CNC message command not implemented: {:?}", msg)
        };

        true
    }
}

// eof