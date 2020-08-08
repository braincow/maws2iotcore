use actix::prelude::*;
use crate::lib::iotcore::IotCoreCNCMessageKind;

pub struct LoggerActor;

impl Actor for LoggerActor {
    type Context = Context<Self>;
}

impl Handler<IotCoreCNCMessageKind> for LoggerActor {
    type Result = bool;

    fn handle(&mut self, msg: IotCoreCNCMessageKind, _: &mut Context<Self>) -> Self::Result {
        info!("actix result handle for iotcorecncmessage received: {:?}", msg);
        true
    }
}

// eof