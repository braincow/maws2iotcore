use actix::prelude::*;
use std::path::Path;
use openssl::nid::Nid;
use addr::Email;
use crate::lib::autodetect::AutoDetectedConfig;
use crate::lib::logger::{UpdateIotCoreActorAddressMessage, LoggerActor};
use crate::lib::iotcore::{UpdateLoggerActorAddressMessage, IotCoreActor};
use crate::lib::certificate::SelfSignedCertificate;

pub async fn run_subcommand(cacertpath: &Path, certpath: &Path, keypath: &Path) {
    // load in the (self signed) certificate
    let cert = match SelfSignedCertificate::load_cerfificate_and_key(certpath, keypath) {
        Ok(cert) => cert,
        Err(error) => {
            error!("Error while loading configured certificate and/or key: {}", error);
            std::process::exit(exitcode::IOERR);
        }
    };

    // parse email address out of the common name field in the certificate
    let cn: Email = match cert.certificate().subject_name().entries_by_nid(Nid::COMMONNAME).into_iter().next().unwrap().data().as_utf8().unwrap().parse() {
        Ok(email) => email,
        Err(error) => {
            error!("Error while parsing client id and domain information from certificate CN= field: {}", error);
            std::process::exit(exitcode::CANTCREAT);
        }
    };

    // query DNS to acquire information about the registry location etc
    let autodetected_config = match AutoDetectedConfig::build(&cn.host().to_string()) {
        Ok(config) => config,
        Err(error) => {
            error!("Error while autodetecting settings from DNS: {}", error);
            std::process::exit(exitcode::OSERR);
        }
    };

    // build actors
    let iotcore_actor = match IotCoreActor::build(&cn.user().to_string(), &autodetected_config, &cacertpath, &certpath, &keypath) {
        Ok(actor) => actor,
        Err(error) => {
            error!("Error while creating iotcore client: {}", error);
            std::process::exit(exitcode::CANTCREAT);
        }
    };
    let logger_actor = LoggerActor::build();

    // start actors
    let iotcore_addr = iotcore_actor.start();
    let logger_addr = logger_actor.start();

    // update both actors with info about each others addresses
    // @TODO: is there a better way of doing this?
    // @TODO: fix the error handling
    match logger_addr.send(UpdateIotCoreActorAddressMessage{
        iotcore_address: iotcore_addr.clone()
    }).await {
        Ok(_resp) => {},
        Err(_error) => {}
    };

    match iotcore_addr.send(UpdateLoggerActorAddressMessage{
        logger_address: logger_addr.clone()
    }).await {
        Ok(_resp) => {},
        Err(_error) => {}
    };

    tokio::signal::ctrl_c().await.unwrap();
    warn!("Ctrl-C received, shutting down");
    System::current().stop();
}
