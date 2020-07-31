mod maws;
mod config;
mod jwt;
mod linecodec;
mod iotcore;

#[macro_use] extern crate log;
#[macro_use] extern crate serde_json;

use clap::{App, Arg};
use dotenv::dotenv;
use directories::ProjectDirs;
use std::path::Path;
use std::env;
use futures::stream::StreamExt;
use tokio_util::codec::Decoder;
use crate::config::read_config;
use crate::linecodec::LineCodec;
use crate::iotcore::IotCoreClient;

#[tokio::main]
async fn main() {
    // initialize dot environment so we can pull arguments from env, env files,
    //  commandline or as hardcoded values in code
    dotenv().ok();

    // project dirs are located somewhere in the system based on arch and os
    let project_dirs = ProjectDirs::from("me", "bcow", env!("CARGO_PKG_NAME")).unwrap();
    let default_config_file_path = Path::new(project_dirs.config_dir()).join("maws2iotcore.toml");

    // initialize Clap (Command line argument parser on build time from YAML file)
    let matches = App::new(env!("CARGO_PKG_NAME")) // get the application name from package name
    .version(env!("CARGO_PKG_VERSION")) // read the version string from cargo.toml
    .about(env!("CARGO_PKG_DESCRIPTION")) // do the same for about, read it from env (cargo.toml)
    .author(env!("CARGO_PKG_AUTHORS")) // and for the author(s) information as well
    .arg(Arg::with_name("verbose") // define verbosity flag
        .long("verbose")
        .short("v")
        .multiple(true)
        .help("Sets the level of verbosity. Specifying multiple flags increases verbosity."))
    .arg(Arg::with_name("config") // define config file path and as a default use the autodetected one.
        .long("config")
        .short("c")
        .help("Specify alternate config file location.")
        .default_value(default_config_file_path.to_str().unwrap()))
    .get_matches();

    // if there are environment variable(s) set for rust log
    //  overwrite them here since command line arguments have higher priority
    match matches.occurrences_of("verbose") {
        0 => env::set_var("RUST_LOG", "error"),
        1 => env::set_var("RUST_LOG", "info"),
        _ => env::set_var("RUST_LOG", "debug")
    }
    // initialize logger
    pretty_env_logger::init();
    info!("Starting {} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // read configuration
    let config = match read_config(matches.value_of("config").unwrap()) {
        Ok(config) => config,
        Err(error) => {
            error!("Unable to open the config file: {}", error);
            std::process::exit(exitcode::CONFIG);
        }
    };

    // create the IotCore MQTT client and connect
    let mut iotcore_client = match IotCoreClient::build(&config) {
        Ok(client) => client,
        Err(error) => {
            error!("Unable to build Iot Core client: {}", error);
            std::process::exit(exitcode::CANTCREAT);
        }
    };
    match iotcore_client.connect().await {
        Ok(_) => {},
        Err(error) => {
            error!("Unable to connect to Iot Core service: {}", error);
            std::process::exit(exitcode::PROTOCOL);
        }
    };

    // open the configured serial port
    let settings = tokio_serial::SerialPortSettings::default();
    let mut port = match tokio_serial::Serial::from_path(config.serial.port, &settings) {
        Ok(port) => port,
        Err(error) => {
            error!("Unable to open serial port: {}", error);
            std::process::exit(exitcode::IOERR);
        }
    };

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

        match iotcore_client.send_message(&config.iotcore.as_iotcore_client_topic(), &message, paho_mqtt::QOS_1).await {
            Ok(_) => {},
            Err(error) => {
                error!("Unable to send a message to IoT core MQTT broker: {}", error);
            }
        };
    }
}

// eof
