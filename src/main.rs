#[macro_use] extern crate log;
extern crate frank_jwt;
#[macro_use] extern crate serde_json;

use clap::{App, Arg};
use dotenv::dotenv;
use directories::ProjectDirs;
use std::path::Path;
use serde::Deserialize;
use std::fs;
use std::{env, io, str};
use tokio_util::codec::{Decoder, Encoder};
use futures::stream::StreamExt;
use bytes::BytesMut;
use frank_jwt::{Algorithm, encode};
use std::time::{SystemTime, UNIX_EPOCH};
use paho_mqtt as mqtt;

#[derive(Debug, Deserialize)]
struct SerialConfig {
    port: String
}

#[derive(Debug, Deserialize)]
struct IotCoreConfig {
    device_id: String,
    private_key: String,
    project_id: String,
    registry_name: String,
    registry_region: String,
    ca_certs: String
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    serial: SerialConfig,
    iotcore: IotCoreConfig
}

struct LineCodec;

impl Decoder for LineCodec {
    type Item = MAWSMessageKind;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let newline = src.as_ref().iter().position(|b| *b == b'\n');
        if let Some(n) = newline {
            let line = src.split_to(n + 1);
            return match str::from_utf8(line.as_ref()) {
                Ok(s) => {
                    // strip the ascii (dec) 1,2,3 codes used by MAWS over serial line
                    let utf_string = s.to_string().replace("\u{1}", "").replace("\u{2}", "").replace("\u{3}", "");
                    Ok(Some(MAWSMessageKind::parse(utf_string)))
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid String")),
            };
        }
        Ok(None)
    }
}

impl Encoder for LineCodec {
    type Item = String;
    type Error = io::Error;

    fn encode(&mut self, _item: Self::Item, _dst: &mut BytesMut) -> Result<(), Self::Error> {
        Ok(())
    }
}

/*
 DEBUG maws2iotcore > LOG         19.0     9.8   55       984.4  1001.7   125      0.0    331      0.5
 DEBUG maws2iotcore > PTU         19.0    10.3    20.2     9.8     8.8    13.0   55      50      99      984.4   983.8   986.7  1001.7  1001.1  1004.4       125       0     871      0.0     0.0     0.2
 DEBUG maws2iotcore > WIND         0.3    300
*/

#[derive(Debug)]
struct MAWSWindMessage {
    ws_cur: f64, // WScur m/s 
    wd_cur: f64 // WDcur °C
}

#[derive(Debug)]
struct MAWSLogMessage {
    ta60s_avg: f64, // TA60sAvg °C
    dp60s_avg: f64, // DP60sAvg °C
    rh60s_avg: f64, // RH60sAvg %
    pa60s_avg: f64, // PA60sAvg hPa
    qff60s_avg: f64, // QFF60sAvg hPa
    sr60s_avg: f64, // SR60sAvg W/m2
    pr60s_sum: f64, // PR60sSum mm
    wd2min_avg: f64, // WD2minAvg °C
    ws2min_avg: f64 // WS2minAvg m/s
}

#[derive(Debug)]
struct MAWSPtuMessage {
    ta60s_avg: f64, // TA60sAvg °C
    ta24h_min: f64, // TA24hMin °C
    ta24h_max: f64, // TA24hMax °C
    dp60s_avg: f64, // DP60sAvg °C
    dp24h_min: f64, // DP24hMin °C
    dp24h_max: f64, // DP24hMax °C
    rh60s_avg: f64, // RH60sAvg %
    rh24h_min: f64, // RH24hMin %
    rh24h_max: f64, // RH24hMax %
    pa60s_avg: f64, // PA60sAvg hPa
    pa24h_min: f64, // PA24hMin hPa
    pa24h_max: f64, // PA24hMax hPa
    qff60s_avg: f64, // QFF60sAvg hPa
    qff24h_min: f64, // QFF24hMin hPa
    qff24h_max: f64, // QFF24hMax hPa
    sr60s_avg: f64, // SR60sAvg W/m2
    sr24h_min: f64, // SR24hMin W/m2
    sr24h_max: f64, // SR24hMax W/m2
    pr60s_avg: f64, // PR60sAvg mm
    pr24h_min: f64, // PR24hMin mm
    pr24h_max: f64 // PR24hMax mm
}

#[derive(Debug)]
enum MAWSMessageKind {
    WIND(MAWSWindMessage),
    LOG(MAWSLogMessage),
    PTU(MAWSPtuMessage),
    UNKNOWN
}

impl MAWSMessageKind {
    fn parse(utf_string: String) -> MAWSMessageKind {
        let string_splitted = utf_string.split("\t").into_iter().map(|x| x.trim()).collect::<Vec<&str>>();
        //debug!("Splitted line: {:?}", string_splitted);

        let message: MAWSMessageKind;
        if utf_string.starts_with("WIND") {
            message = MAWSMessageKind::WIND(MAWSWindMessage{
                ws_cur: string_splitted[1].parse().unwrap(),
                wd_cur: string_splitted[2].parse().unwrap()
            });
        } else if utf_string.starts_with("LOG") {
            message = MAWSMessageKind::LOG(MAWSLogMessage{
                ta60s_avg: string_splitted[1].parse().unwrap(),
                dp60s_avg: string_splitted[2].parse().unwrap(),
                rh60s_avg: string_splitted[3].parse().unwrap(),
                pa60s_avg: string_splitted[4].parse().unwrap(),
                qff60s_avg: string_splitted[5].parse().unwrap(),
                sr60s_avg: string_splitted[6].parse().unwrap(),
                pr60s_sum: string_splitted[7].parse().unwrap(),
                wd2min_avg: string_splitted[8].parse().unwrap(),
                ws2min_avg: string_splitted[9].parse().unwrap(),
            })
        } else if utf_string.starts_with("PTU") {
            message = MAWSMessageKind::PTU(MAWSPtuMessage {
                ta60s_avg: string_splitted[1].parse().unwrap(),
                ta24h_min: string_splitted[2].parse().unwrap(),
                ta24h_max: string_splitted[3].parse().unwrap(),
                dp60s_avg: string_splitted[4].parse().unwrap(),
                dp24h_min: string_splitted[5].parse().unwrap(),
                dp24h_max: string_splitted[6].parse().unwrap(),
                rh60s_avg: string_splitted[7].parse().unwrap(),
                rh24h_min: string_splitted[8].parse().unwrap(),
                rh24h_max: string_splitted[9].parse().unwrap(),
                pa60s_avg: string_splitted[10].parse().unwrap(),
                pa24h_min: string_splitted[11].parse().unwrap(),
                pa24h_max: string_splitted[12].parse().unwrap(),
                qff60s_avg: string_splitted[13].parse().unwrap(),
                qff24h_min: string_splitted[14].parse().unwrap(),
                qff24h_max: string_splitted[15].parse().unwrap(),
                sr60s_avg: string_splitted[16].parse().unwrap(),
                sr24h_min: string_splitted[17].parse().unwrap(),
                sr24h_max: string_splitted[18].parse().unwrap(),
                pr60s_avg: string_splitted[19].parse().unwrap(),
                pr24h_min: string_splitted[20].parse().unwrap(),
                pr24h_max: string_splitted[21].parse().unwrap()    
            })
        } else {
            message = MAWSMessageKind::UNKNOWN;
        }

        message
    }
}

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

    // read the bots users file
    info!("Using config file: {}", matches.value_of("config").unwrap());
    let config_toml = match fs::read_to_string(matches.value_of("config").unwrap()) {
        Ok(file) => file,
        Err(error) => {
            error!("Error on reading config file: {}", error);
            std::process::exit(exitcode::CONFIG);
        }
    };
    let config: AppConfig = match toml::from_str(&config_toml) {
        Ok(config) => config,
        Err(error) => {
            error!("Error while deserializing the config file: {}", error);
            std::process::exit(exitcode::CONFIG);
        }
    };

    // create JWT key that we shall use to authenticate towards iot core
    let now = SystemTime::now();
    let secs_since_epoc = now.duration_since(UNIX_EPOCH).unwrap();
    let payload = json!({
        "iat": secs_since_epoc.as_secs(),
        "exp": secs_since_epoc.as_secs() + 3600,
        "aud": config.iotcore.project_id
    });
    let header = json!({});
    let jwt = match encode(header, &Path::new(&config.iotcore.private_key).to_path_buf(), &payload, Algorithm::RS256) {
        Ok(jwt_key) => jwt_key,
        Err(error) => {
            error!("Unable to create a JWT key: {}", error);
            std::process::exit(exitcode::PROTOCOL)
        }
    };

    // construct the string that is used as mqtt password
    let client_id = format!("projects/{}/locations/{}/registries/{}/devices/{}",
        config.iotcore.project_id,
        config.iotcore.registry_region,
        config.iotcore.registry_name,
        config.iotcore.device_id);

    // connect to iotcore mqtt server cluster
    let create_opts = mqtt::CreateOptionsBuilder::new()
        .client_id(client_id)
        .mqtt_version(mqtt::types::MQTT_VERSION_3_1_1)
        .server_uri("ssl://mqtt.googleapis.com:8883")
        .persistence(mqtt::PersistenceType::None)
        .finalize();

    let cli = match mqtt::AsyncClient::new(create_opts) {
        Ok(cli) => cli,
        Err(error) => {
            error!("Error on creating mqtt client: {}", error);
            std::process::exit(exitcode::TEMPFAIL);
        }
    };
    let ssl_options = match mqtt::SslOptionsBuilder::new()
        .ssl_version(mqtt::SslVersion::Tls_1_2)
        .trust_store(Path::new(&config.iotcore.ca_certs).to_path_buf()) {
            Ok(ssl_options) => ssl_options.finalize(),
            Err(error) => {
                error!("Error on building SSL settings for MQTT client: {}", error);
                std::process::exit(exitcode::TEMPFAIL);    
            }
    };    
    let conn_opts = mqtt::ConnectOptionsBuilder::new()
        .user_name("not_used")
        .password(jwt)
        .ssl_options(ssl_options)
        .finalize();
    match cli.connect(conn_opts).await {
        Ok(_) => {},
        Err(error) => {
            error!("Error on connecting to IoT Core via MQTT: {}", error);
            std::process::exit(exitcode::IOERR);
        }
    };

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
            error!("Unable to set UNIX serial port exclusive to false: {}", error);
            std::process::exit(exitcode::IOERR);
        }
    }

    let mut reader = LineCodec.framed(port);

    while let Some(message_result) = reader.next().await {
        let message = match message_result {
            Ok(message) => message,
            Err(error) => {
                error!("Failed to read a line over the serial line: {}", error);
                std::process::exit(exitcode::IOERR);
            }
        };
        debug!("{:?}", message);
    }
}

// eof
