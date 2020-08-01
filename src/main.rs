mod maws;
mod config;
mod jwt;
mod linecodec;
mod iotcore;
mod autodetect;

#[macro_use] extern crate log;
#[macro_use] extern crate serde_json;

use clap::{App, Arg};
use dotenv::dotenv;
use directories::ProjectDirs;
use std::path::Path;
use std::{fs, env};
use futures::stream::StreamExt;
use tokio_util::codec::Decoder;
use dialoguer::Confirm;
use crate::config::AppConfig;
use crate::linecodec::LineCodec;
use crate::iotcore::IotCoreClient;

use openssl::x509::{X509, X509Name};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use openssl::asn1::Asn1Time;

struct SelfSignedCertificate {
    certificate: X509,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>
}

impl SelfSignedCertificate {
    fn build_certificate() -> Result<SelfSignedCertificate, openssl::error::ErrorStack> {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
    
        let mut name = X509Name::builder()?;
        name.append_entry_by_nid(Nid::COMMONNAME, "not_used")?;
        let name = name.build();
    
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
        builder.sign(&pkey, MessageDigest::sha256())?;
    
        let certificate: X509 = builder.build();
    
        Ok(SelfSignedCertificate {
            certificate: certificate,
            private_key: pkey
        })
    }

    fn as_certificate_pem(&self) -> Result<String, Box<dyn std::error::Error>> {
        let pem = self.certificate.to_pem()?;
        Ok(String::from_utf8(pem)?)
    }

    fn as_private_key_pem(&self) -> Result<String, Box<dyn std::error::Error>> {
        let rsa = self.private_key.rsa()?;
        Ok(String::from_utf8(rsa.private_key_to_pem()?)?)
    }
}

async fn config_subcommand(deviceid: &str, configfile: &Path, domain: &str, port: &str, cafile: &Path, pubkey: &Path, prikey: &Path) {
    // query DNS to acquire information about the registry
    let autodetected_config = autodetect::AutoDetectedConfig::build(domain).expect("error on querying dns");

    // create a new configuration file and write to disk
    let config = AppConfig::build(deviceid, port, cafile, prikey,
        &autodetected_config.registry_config.project,
        &autodetected_config.registry_config.name,
        &autodetected_config.registry_config.region
    );
    if configfile.exists() {
        warn!("Config file '{}' already exists.", configfile.display());
        if !Confirm::new().with_prompt("Do you wish to overwrite existing configuration file?").default(false).interact().unwrap() {
            warn!("Aborting.");
            std::process::exit(exitcode::NOPERM);
        }
    }
    // write the autodetected config to disk
    match config.write_config(configfile) {
        Ok(_) => info!("Config file '{}' created.", configfile.display().to_string()),
        Err(error) => {
            error!("Unable to create config file '{}': {}", configfile.display().to_string(), error);
            std::process::exit(exitcode::IOERR);            
        }
    };

    // download the CA certificates definied in autodetected configuration and write to disk
    if cafile.exists() {
        warn!("Certificate Authority chain file '{}' already exists.", cafile.display());
        if !Confirm::new().with_prompt("Do you wish to overwrite existing CA file?").default(false).interact().unwrap() {
            warn!("Aborting.");
            std::process::exit(exitcode::NOPERM);
        }
    }
    let ca_result = match reqwest::get(&autodetected_config.ca_url).await {
        Ok(result) => result,
        Err(error) => {
            error!("Unable to download CA certificate chain: {}", error);
            std::process::exit(exitcode::PROTOCOL);
        }
    };
    let ca_pem_contents = match ca_result.text().await {
        Ok(text) => text,
        Err(error) => {
            error!("Unable to download CA certificate chain: {}", error);
            std::process::exit(exitcode::PROTOCOL);
        }
    };
    match fs::write(cafile, ca_pem_contents) {
        Ok(_) => info!("Created Certificate Authority File"),
        Err(error) => {
            error!("Unable to create Certificate Chain file '{}': {}", cafile.display().to_string(), error);
            std::process::exit(exitcode::IOERR);
        }
    }

    // create locally X509 certificate and private key
    let x509 = SelfSignedCertificate::build_certificate().unwrap();
    let cert_pem = x509.as_certificate_pem().unwrap();
    if pubkey.exists() {
        warn!("Certificate file '{}' already exists.", pubkey.display());
        if !Confirm::new().with_prompt("Do you wish to overwrite existing certificate?").default(false).interact().unwrap() {
            warn!("Aborting.");
            std::process::exit(exitcode::NOPERM);
        }
    }
    match fs::write(pubkey, cert_pem) {
        Ok(_) => info!("Wrote certificate file '{}'", pubkey.display()),
        Err(error) => {
            error!("Unable to write certificate file '{}': {}", pubkey.display().to_string(), error);
            std::process::exit(exitcode::IOERR);
        }
    };
    let key_pem = x509.as_private_key_pem().unwrap();
    if prikey.exists() {
        warn!("Private key file '{}' already exists.", prikey.display());
        if !Confirm::new().with_prompt("Do you wish to overwrite existing private key?").default(false).interact().unwrap() {
            warn!("Aborting.");
            std::process::exit(exitcode::NOPERM);
        }
    }
    match fs::write(prikey, key_pem) {
        Ok(_) => info!("Wrote private key file '{}'", prikey.display()),
        Err(error) => {
            error!("Unable to write private key file '{}': {}", prikey.display().to_string(), error);
            std::process::exit(exitcode::IOERR);
        }
    };
}

async fn run_subcommand(config_file: &str) {
    // read configuration
    let config = match AppConfig::read_config(config_file) {
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

        match iotcore_client.send_message(&config.iotcore.as_iotcore_client_topic(), &message, paho_mqtt::QOS_1).await {
            Ok(_) => {},
            Err(error) => {
                error!("Unable to send a message to IoT core MQTT broker: {}", error);
            }
        };
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
    let default_ca_file_path = Path::new(project_dirs.data_dir()).join("ca.pem");
    let default_pubkey_file_path = Path::new(project_dirs.data_dir()).join("public.pem");
    let default_prikey_file_path = Path::new(project_dirs.data_dir()).join("private.pem");

    // initialize Clap (Command line argument parser on build time from YAML file)
    let matches = App::new(env!("CARGO_PKG_NAME")) // get the application name from package name
        .version(env!("CARGO_PKG_VERSION")) // read the version string from cargo.toml
        .author(env!("CARGO_PKG_AUTHORS")) // and for the author(s) information as well
        .about(env!("CARGO_PKG_DESCRIPTION")) // do the same for about, read it from env (cargo.toml)
            .arg(Arg::with_name("verbose") // define verbosity flag
                .long("verbose")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity. Specifying multiple flags increases verbosity.")
                .global(true))
            .arg(Arg::with_name("config") // define config file path and as a default use the autodetected one.
                .long("config")
                .short("c")
                .help("Specify alternate config file location.")
                .default_value(default_config_file_path.to_str().unwrap())
                .global(true))
        .subcommand(
            App::new("run")
                .version(env!("CARGO_PKG_VERSION")) // read the version string from cargo.toml
                .author(env!("CARGO_PKG_AUTHORS")) // and for the author(s) information as well
                .about("Relay data from MAWS to IoT Core")
        )
        .subcommand(
            App::new("configure")
                .version(env!("CARGO_PKG_VERSION")) // read the version string from cargo.toml
                .author(env!("CARGO_PKG_AUTHORS")) // and for the author(s) information as well
                .about("Create configuration and authentication files.")
                .arg(Arg::with_name("deviceid")
                    .long("device-id")
                    .short("i")
                    .help("Specify ID (name) of this device as it is known by the IoT Core registry.")
                    .takes_value(true)
                    .required(true))
                .arg(Arg::with_name("domain")
                    .long("domain")
                    .short("d")
                    .help("Specify alternate DNS domain to use for IOT Core connection settings detection.")
                    .default_value(include_str!("dns.txt")))
                .arg(Arg::with_name("cafile")
                    .long("ca")
                    .short("a")
                    .help("Specify alternate location of the CA certificate chain file.")
                    .default_value(default_ca_file_path.to_str().unwrap()))
                .arg(Arg::with_name("pubkey")
                    .long("public-certificate")
                    .short("e")
                    .help("Specify alternate location of the public certificate file.")
                    .default_value(default_pubkey_file_path.to_str().unwrap()))
                .arg(Arg::with_name("prikey")
                    .long("private-key")
                    .short("p")
                    .help("Specify alternate location of the private key file.")
                    .default_value(default_prikey_file_path.to_str().unwrap()))
                .arg(Arg::with_name("port")
                    .long("port")
                    .short("t")
                    .help("Specify alternate location of the RS232 port.")
                    .default_value("/dev/ttyr00"))
        )
        .get_matches();

    // if there are environment variable(s) set for rust log
    //  overwrite them here since command line arguments have higher priority
    match matches.occurrences_of("verbose") {
        0 => env::set_var("RUST_LOG", "error"),
        1 => env::set_var("RUST_LOG", "info"),
        _ => env::set_var("RUST_LOG", "debug")
    }
    // initialize logger
    pretty_env_logger::try_init_timed().unwrap();
    info!("Starting {} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // initialize software default data folders
    match fs::create_dir_all(project_dirs.config_dir()) {
        Ok(_) => debug!("Created application default config directory '{}'", project_dirs.config_dir().display()),
        Err(error) => {
            error!("Failed to create default application config folder '{}': {}", project_dirs.config_dir().display(), error);
            std::process::exit(exitcode::IOERR);
        }
    };
    match fs::create_dir_all(project_dirs.data_dir()) {
        Ok(_) => debug!("Created application data directory '{}'", project_dirs.data_dir().display()),
        Err(error) => {
            error!("Failed to create default application data folder '{}': {}", project_dirs.data_dir().display(), error);
            std::process::exit(exitcode::IOERR);
        }
    };

    if matches.is_present("run") {
        run_subcommand(&matches.value_of("config").unwrap()).await;
        std::process::exit(exitcode::OK);
    }

    if matches.is_present("configure") {
        config_subcommand(
            &matches.subcommand_matches("configure").unwrap().value_of("deviceid").unwrap(),
            &Path::new(matches.value_of("config").unwrap()),
            &matches.subcommand_matches("configure").unwrap().value_of("domain").unwrap(),
            &matches.subcommand_matches("configure").unwrap().value_of("port").unwrap(),
            &Path::new(matches.subcommand_matches("configure").unwrap().value_of("cafile").unwrap()),
            &Path::new(matches.subcommand_matches("configure").unwrap().value_of("pubkey").unwrap()),
            &Path::new(matches.subcommand_matches("configure").unwrap().value_of("prikey").unwrap())
        ).await;
        std::process::exit(exitcode::OK);
    }

    println!("{}", matches.usage());
    std::process::exit(exitcode::NOINPUT);
}

// eof
