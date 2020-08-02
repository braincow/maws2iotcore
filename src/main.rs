mod commands;
mod lib;

#[macro_use] extern crate log;
#[macro_use] extern crate serde_json;

use clap::{App, Arg};
use dotenv::dotenv;
use directories::ProjectDirs;
use std::path::Path;
use std::{fs, env};
use crate::commands::configure::config_subcommand;
use crate::commands::run::run_subcommand;

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
        1 => env::set_var("RUST_LOG", "warn"),
        2 => env::set_var("RUST_LOG", "info"),
        3 => env::set_var("RUST_LOG", "debug"),
        _ => env::set_var("RUST_LOG", "trace")
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
