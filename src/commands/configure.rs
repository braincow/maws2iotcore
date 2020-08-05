use std::path::Path;
use std::fs;
use dialoguer::Confirm;
use crate::lib::certificate::SelfSignedCertificate;
use crate::lib::autodetect;
use crate::lib::config::AppConfig;

pub async fn config_subcommand(deviceid: &str, configfile: &Path, domain: &str, port: &str, cafile: &Path, pubkey: &Path, prikey: &Path) {
    // query DNS to acquire information about the registry
    let autodetected_config = match autodetect::AutoDetectedConfig::build(domain) {
        Ok(config) => config,
        Err(error) => {
            error!("Error while autodetecting settings from DNS: {}", error);
            std::process::exit(exitcode::OSERR);
        }
    };

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
        Ok(_) => info!("Config file '{}' created.", configfile.display()),
        Err(error) => {
            error!("Unable to create config file '{}': {}", configfile.display(), error);
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
            error!("Unable to create Certificate Chain file '{}': {}", cafile.display(), error);
            std::process::exit(exitcode::IOERR);
        }
    }

    // create locally X509 certificate and private key
    let x509 = match SelfSignedCertificate::build_certificate() {
        Ok(cert) => cert,
        Err(error) => {
            error!("Unable to build self signed certificate: {}", error);
            std::process::exit(exitcode::CANTCREAT);
        }
    };
    let cert_pem = x509.as_certificate_pem().unwrap();
    if pubkey.exists() {
        warn!("Certificate file '{}' already exists.", pubkey.display());
        if !Confirm::new().with_prompt("Do you wish to overwrite existing certificate?").default(false).interact().unwrap() {
            warn!("Aborting.");
            std::process::exit(exitcode::NOPERM);
        }
    }
    match fs::write(pubkey, cert_pem.clone()) {
        Ok(_) => info!("Wrote certificate file '{}'", pubkey.display()),
        Err(error) => {
            error!("Unable to write certificate file '{}': {}", pubkey.display(), error);
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
            error!("Unable to write private key file '{}': {}", prikey.display(), error);
            std::process::exit(exitcode::IOERR);
        }
    };

    // finalize configuration by conviniently showing to the user the contents of the public key
    println!("");
    println!("Use following X509 certificate (RS256_X509) as public key in IoT core when setting up this device:");
    println!("{}", cert_pem);
    println!("");
}

// eof
