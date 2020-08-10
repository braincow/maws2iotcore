use std::fs::read_to_string;
use std::path::Path;
use openssl::x509::{X509, X509Name};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use openssl::asn1::Asn1Time;
use addr::Email;
use crate::lib::error::MawsToIotCoreError;

type SelfSignedCertificateError = MawsToIotCoreError;

pub struct SelfSignedCertificate {
    certificate: X509,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>
}

impl SelfSignedCertificate {
    pub fn certificate(&self) -> &X509 {
        &self.certificate
    }

    pub fn load_cerfificate_and_key(certpath: &Path, keypath: &Path) -> Result<SelfSignedCertificate, SelfSignedCertificateError> {
        let cert_pem = match read_to_string(certpath) {
            Ok(pem) => pem,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to read in certificate file '{}': {}", certpath.to_str().unwrap(), error)))
        };
        let cert = match X509::from_pem(&cert_pem.into_bytes()) {
            Ok(cert) => cert,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Error on loading certificate file '{}': {}", certpath.to_str().unwrap(), error)))
        };
        let key_pem = match read_to_string(keypath) {
            Ok(pem) => pem,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to read in key file '{}': {}", certpath.to_str().unwrap(), error)))
        };
        let key = match PKey::private_key_from_pem(&key_pem.into_bytes()) {
            Ok(key) => key,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Error on loading key file '{}': {}", certpath.to_str().unwrap(), error)))
        };

        Ok(SelfSignedCertificate{
            certificate: cert,
            private_key: key
        })
    }

    pub fn build_certificate(deviceid: &str, domain: &str) -> Result<SelfSignedCertificate, SelfSignedCertificateError> {
        let cn: Email = match format!("{}@{}", deviceid, domain).parse() {
            Ok(addr) => addr,
            Err(error) => {
                return Err(SelfSignedCertificateError::new(&format!("Unable to parse CN value from client id and domain name: {}", error)));
            }
        };

        let rsa = match Rsa::generate(2048) {
            Ok(rsa) => rsa,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Error on creating RSA key: {}", error)))
        };
        let pkey = match PKey::from_rsa(rsa) {
            Ok(pkey) => pkey,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Error on creating private key: {}", error)))
        };

        let mut name = match X509Name::builder() {
            Ok(name) => name,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to init X509 name builder: {}", error)))
        };
        match name.append_entry_by_nid(Nid::COMMONNAME, &format!("{}", cn)) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("CN field insert failed for X509: {}", error)))
        };
        let name = name.build();
    
        let mut builder = match X509::builder() {
            Ok(builder) => builder,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to init X509 builder: {}", error)))
        };
        match builder.set_version(2) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to set X509 version: {}", error)))
        };
        match builder.set_subject_name(&name) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to set X509 subject name: {}", error)))
        };
        match builder.set_issuer_name(&name) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to set X509 issuer name: {}", error)))
        };
        match builder.set_pubkey(&pkey) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to set X509 private key: {}", error)))
        };
        let not_before = match Asn1Time::days_from_now(0) {
            Ok(asn1) => asn1,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to build ASN1 not before timestamp: {}", error)))
        };
        let not_after = match Asn1Time::days_from_now(3650) {
            Ok(asn1) => asn1,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to build ASN1 not after timestamp: {}", error)))
        };
        match builder.set_not_before(not_before.as_ref()) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to set X509 not before: {}", error)))
        };
        match builder.set_not_after(not_after.as_ref()) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to set X509 not after: {}", error)))
        };
        match builder.sign(&pkey, MessageDigest::sha256()) {
            Ok(_) => {},
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to sign X509 as SHA256 digest: {}", error)))
        };
        let certificate: X509 = builder.build();
    
        Ok(SelfSignedCertificate {
            certificate: certificate,
            private_key: pkey
        })
    }

    pub fn as_certificate_pem(&self) -> Result<String, SelfSignedCertificateError> {
        let pem_bytes = match self.certificate.to_pem() {
            Ok(raw) => raw,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to convert X509 struct into UTF8 byte array: {}", error)))
        };
        let pem = match String::from_utf8(pem_bytes) {
            Ok(pem) => pem,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to convert X509 PEM bytes into UTF8 string: {}", error)))
        };
        Ok(pem)
    }

    pub fn as_private_key_pem(&self) -> Result<String, SelfSignedCertificateError> {
        let rsa_bytes = match self.private_key.rsa() {
            Ok(raw) => raw,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to convert RSA struct into PEM bytes: {}", error)))
        };
        let pem_bytes = match rsa_bytes.private_key_to_pem() {
            Ok(raw) => raw,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to convert RSA PEM bytes into UTF8 byte array: {}", error)))
        };
        let pem = match String::from_utf8(pem_bytes) {
            Ok(pem) => pem,
            Err(error) => return Err(SelfSignedCertificateError::new(&format!("Unable to convert RSA PEM bytes into UTF8 string: {}", error)))
        };
        Ok(pem)
    }
}
