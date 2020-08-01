use openssl::x509::{X509, X509Name};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::nid::Nid;
use openssl::asn1::Asn1Time;

pub struct SelfSignedCertificate {
    certificate: X509,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>
}

impl SelfSignedCertificate {
    pub fn build_certificate() -> Result<SelfSignedCertificate, openssl::error::ErrorStack> {
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

    pub fn as_certificate_pem(&self) -> Result<String, Box<dyn std::error::Error>> {
        let pem = self.certificate.to_pem()?;
        Ok(String::from_utf8(pem)?)
    }

    pub fn as_private_key_pem(&self) -> Result<String, Box<dyn std::error::Error>> {
        let rsa = self.private_key.rsa()?;
        Ok(String::from_utf8(rsa.private_key_to_pem()?)?)
    }
}
