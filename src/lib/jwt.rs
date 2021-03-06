use frank_jwt::{Algorithm, encode};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::{Path, PathBuf};
use serde::Serialize;
use crate::lib::config::AppConfig;

#[derive(Debug, Serialize)]
pub struct JWTHeaders;

#[derive(Debug, Serialize)]
pub struct JWTPayload {
    iat: u64,
    exp: u64,
    aud: String
}

impl JWTPayload {
    fn new(audience: &String, lifetime: &u64) -> JWTPayload {
        let now = SystemTime::now();
        let secs_since_epoc = now.duration_since(UNIX_EPOCH).unwrap();
    
        JWTPayload {
            iat: secs_since_epoc.as_secs(),
            exp: secs_since_epoc.as_secs() + lifetime,
            aud: audience.clone()
        }
    }
}

pub struct IotCoreAuthToken {
    headers: JWTHeaders,
    payload: JWTPayload,
    private_key: PathBuf,
    audience: String,
    lifetime: u64
}

impl IotCoreAuthToken {
    pub fn build(config: &AppConfig) -> IotCoreAuthToken {
        IotCoreAuthToken {
            headers: JWTHeaders,
            payload: JWTPayload::new(&config.iotcore.project_id, &config.iotcore.token_lifetime),
            private_key: Path::new(&config.iotcore.private_key).to_path_buf(),
            audience: config.iotcore.project_id.clone(),
            lifetime: config.iotcore.token_lifetime
        }
    }

    pub fn issue_new(&self) -> Result<String, frank_jwt::Error> {
        let jwt = encode(json!(self.headers), &self.private_key, &json!(self.payload), Algorithm::RS256)?;
        Ok(jwt)
    }

    pub fn renew(&mut self) -> Result<String, frank_jwt::Error> {
        self.payload = JWTPayload::new(&self.audience, &self.lifetime);
        self.issue_new()
    }

    pub fn is_valid(&self, threshold: u64) -> bool {
        let now = SystemTime::now();
        let secs_since_epoc = now.duration_since(UNIX_EPOCH).unwrap();

        if secs_since_epoc.as_secs() > self.payload.exp - threshold {
            debug!("JWT token has expired / is expiring within the threshold.");
            return false
        }

        debug!("JWT token has not expired.");
        true
    }
}

// eof
