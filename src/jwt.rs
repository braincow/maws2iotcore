use frank_jwt::{Algorithm, encode};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::{Path, PathBuf};
use serde::Serialize;
use crate::config::AppConfig;

#[derive(Debug, Serialize)]
pub struct JWTHeaders;

#[derive(Debug, Serialize)]
pub struct JWTPayload {
    iat: u64,
    exp: u64,
    aud: String
}

impl JWTPayload {
    fn new(audience: &String) -> JWTPayload {
        let now = SystemTime::now();
        let secs_since_epoc = now.duration_since(UNIX_EPOCH).unwrap();
    
        JWTPayload {
            iat: secs_since_epoc.as_secs(),
            exp: secs_since_epoc.as_secs() + 3600,
            aud: audience.clone()
        }
    }
}

pub struct IotCoreAuthToken {
    headers: JWTHeaders,
    payload: JWTPayload,
    private_key: PathBuf,
    audience: String
}

impl IotCoreAuthToken {
    pub fn build(config: &AppConfig) -> IotCoreAuthToken {
        IotCoreAuthToken {
            headers: JWTHeaders,
            payload: JWTPayload::new(&config.iotcore.project_id),
            private_key: Path::new(&config.iotcore.private_key).to_path_buf(),
            audience: config.iotcore.project_id.clone()
        }
    }

    pub fn issue_new(&self) -> Result<String, frank_jwt::Error> {
        let jwt = encode(json!(self.headers), &self.private_key, &json!(self.payload), Algorithm::RS256)?;
        Ok(jwt)
    }

    pub fn renew(&mut self) -> Result<String, frank_jwt::Error> {
        self.payload = JWTPayload::new(&self.audience);
        self.issue_new()
    }
}

// eof
