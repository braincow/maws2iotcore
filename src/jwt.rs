use frank_jwt::{Algorithm, encode};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use crate::config::AppConfig;

pub fn issue_new_jwt_token(config: &AppConfig) -> Result<String, frank_jwt::Error> {
    // create JWT key that we shall use to authenticate towards iot core
    let now = SystemTime::now();
    let secs_since_epoc = now.duration_since(UNIX_EPOCH).unwrap();

    let payload = json!({
        "iat": secs_since_epoc.as_secs(),
        "exp": secs_since_epoc.as_secs() + 3600,
        "aud": config.iotcore.project_id
    });

    let header = json!({});

    let jwt = encode(header, &Path::new(&config.iotcore.private_key).to_path_buf(), &payload, Algorithm::RS256)?;

    Ok(jwt)
}