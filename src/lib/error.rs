use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub struct MawsToIotCoreError {
    details: String
}

impl MawsToIotCoreError {
    pub fn new(msg: &str) -> MawsToIotCoreError {
        MawsToIotCoreError {
            details: msg.to_string()
        }
    }
}

impl fmt::Display for MawsToIotCoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for MawsToIotCoreError {
    fn description(&self) -> &str {
        &self.details
    }
}
