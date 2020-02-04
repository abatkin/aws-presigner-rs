use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
}

impl Error {
    pub fn new(message: &str) -> Error {
        Error {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for Error {}
