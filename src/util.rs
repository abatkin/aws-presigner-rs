use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use percent_encoding::AsciiSet;
use sha2::{Digest, Sha256};

const URLENCODE_PATH: AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');

const URLENCODE_PARAM: AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub fn urlencode_path(data: &str) -> String {
    percent_encoding::percent_encode(data.as_bytes(), &URLENCODE_PATH).to_string()
}

pub fn urlencode_param(data: &str) -> String {
    percent_encoding::percent_encode(data.as_bytes(), &URLENCODE_PARAM).to_string()
}

pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(data);
    hasher.result().to_vec()
}

type HmacSha256 = Hmac<Sha256>;

pub fn hmac(key: &[u8], value: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_varkey(key).expect("unable to create HMAC");
    mac.input(value.as_bytes());
    mac.result().code().into_iter().collect()
}

pub fn sign(signing_key: &[u8], string_to_sign: &str) -> String {
    hex_encode(&hmac(signing_key, string_to_sign))
}

pub fn to_date_string(date: &DateTime<Utc>) -> String {
    date.format("%Y%m%d").to_string()
}

pub fn to_timestamp_string(date: &DateTime<Utc>) -> String {
    date.format("%Y%m%dT%H%M%SZ").to_string()
}
