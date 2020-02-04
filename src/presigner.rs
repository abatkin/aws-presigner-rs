use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use url::Url;

use crate::util::*;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

pub struct SigningCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

pub struct PresignerRequest {
    pub request_method: String,
    pub url: Url,
    pub headers: BTreeMap<String, Vec<String>>,
    pub payload: Vec<u8>,
}

pub struct SigningParams {
    pub double_encode_url: bool, // true for all services except S3
    pub region: String,
    pub service_name: String,
    pub expiry: Duration,
    pub timestamp: DateTime<Utc>,
}

pub fn presign(
    request: &PresignerRequest,
    params: &SigningParams,
    credentials: &SigningCredentials,
) -> String {
    let mut encoded_path = request.url.path().to_string();
    if params.double_encode_url {
        encoded_path = urlencode_path(&encoded_path);
    }

    let credential_scope =
        build_credential_scope(&params.timestamp, &params.region, &params.service_name);

    let presign_query_params = build_presign_query_params(
        request,
        params,
        &credential_scope,
        &credentials.access_key_id,
        &credentials.session_token,
    );
    let canonical_query_string = canonical_query_string(&presign_query_params);
    let encoded_request_payload_hash = hex_encode(&hash(&request.payload));
    let canonical_headers = canonical_headers(&request.headers);
    let signed_headers = signed_headers(&request.headers);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.request_method,
        encoded_path,
        canonical_query_string,
        canonical_headers,
        signed_headers,
        encoded_request_payload_hash
    );

    let request_date_time = to_timestamp_string(&params.timestamp);
    let hashed_canonical_request = hex_encode(&hash(canonical_request.as_bytes()));

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        ALGORITHM, request_date_time, credential_scope, hashed_canonical_request
    );

    let k_signing = derive_signing_key(
        &credentials.secret_access_key,
        &params.timestamp,
        &params.region,
        &params.service_name,
    );
    let signature = sign(&k_signing, &string_to_sign);

    let host = request.url.host_str().unwrap_or_else(|| "").to_string();
    let host_and_port = if let Some(port) = &request.url.port() {
        format!("{}:{}", host, port)
    } else {
        host
    };

    let url = format!(
        "{}://{}{}?{}&X-Amz-Signature={}",
        request.url.scheme(),
        host_and_port,
        request.url.path(),
        canonical_query_string,
        signature
    );

    url
}

fn derive_signing_key(
    secret_access_key: &str,
    timestamp: &DateTime<Utc>,
    region: &str,
    service_name: &str,
) -> Vec<u8> {
    let key_string = format!("AWS4{}", secret_access_key);
    let k_secret = key_string.as_bytes();
    let date_string = to_date_string(&timestamp);
    let k_date = hmac(k_secret, &date_string);
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service_name);
    hmac(&k_service, "aws4_request") // k_signing
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};

    use crate::presigner::{derive_signing_key, sign};
    use crate::util::*;

    fn build_test_signing_key() -> Vec<u8> {
        let k_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let date = Utc.ymd_opt(2015, 8, 30).and_hms_opt(0, 0, 0).unwrap();
        let region = "us-east-1";
        let service_name = "iam";
        derive_signing_key(k_secret, &date, region, service_name)
    }

    // From https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html step 1
    #[test]
    fn test_derive_signing_key() {
        let signing_key = build_test_signing_key();
        assert_eq!(
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
            hex_encode(&signing_key)
        );
    }

    #[test]
    // From https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html step 2
    fn test_signature() {
        let signing_key = build_test_signing_key();
        let string_to_sign = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
        let signature = sign(&signing_key, string_to_sign);
        assert_eq!(
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
            signature
        );
    }
}

fn build_credential_scope(date: &DateTime<Utc>, region: &str, service_name: &str) -> String {
    let date_string = to_date_string(&date);
    format!("{}/{}/{}/aws4_request", date_string, region, service_name)
}

pub fn build_presign_query_params(
    request: &PresignerRequest,
    params: &SigningParams,
    credential_scope: &str,
    access_key_id: &str,
    session_token: &Option<String>,
) -> BTreeMap<String, Vec<String>> {
    let mut presign_query_params: BTreeMap<String, Vec<String>> = BTreeMap::new();
    request.url.query_pairs().for_each(|(key, value)| {
        presign_query_params
            .entry(key.to_string())
            .or_default()
            .push(value.to_string());
    });

    let timestamp_string = to_timestamp_string(&params.timestamp);
    let signed_headers = signed_headers(&request.headers);

    presign_query_params.insert("X-Amz-Algorithm".to_string(), vec![ALGORITHM.to_string()]);
    presign_query_params.insert(
        "X-Amz-Credential".to_string(),
        vec![format!("{}/{}", access_key_id, credential_scope)],
    );
    presign_query_params.insert("X-Amz-Date".to_string(), vec![timestamp_string]);
    presign_query_params.insert(
        "X-Amz-Expires".to_string(),
        vec![format!("{}", params.expiry.as_secs())],
    );
    presign_query_params.insert("X-Amz-SignedHeaders".to_string(), vec![signed_headers]);
    if let Some(session_token) = session_token {
        presign_query_params.insert(
            "X-Amz-Security-Token".to_string(),
            vec![session_token.clone()],
        );
    }

    presign_query_params
}

fn canonical_query_string(params: &BTreeMap<String, Vec<String>>) -> String {
    let mut qs = String::new();
    let mut keys: Vec<String> = params.keys().map(|k| urlencode_param(k)).collect();
    keys.sort();
    for key in keys {
        let mut values: Vec<String> = params
            .get(&key)
            .unwrap()
            .iter()
            .map(|v| urlencode_param(v))
            .collect();
        values.sort();
        for value in values {
            if !qs.is_empty() {
                qs.push('&');
            }

            qs.push_str(&key);
            qs.push('=');
            qs.push_str(&value);
        }
    }
    qs
}

fn canonical_headers(headers: &BTreeMap<String, Vec<String>>) -> String {
    let mut hs = String::new();

    for (key, values) in headers {
        let value = values.join(",");
        let lc_key = key.to_lowercase();
        hs.push_str(&format!("{}:{}\n", lc_key, value));
    }

    hs
}

fn signed_headers(headers: &BTreeMap<String, Vec<String>>) -> String {
    let mut names: Vec<String> = headers.keys().map(|v| v.to_lowercase()).collect();
    names.sort();
    names.join(";")
}
