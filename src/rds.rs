use std::collections::BTreeMap;
use std::time::Duration;

use chrono::Utc;
use url::Url;

use crate::error;
use crate::presigner;

pub fn presign_rds_iam(
    credentials: &presigner::SigningCredentials,
    host_and_port: &str,
    iam_username: &str,
    region: &str,
    duration: &Duration,
) -> Result<String, error::Error> {
    let mut headers = BTreeMap::new();
    headers.insert("Host".to_string(), vec![host_and_port.to_string()]);

    let url = Url::parse_with_params(
        &format!("http://{}/", host_and_port),
        vec![("Action", "connect"), ("DBUser", iam_username)],
    )
    .map_err(|_e| error::Error::new("bad host/port"))?;

    let request = presigner::PresignerRequest {
        request_method: "GET".to_string(),
        url,
        headers,
        payload: vec![],
    };

    let params = presigner::SigningParams {
        double_encode_url: true,
        region: region.to_string(),
        service_name: "rds-db".to_string(),
        expiry: *duration,
        timestamp: Utc::now(),
    };

    let url = presigner::presign(&request, &params, credentials);

    Ok(url)
}
