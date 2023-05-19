use cassandra_cpp_sys::{
    cass_authenticator_set_response, cass_cluster_set_authenticator_callbacks, CassAuthenticator,
    CassAuthenticatorCallbacks, CassCluster,
};
use chrono::prelude::*;
use sha256;
use std::{
    env,
    ffi::{c_char, c_void, CStr},
    time::SystemTime,
};

const AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";
const AWS_REGION: &str = "AWS_REGION";

const INITIAL_RESPONSE: &str = "SigV4\0\0";

unsafe extern "C" fn initial_callback(
    auth: *mut cassandra_cpp_sys::CassAuthenticator,
    _: *mut c_void,
) {
    cass_authenticator_set_response(
        auth,
        INITIAL_RESPONSE.as_ptr().cast(),
        INITIAL_RESPONSE.len(),
    );
}

fn extract_none(token: &str) -> String {
    let params: Vec<&str> = token.split(",").collect();
    let nonce = params
        .iter()
        .find(|p| p.starts_with("nonce="))
        .unwrap()
        .replace("nonce=", "");
    nonce
}

fn form_canonical_request(
    access_key: &String,
    scope: &String,
    t: &DateTime<Utc>,
    nonce: &String,
) -> String {
    let nonce_hash: String = sha256::digest(nonce.as_bytes());
    let mut headers = vec![
        String::from("X-Amz-Algorithm=AWS4-HMAC-SHA256"),
        format!(
            "X-Amz-Credential={}%2F{}",
            access_key,
            url_escape::encode_component(scope)
        ),
        format!(
            "X-Amz-Date={}",
            url_escape::encode_component(&t.to_rfc3339_opts(SecondsFormat::Millis, true))
        ),
        String::from("X-Amz-Expires=900"),
    ];
    headers.sort_unstable();
    let query_string = headers.join("&");

    let cr = format!(
        "PUT\n/authenticate\n{}\nhost:cassandra\n\nhost\n{}",
        query_string, nonce_hash
    );
    cr
}

fn create_signature(
    canonical_request: &String,
    t: &DateTime<Utc>,
    signing_scope: &String,
    signing_key: &[u8],
) -> String {
    let digest: String = sha256::digest(canonical_request.as_bytes());
    let s = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        t.to_rfc3339_opts(SecondsFormat::Millis, true),
        signing_scope,
        digest
    );

    aws_sigv4::sign::calculate_signature(signing_key, s.as_bytes())
}

fn compute_scope(t: &DateTime<Utc>, region: &String) -> String {
    format!("{}/{}/cassandra/aws4_request", t.format("%Y%m%d"), region)
}

fn derive_secret_key(
    secret_access_key: &String,
    t: SystemTime,
    region: &String,
) -> impl AsRef<[u8]> {
    aws_sigv4::sign::generate_signing_key(
        secret_access_key.as_str(),
        t,
        region.as_str(),
        "cassandra",
    )
}

fn build_signed_response(
    region: &String,
    nonce: &String,
    access_key: &String,
    secret: &String,
    session_token: &Option<String>,
    t: SystemTime,
) -> String {
    let c_t = DateTime::<Utc>::from(t);
    let scope = compute_scope(&c_t, &region);
    let canonical_request = form_canonical_request(access_key, &scope, &c_t, &nonce);
    let sk = derive_secret_key(secret, t, region);

    let signature = create_signature(&canonical_request, &c_t, &scope, sk.as_ref());

    let mut result = format!(
        "signature={},access_key={},amzdate={}",
        signature,
        access_key,
        c_t.to_rfc3339_opts(SecondsFormat::Millis, true)
    );
    if let Some(session_token) = session_token {
        result.push_str(",session_token=");
        result.push_str(session_token)
    }

    result
}

unsafe extern "C" fn challenge_callback(
    auth: *mut CassAuthenticator,
    data: *mut c_void,
    token: *const c_char,
    _token_size: usize,
) {
    let config = data as *mut Config;
    let access_key = &config.as_ref().unwrap().access_key;
    let secret_access_key = &config.as_ref().unwrap().secret_access_key;
    let session_token = &config.as_ref().unwrap().session_token;
    let region = &config.as_ref().unwrap().region;

    let token = CStr::from_ptr(token).to_str().unwrap();
    let nonce = extract_none(token);

    let now = Utc::now();

    let result = build_signed_response(
        region,
        &nonce,
        access_key,
        secret_access_key,
        session_token,
        now.into(),
    );
    let result = format!("{}", result);
    let result_c_str = result.as_bytes();

    cass_authenticator_set_response(auth, result_c_str.as_ptr().cast(), result_c_str.len());
}

const CALLBACKS: CassAuthenticatorCallbacks = CassAuthenticatorCallbacks {
    initial_callback: Some(initial_callback),
    challenge_callback: Some(challenge_callback),
    success_callback: None,
    cleanup_callback: None,
};

fn sigv4_authenticators() -> *const CassAuthenticatorCallbacks {
    &CALLBACKS
}

pub struct Authenticator {
    access_key: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: String,
}

struct Config {
    access_key: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: String,
}

unsafe extern "C" fn cleanup_config(data: *mut c_void) {
    let config = Box::from_raw(data);
    drop(config);
}

impl Authenticator {
    pub fn new(
        access_key: String,
        secret_access_key: String,
        session_token: Option<String>,
        region: String,
    ) -> Self {
        return Authenticator {
            access_key,
            secret_access_key,
            session_token,
            region,
        };
    }

    pub fn default() -> Self {
        let access_key =
            env::var(AWS_ACCESS_KEY_ID).expect("AWS_ACCESS_KEY_ID env variable is missing");
        let secret_access_key =
            env::var(AWS_SECRET_ACCESS_KEY).expect("AWS_SECRET_ACCESS_KEY env variable is missing");
        let session_token = env::var(AWS_SESSION_TOKEN).ok();
        let region = env::var(AWS_DEFAULT_REGION).or_else(|_| env::var(AWS_REGION)).expect("AWS_DEFAULT_REGION and AWS_REGION env variables are missing. Setup at least one of them ");
        Authenticator {
            access_key,
            secret_access_key,
            session_token,
            region,
        }
    }

    pub fn set_authenticator(&self, cluster: *mut CassCluster) {
        unsafe {
            let config = Box::new(Config {
                access_key: self.access_key.clone(),
                secret_access_key: self.secret_access_key.clone(),
                session_token: self.session_token.clone(),
                region: self.region.clone(),
            });
            let config_ptr = Box::into_raw(config) as *mut Config as *mut c_void;
            cass_cluster_set_authenticator_callbacks(
                cluster,
                sigv4_authenticators(),
                Some(cleanup_config),
                config_ptr,
            );
        }
    }
}

#[cfg(test)]
mod lib_test {
    use super::*;

    const NONCE: &str = "91703fdc2ef562e19fbdab0f58e42fe5";
    const REGION: &str = "us-west-2";
    const ACCESS_KEY_ID: &str = "UserID-1";
    const SECRET: &str = "UserSecretKey-1";

    fn time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2020-06-09T22:41:51Z")
            .unwrap()
            .into()
    }

    #[test]
    fn extract_nonce_test() {
        let challenge = "nonce=1256";
        let actual_nonce = extract_none(challenge);
        assert_eq!(actual_nonce, "1256");
    }

    #[test]
    fn extract_nonce_test_multiple_params() {
        let challenge = "param1=dfg,nonce=1256,param2=hhhh";
        let actual_nonce = extract_none(challenge);
        assert_eq!(actual_nonce, "1256");
    }

    #[test]
    #[should_panic]
    fn extract_no_nonce() {
        let challenge = "n1256";
        extract_none(challenge);
    }

    #[test]
    fn compute_scope_test() {
        let scope = compute_scope(&time(), &"us-west-2".to_string());
        assert_eq!("20200609/us-west-2/cassandra/aws4_request", scope);
    }

    #[test]
    fn form_canonical_request_test() {
        let scope = String::from("20200609/us-west-2/cassandra/aws4_request");
        let mut canonical_request = String::from("");
        canonical_request.push_str("PUT\n");
        canonical_request.push_str("/authenticate\n");
        canonical_request.push_str("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=UserID-1%2F20200609%2Fus-west-2%2Fcassandra%2Faws4_request&X-Amz-Date=2020-06-09T22%3A41%3A51.000Z&X-Amz-Expires=900\n");
        canonical_request.push_str("host:cassandra\n\n");
        canonical_request.push_str("host\n");
        canonical_request
            .push_str("ddf250111597b3f35e51e649f59e3f8b30ff5b247166d709dc1b1e60bd927070");

        let actual = form_canonical_request(
            &String::from("UserID-1"),
            &scope,
            &time(),
            &NONCE.to_string(),
        );
        assert_eq!(canonical_request, actual);
    }

    #[test]
    fn get_signing_key() {
        let mock_now = SystemTime::from(time());
        let expected =
            hex::decode("7fb139473f153aec1b05747b0cd5cd77a1186d22ae895a3a0128e699d72e1aba")
                .unwrap();
        let actual = derive_secret_key(&SECRET.to_string(), mock_now, &REGION.to_string());
        assert_eq!(expected, actual.as_ref());
    }

    #[test]
    fn create_signature_test() {
        let sk = hex::decode("7fb139473f153aec1b05747b0cd5cd77a1186d22ae895a3a0128e699d72e1aba")
            .unwrap();
        let scope = String::from("20200609/us-west-2/cassandra/aws4_request");

        let mut canonical_request = String::from("");
        canonical_request.push_str("PUT\n");
        canonical_request.push_str("/authenticate\n");
        canonical_request.push_str("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=UserID-1%2F20200609%2Fus-west-2%2Fcassandra%2Faws4_request&X-Amz-Date=2020-06-09T22%3A41%3A51.000Z&X-Amz-Expires=900\n");
        canonical_request.push_str("host:cassandra\n\n");
        canonical_request.push_str("host\n");
        canonical_request
            .push_str("ddf250111597b3f35e51e649f59e3f8b30ff5b247166d709dc1b1e60bd927070");

        let actual = create_signature(&canonical_request, &time(), &scope, &sk);
        let expected = "7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87";

        assert_eq!(expected, actual);
    }

    #[test]
    fn build_signed_response_test() {
        let actual = build_signed_response(
            &REGION.to_string(),
            &NONCE.to_string(),
            &ACCESS_KEY_ID.to_string(),
            &SECRET.to_string(),
            &None,
            time().into(),
        );
        let expected = "signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z";
        assert_eq!(expected, actual);
    }

    #[test]
    fn build_signed_response_session_test() {
        let actual = build_signed_response(
            &REGION.to_string(),
            &NONCE.to_string(),
            &ACCESS_KEY_ID.to_string(),
            &SECRET.to_string(),
            &Some("sess-token-1".to_string()),
            time().into(),
        );
        let expected = "signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z,session_token=sess-token-1";
        assert_eq!(expected, actual);
    }
}
