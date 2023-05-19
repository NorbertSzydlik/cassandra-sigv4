# Authorizer for AWS sigv4 and cassandra-cpp-sys (DataStax cpp driver)

It uses `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_DEFAULT_REGION`, `AWS_REGION` for configuration.

Example usage with cassandra-rs (cassandra-cpp crate):
```
use tokio;
use std::fs;

use cassandra_cpp::*;
use cassandra_sigv4::*;

#[tokio::main]
async fn main() {
    let mut cluster = Cluster::default();
    cluster.set_contact_points("cassandra.eu-central-1.amazonaws.com").unwrap();
    cluster.set_port(9142).unwrap();

    // Add these lines to use SigV4 authentication
    let auth = Authenticator::default();
    auth.set_authenticator(cluster.0);

    let cert = fs::read_to_string("./sf-class2-root.crt")
        .expect("Certificate is missing");

    let mut ssl = Ssl::default();
    ssl.add_trusted_cert(cert.as_str()).unwrap();
    ssl.set_verify_flags(&[SslVerifyFlag::NONE]);
    cluster.set_ssl(ssl);

    let session = cluster.connect().await.unwrap();
    let statement = session.statement("SELECT keyspace_name FROM system_schema.keyspaces");
    let result = statement.execute().await.unwrap();
    for row in result.iter() {
        let keyspace_name: String = row.get(0).unwrap();
        println!("Keyspace: {}", keyspace_name);
    }
}

```
