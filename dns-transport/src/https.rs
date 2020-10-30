#![cfg_attr(not(feature="https"), allow(unused))]

use async_trait::async_trait;
use log::*;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **HTTPS transport**, which uses Hyper.
///
/// # Examples
///
/// ```no_run
/// use dns_transport::{Transport, HttpsTransport};
/// use dns::{Request, Flags, Query, Labels, QClass, qtype, record::A};
///
/// let query = Query {
///     qname: Labels::encode("dns.lookup.dog").unwrap(),
///     qclass: QClass::IN,
///     qtype: qtype!(A),
/// };
///
/// let request = Request {
///     transaction_id: 0xABCD,
///     flags: Flags::query(),
///     query: query,
///     additional: None,
/// };
///
/// let transport = HttpsTransport::new("https://cloudflare-dns.com/dns-query");
/// transport.send(&request);
/// ```
#[derive(Debug)]
pub struct HttpsTransport {
    url: String,
}

impl HttpsTransport {

    /// Creates a new HTTPS transport that connects to the given URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

#[async_trait]
impl Transport for HttpsTransport {

    #[cfg(feature="https")]
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        use hyper::body::HttpBody as _;

        let https = hyper_tls::HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, hyper::Body>(https);

        let bytes = request.to_bytes().expect("failed to serialise request");
        info!("Sending {} bytes of data to {:?}", bytes.len(), self.url);

        let request = hyper::Request::builder()
            .method("POST")
            .uri(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept",       "application/dns-message")
            .body(hyper::Body::from(bytes))
            .expect("Failed to build request");  // we control the request, so this should never fail

        let mut response = client.request(request).await?;
        debug!("Response: {}", response.status());
        debug!("Headers: {:#?}", response.headers());

        if response.status() != 200 {
            return Err(Error::BadRequest);
        }

        debug!("Reading body...");
        let mut buf = Vec::new();
        while let Some(chunk) = response.body_mut().data().await {
            buf.extend(&chunk?);
        }

        info!("Received {} bytes of data", buf.len());
        let response = Response::from_bytes(&buf)?;

        Ok(response)
    }

    #[cfg(not(feature="https"))]
    async fn send(&self, _request: &Request) -> Result<Response, Error> {
        unimplemented!("HTTPS feature disabled")
    }
}
