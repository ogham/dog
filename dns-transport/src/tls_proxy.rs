use core::convert::{TryFrom, TryInto};
use std::error::Error as StdError;
use std::net::TcpStream;
use std::env;
use std::io::{Read, Write};
use std::collections::HashMap;
use std::time::Duration;
use super::to_socket_addr;

use super::error::Error;
use http::header::HeaderValue;
use url::Url;

/// A particular scheme used for proxying requests.
///
/// For example, HTTP vs SOCKS5
#[derive(Clone)]
pub enum ProxyScheme {
    Http {
        auth: Option<HeaderValue>,
        host: http::uri::Authority,
    },
    Https {
        auth: Option<HeaderValue>,
        host: http::uri::Authority,
    },
    // TODO: leave socks5 out for now
}

impl TryFrom<String> for ProxyScheme {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        use url::Position;
        // validate the URL
        let url = parse_url_string(value)?;
        let scheme = match url.scheme() {
            "http" => Self::Http{auth: None, host: url[Position::BeforeHost..Position::AfterPort].parse()?},
            "https" => Self::Https{auth: None, host: url[Position::BeforeHost..Position::AfterPort].parse()?},
            _ => return Err(Error::ProxyError("Invalid uri".into())),
        };
        Ok(scheme)
    }
}

fn parse_url_string(value: String) -> Result<Url, Error> {
    // validate the URL
    let url = match Url::parse(&value) {
        Ok(ok) => ok,
        Err(e) => {
            let mut presumed_to_have_scheme = true;
            let mut source = e.source();
            while let Some(err) = source {
                if let Some(parse_error) = err.downcast_ref::<url::ParseError>() {
                    match parse_error {
                        url::ParseError::RelativeUrlWithoutBase => {
                            presumed_to_have_scheme = false;
                            break;
                        }
                        _ => {}
                    }
                }
                source = err.source();
            }
            if presumed_to_have_scheme {
                return Err(Error::ProxyError("Invalid url".into()));
            }
            // the issue could have been caused by a missing scheme, so we try adding http://
            let try_this = format!("http://{}", value);
            parse_url_string(try_this)?
        }
    };
    Ok(url)
}


type SystemProxyMap = HashMap<String, ProxyScheme>;

/// Get system proxies information.
///
/// All platforms will check for proxy settings via environment variables.
/// If those aren't set, platform-wide proxy settings will be looked up on
/// Windows and MacOS platforms instead. Errors encountered while discovering
/// these settings are ignored.
///
/// Returns:
///     System proxies information as a hashmap like
///     {"http": Url::parse("http://127.0.0.1:80"), "https": Url::parse("https://127.0.0.1:80")}
fn get_sys_proxies(
    #[cfg_attr(
        not(any(target_os = "windows", target_os = "macos")),
        allow(unused_variables)
    )]
    platform_proxies: Option<String>,
) -> SystemProxyMap {
    let proxies = get_from_environment();

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    if proxies.is_empty() {
        // if there are errors in acquiring the platform proxies,
        // we'll just return an empty HashMap
        if let Some(platform_proxies) = platform_proxies {
            return parse_platform_values(platform_proxies);
        }
    }

    proxies
}

fn insert_proxy(proxies: &mut SystemProxyMap, scheme: impl Into<String>, addr: String) -> bool {
    if addr.trim().is_empty() {
        // do not accept empty or whitespace proxy address
        false
    } else if let Ok(valid_addr) = addr.try_into() {
        proxies.insert(scheme.into(), valid_addr);
        true
    } else {
        false
    }
}

fn get_from_environment() -> SystemProxyMap {
    let mut proxies = HashMap::new();

    if !insert_from_env(&mut proxies, "http", "HTTP_PROXY") {
        insert_from_env(&mut proxies, "http", "http_proxy");
    }

    if !insert_from_env(&mut proxies, "https", "HTTPS_PROXY") {
        insert_from_env(&mut proxies, "https", "https_proxy");
    }

    if !(insert_from_env(&mut proxies, "http", "ALL_PROXY")
        && insert_from_env(&mut proxies, "https", "ALL_PROXY"))
    {
        insert_from_env(&mut proxies, "http", "all_proxy");
        insert_from_env(&mut proxies, "https", "all_proxy");
    }

    proxies
}

fn insert_from_env(proxies: &mut SystemProxyMap, scheme: &str, var: &str) -> bool {
    if let Ok(val) = env::var(var) {
        insert_proxy(proxies, scheme, val)
    } else {
        false
    }
}

/// make a http connect tunnel for tls stream
#[cfg(any(feature = "with_nativetls", feature = "with_nativetls_vendored"))]
pub fn tunnel(
    mut stream: TcpStream,
    host: String,
    port: u16,
    user_agent: Option<HeaderValue>,
    auth: Option<HeaderValue>,
) -> Result<TcpStream, Error>
{

    let mut buf = format!(
        "\
        CONNECT {0}:{1} HTTP/1.1\r\n\
        Host: {0}:{1}\r\n\
        ",
        host, port
    )
    .into_bytes();

    // user-agent
    if let Some(user_agent) = user_agent {
        buf.extend_from_slice(b"User-Agent: ");
        buf.extend_from_slice(user_agent.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // proxy-authorization
    if let Some(value) = auth {
        log::debug!("tunnel to {}:{} using basic auth", host, port);
        buf.extend_from_slice(b"Proxy-Authorization: ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // headers end
    buf.extend_from_slice(b"\r\n");
    let written_len = stream.write(&buf)?;

    if written_len != buf.len() {
        return Err(Error::ProxyError("failed to send tunnel request".into()));
    }

    let mut buf = [0; 8192];
    let mut pos = 0;

    loop {
        let n = stream.read(&mut buf[pos..])?;

        if n == 0 {
            return Err(Error::ProxyError("unexpected eof while tunneling".into()));
        }
        pos += n;

        let recvd = &buf[..pos];
        if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
            if recvd.ends_with(b"\r\n\r\n") {
                return Ok(stream);
            }
            if pos == buf.len() {
                return Err(Error::ProxyError("proxy headers too long for tunnel".into()));
            }
        // else read more
        } else if recvd.starts_with(b"HTTP/1.1 407") {
            return Err(Error::ProxyError("proxy authentication required".into()));
        } else {
            return Err(Error::ProxyError("unsuccessful tunnel".into()));
        }
    }
}

/// setup a maybe proxied stream
pub fn auto_stream(domain: &str, port: u16, timeout: Option<Duration>) -> Result<TcpStream, Error>
{
    // check proxy config and use https proxy if possible
    let proxies: HashMap<String, ProxyScheme> = get_sys_proxies(None);
    
    if let Some(proxy) = proxies.get("https") {
        match proxy {
            ProxyScheme::Http { auth: _, host } => {
                // TODO Implement time-out
                let mut stream = TcpStream::connect(host.as_str())?;
                stream = tunnel(stream, domain.into(), port, None, None)?;
                return Ok(stream);
            }
            #[cfg(any(feature = "with_nativetls", feature = "with_nativetls_vendored"))]
            ProxyScheme::Https { auth: _, host } => {
                // TODO Implement time-out
                let connector = native_tls::TlsConnector::new()?;
                let mut stream = TcpStream::connect(host.as_str())?;
                connector.connect(domain, stream.try_clone()?)?;
                stream = tunnel(stream, domain.into(), port, None, None)?;
                return Ok(stream);
            }
            #[cfg(feature = "with_rustls")]
            ProxyScheme::Https { auth, host } => {
                todo!("not implemented for rustls")
            }
        }
        
    } else {
        let sock_addr = to_socket_addr(domain, port)?;
        let stream = if timeout.is_none() {TcpStream::connect(&sock_addr)?} else { TcpStream::connect_timeout(&sock_addr, timeout.unwrap())?};
        Ok(stream)
    }
}
