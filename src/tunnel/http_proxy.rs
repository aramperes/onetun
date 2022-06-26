use std::convert::Infallible;
use std::net::SocketAddr;
use crate::{PortProtocol, TcpPortPool};
use crate::Bus;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Server, Method, Request, Body, Response, http};
use hyper::server::conn::AddrStream;
use crate::config::PortForwardConfig;
use crate::tunnel::tcp::handle_tcp_proxy_connection;

pub async fn http_proxy_server(
    listen_addr: SocketAddr,
    port_pool: TcpPortPool,
    bus: Bus,
) -> anyhow::Result<()> {

    let make_service = make_service_fn(move |conn: &AddrStream| {
        let bus = bus.clone();
        let port_pool = port_pool.clone();
        let addr = conn.remote_addr();
        async move {
            let addr = addr.clone();
            Ok::<_, Infallible>(service_fn(move |req| proxy(addr, req, port_pool.clone(), bus.clone())))
        }
    });

    let server = Server::bind(&listen_addr).serve(make_service);

    Ok(server.await?)

}

async fn proxy(remote_addr: SocketAddr, req: Request<Body>, port_pool: TcpPortPool, bus: Bus) -> Result<Response<Body>, hyper::Error> {
    debug!("http request from {}: {:?}", remote_addr, req);

    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let config = PortForwardConfig {
                            destination: addr.parse().expect("failed to parse destination SocketAddr"),
                            source: remote_addr, // doesn't matter, won't be used
                            protocol: PortProtocol::Tcp,
                            remote: false
                        };
                        info!("proxy {} -> {}", remote_addr, config.destination);
                        if let Err(e) = handle_tcp_proxy_connection(upgraded, port_pool.next().await.unwrap(), config, bus.clone()).await {
                            eprintln!("server io error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(Body::empty()))
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        let mut resp = Response::new(Body::from("Only CONNECT method supported"));
        *resp.status_mut() = http::StatusCode::METHOD_NOT_ALLOWED;

        Ok(resp)
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}