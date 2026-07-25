use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::error::ProxyError;
use crate::route::{classify, RouteVerdict};

/// Runs the M1 transport + routing skeleton (plan §10.3, milestone 1): a plain-HTTP loopback
/// server with no TLS layer and no upstream client at all. Every accepted connection is
/// classified by [`crate::route::classify`]; matched routes (`Mask`/`Pass`) get a test-double
/// response, never a forwarded one — egress is impossible by construction in this milestone,
/// not merely policy-denied. Unmatched routes are rejected. Runs until `shutdown` resolves.
pub async fn run(
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ProxyError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ProxyError::Bind { addr, source })?;

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(handle))
                        .await
                    {
                        eprintln!("vg-proxy: connection error: {err}");
                    }
                });
            }
        }
    }
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    Ok(test_double_response(
        classify(&method, &target),
        &method,
        &target,
    ))
}

/// M1's stand-in for "forward to the real upstream" — there is no upstream client in this
/// milestone, so a matched route is echoed back to the caller instead, never dispatched
/// anywhere. `Block` fails closed with 403, matching the plan's fail-closed rule (§5 step 2:
/// "any other route BLOCKS; it is never passed through").
fn test_double_response(
    verdict: RouteVerdict,
    method: &Method,
    target: &str,
) -> Response<Full<Bytes>> {
    match verdict {
        RouteVerdict::Mask | RouteVerdict::Pass => Response::builder()
            .status(StatusCode::OK)
            .header("x-vg-proxy-verdict", verdict_name(verdict))
            .body(Full::new(Bytes::from(format!(
                "vg-proxy M1 test double: {method} {target} matched ({}) \
                 — not forwarded, no upstream client exists yet\n",
                verdict_name(verdict)
            ))))
            .expect("static response is well-formed"),
        RouteVerdict::Block => Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("x-vg-proxy-verdict", "block")
            .body(Full::new(Bytes::from(format!(
                "vg-proxy: {method} {target} is not a recognized route — fail closed\n"
            ))))
            .expect("static response is well-formed"),
    }
}

fn verdict_name(verdict: RouteVerdict) -> &'static str {
    match verdict {
        RouteVerdict::Mask => "mask",
        RouteVerdict::Pass => "pass",
        RouteVerdict::Block => "block",
    }
}
