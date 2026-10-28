//! Native loopback client API tests. These are NOT browser tests.
//!
//! On native targets `connect` wires the in-memory loopback
//! with neutral fixtures so the registry/call/notify/close contract is
//! testable without a browser.
//!
//! `JsValue` error construction is unsupported natively. Typed polling
//! regressions live in lib.rs; browser rejection paths use browser.html
//! with configured real WSS fixtures, not a fictitious loopback URL.

#![cfg(not(target_arch = "wasm32"))]

#[tokio::test]
async fn connect_call_close_round_trip() {
    // The registry is process-global and tests run in parallel, so this
    // test asserts per-id behavior only (no global counts).
    let id = syntra_web::connect("loopback://test".to_string(), vec![])
        .await
        .expect("connect");
    let out = syntra_web::call(id, "/example.Echo/Echo".to_string(), b"web".to_vec(), 2000)
        .await
        .expect("call");
    assert_eq!(out, b"web");
    assert!(syntra_web::close(id).await);
    // Second close reports unknown (no JsValue involved).
    assert!(!syntra_web::close(id).await);
    assert!(!syntra_web::close(424242).await);
}

#[tokio::test]
async fn notify_poll_timeout_is_none() {
    let id = syntra_web::connect("loopback://test".to_string(), vec![])
        .await
        .expect("connect");
    // No notifications sent: bounded wait resolves None.
    let got = syntra_web::poll_notify(id, 100).await.expect("poll");
    assert!(got.is_none());
    assert!(syntra_web::close(id).await);
}
