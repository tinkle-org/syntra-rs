//! Native support checks only. Protected browser connection behavior is exercised
//! by connection-browser.html, never by silently substituting a native loopback.
#![cfg(not(target_arch = "wasm32"))]

#[tokio::test]
async fn unknown_close_does_not_create_a_fixture_client() {
    assert!(!syntra_web::close(424242).await.unwrap());
    assert_eq!(syntra_web::client_count(), 0);
}

#[cfg(feature = "browser-connection")]
#[test]
fn support_discloses_protected_authentication_and_browser_limitations() {
    let support = syntra_web::connection_support();
    assert!(support.contains("syntra.1.0"));
    assert!(support.contains("NK and NKpsk0 authentication"));
    assert!(support.contains("UNSUPPORTED:"));
    assert!(support.contains("Syntra 1.0; NK and NKpsk0 authentication; syntra.1.0 context;"));
    assert!(support.contains("encrypted hello; ordered records;"));
}
