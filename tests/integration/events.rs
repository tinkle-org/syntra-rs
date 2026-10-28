//! Neutral event fixtures (host -> initiator notifications).
//!
//! Notifications carry opaque bytes and never complete an RPC
//! (SNTR-RPC-020, SNTR-EVENT-005). Empty payloads are valid events
//! (SNTR-WIRE-007). These fixtures drive delivery, ordering, and the
//! bounded-queue drop policy; they assert nothing about application
//! meaning.

/// Representative event payloads, including the empty event.
pub fn event_payloads() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"tick".to_vec(),
        vec![0x00, 0xff, 0x01],
        vec![0x55; 512],
    ]
}
