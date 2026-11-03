//! Synthetic same-library peer for the browser API harness, NOT independent
//! interoperability, TLS, enrollment, authorization or conformance evidence.
//! Only compiled with browser-test-fixture; never ship this feature.

use std::sync::Arc;
use syntra_core::secure_channel::{
    frame_plaintext, respond, Carrier, Channel, Context, FrameDecoder, KeyStore, Mode, Secret32,
    ServerConfig, MAX_PLAINTEXT,
};
use syntra_core::{
    proto::{frame::Body, rpc_result::Outcome},
    ConnectionState, Frame, ValidationContext,
};
use wasm_bindgen::prelude::*;

struct Store;
impl KeyStore for Store {
    fn lookup(&self, context: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
        if context.handle != [7; 8] || context.epoch != 1 {
            return Err(syntra_core::secure_channel::Error::Authentication);
        }
        Ok(Secret32::new([9; 32]))
    }
}

#[wasm_bindgen]
pub struct ConnectionFixture {
    server: ServerConfig,
    public: [u8; 32],
    channel: Option<Channel>,
    decoder: FrameDecoder,
    ready: bool,
}

#[wasm_bindgen]
impl ConnectionFixture {
    #[wasm_bindgen(constructor)]
    pub fn new(returning: bool) -> Result<ConnectionFixture, JsValue> {
        let (private_key, public) =
            syntra_core::secure_channel::generate_server_key().map_err(crate::err)?;
        Ok(Self {
            server: ServerConfig {
                mode: if returning {
                    Mode::Returning
                } else {
                    Mode::Bootstrap
                },
                carrier: Carrier::SecureWebSocket,
                server_key_id: 0,
                scope: b"browser-fixture".to_vec(),
                private_key,
                store: returning.then(|| Arc::new(Store) as Arc<dyn KeyStore>),
            },
            public,
            channel: None,
            decoder: FrameDecoder::default(),
            ready: false,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    pub fn handshake(&mut self, first: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let (channel, second) = respond(&self.server, &first).map_err(crate::err)?;
        self.channel = Some(channel);
        Ok(second)
    }

    pub fn receive(&mut self, ciphertext: Vec<u8>) -> Result<js_sys::Array, JsValue> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| crate::err("fixture has no channel"))?;
        let plaintext = channel.decrypt(&ciphertext).map_err(crate::err)?;
        let frames = self.decoder.push(&plaintext).map_err(crate::err)?;
        let responses = js_sys::Array::new();
        for bytes in frames {
            let frame = syntra_core::decode_frame(
                &bytes,
                if self.ready {
                    ValidationContext::active(1)
                } else {
                    ValidationContext::pre_handshake(ConnectionState::Connected)
                },
            )
            .map_err(crate::err)?;
            let body = match frame.body {
                Some(Body::Hello(_)) if !self.ready && !self.decoder.is_partial() => {
                    self.ready = true;
                    Body::Ready(syntra_core::ServerReady {
                        connection_id: "browser-fixture".into(),
                    })
                }
                Some(Body::Request(request)) if self.ready => {
                    Body::Result(syntra_core::RpcResult {
                        outcome: Some(Outcome::Payload(request.payload)),
                    })
                }
                Some(Body::Cancel(_)) if self.ready => continue,
                _ => return Err(crate::err("invalid fixture envelope")),
            };
            let validation = if matches!(body, Body::Ready(_)) {
                ValidationContext::pre_handshake(ConnectionState::Authenticating)
            } else {
                ValidationContext::active(1)
            };
            let reply = syntra_core::encode_frame(
                &Frame {
                    version: 1,
                    request_id: frame.request_id,
                    body: Some(body),
                },
                validation,
            )
            .map_err(crate::err)?;
            let framed = frame_plaintext(&reply).map_err(crate::err)?;
            // Split even the u32 prefix to exercise browser inner reassembly.
            for chunk in framed.chunks(if framed.len() < 64 { 2 } else { MAX_PLAINTEXT }) {
                let encrypted = channel.encrypt(chunk).map_err(crate::err)?;
                responses.push(&js_sys::Uint8Array::from(encrypted.as_slice()));
            }
        }
        Ok(responses)
    }
}
