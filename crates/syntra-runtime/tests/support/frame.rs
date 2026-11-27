use syntra_core::{encode_frame, wire::frame::Body, ConnectionState, Frame, ValidationContext};

pub trait FrameFixture {
    fn fixture_bytes(&self) -> Vec<u8>;
}

impl FrameFixture for Frame {
    fn fixture_bytes(&self) -> Vec<u8> {
        use bebop::{Record, SliceWrapper};
        use syntra_core::{generated as g, wire::call_result::Outcome};

        // Negative tests send structurally valid calls with invalid methods/IDs
        // and zero-code errors; the peer (not our emitter) must reject them.
        let raw_body = match &self.body {
            Some(Body::Call(call)) => Some(g::FrameBody::Call {
                method: Some(&call.method),
                payload: Some(SliceWrapper::from_cooked(&call.payload)),
                timeout_ms: Some(call.timeout_ms),
            }),
            Some(Body::Result(result)) => match &result.outcome {
                None => {
                    return [
                        &self.version.to_le_bytes()[..],
                        &self.request_id.to_le_bytes(),
                        &[0, 0, 0, 0, 13],
                    ]
                    .concat()
                }
                Some(Outcome::Error(e)) => Some(g::FrameBody::CallResult {
                    outcome: g::CallOutcome::RpcError {
                        code: Some(e.code),
                        diagnostic: Some(&e.message),
                    },
                }),
                _ => None,
            },
            _ => None,
        };
        if let Some(body) = raw_body {
            let mut bytes = Vec::new();
            g::Frame {
                version: self.version,
                request_id: self.request_id,
                body,
            }
            .serialize(&mut bytes)
            .unwrap();
            return bytes;
        }
        if self.version == 0 {
            let mut valid = self.clone();
            valid.version = 1;
            let mut bytes = valid.fixture_bytes();
            bytes[..4].fill(0);
            return bytes;
        }
        let context = match self.body {
            Some(Body::Hello(_)) => ValidationContext::pre_handshake(ConnectionState::Connected),
            Some(Body::Ready(_)) => ValidationContext::pre_handshake(ConnectionState::Negotiating),
            _ => ValidationContext::active(self.version),
        };
        encode_frame(self, context).expect("valid fixture frame")
    }
}
