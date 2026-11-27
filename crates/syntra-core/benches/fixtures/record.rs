use std::sync::Arc;
use syntra_core::secure_channel::{
    generate_server_key, respond, Carrier, ClientConfig, ClientHandshake, Context, Error, KeyStore,
    Mode, Secret32, ServerConfig,
};

pub const RECORD_SIZES: [usize; 3] = [64, 1024, 65_519];

struct FixedStore;

impl KeyStore for FixedStore {
    fn lookup(&self, ctx: &Context) -> Result<Secret32, Error> {
        if ctx.handle == [1; 8] && ctx.epoch == 1 {
            Ok(Secret32::new([9; 32]))
        } else {
            Err(Error::Authentication)
        }
    }
}

pub fn warm_record(size: usize) -> impl FnMut() {
    let (private_key, public_key) = generate_server_key().unwrap();
    let context = Context {
        mode: Mode::Returning,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"bench".to_vec(),
        handle: [1; 8],
        epoch: 1,
    };
    let server_cfg = ServerConfig {
        mode: context.mode,
        carrier: context.carrier,
        server_key_id: context.server_key_id,
        scope: context.scope.clone(),
        private_key,
        store: Some(Arc::new(FixedStore)),
    };
    let (hs, m1) = ClientHandshake::start(ClientConfig {
        context,
        server_public_key: public_key,
        authorization_key: Some(Secret32::new([9; 32])),
    })
    .unwrap();
    let (mut server, m2) = respond(&server_cfg, &m1).unwrap();
    let mut client = hs.finish(&m2).unwrap();
    let confirmation = client.encrypt(b"confirm").unwrap();
    assert_eq!(
        server.decrypt(&confirmation).unwrap().as_slice(),
        b"confirm"
    );
    let payload = vec![0xA5; size];
    move || {
        let ct = client.encrypt(&payload).unwrap();
        let pt = server.decrypt(&ct).unwrap();
        assert_eq!(pt.as_slice(), payload.as_slice());
    }
}
