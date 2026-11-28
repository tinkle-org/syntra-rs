//! Test-only fixture for ordinary encrypted connections to a single loopback listener.

use std::sync::Arc;
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, Secret32, ServerConfig,
};
use syntra_net::{tcp, AuthenticatorFactory, ClientHandle, Error, HostHandle};
use syntra_runtime::Handler;

pub const CREDENTIAL: &[u8] = b"loopback-test-caller";
const SCOPE: &[u8] = b"mixed-traffic-fixture";
const MAX_LIVE_PAIRS: usize = 2;

struct Enrollment(Secret32);

impl KeyStore for Enrollment {
    fn lookup(&self, ctx: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
        if ctx.scope != SCOPE || ctx.handle != [1; 8] || ctx.epoch != 1 {
            return Err(syntra_core::secure_channel::Error::Authentication);
        }
        Ok(Secret32::new(*self.0.expose()))
    }
}

pub struct Loopback {
    listener: tcp::Listener,
    server: ServerConfig,
    server_public_key: [u8; 32],
    enrollment: Arc<Enrollment>,
}

impl Loopback {
    /// Bind one listener for at most two live client/host pairs.
    pub async fn bind() -> Result<Self, Error> {
        let (private_key, server_public_key) = generate_server_key()?;
        // Fixed test enrollment; each connection still establishes fresh traffic keys.
        let enrollment = Arc::new(Enrollment(Secret32::new([7; 32])));
        Ok(Self {
            listener: tcp::Listener::bind((std::net::Ipv4Addr::LOCALHOST, 0), MAX_LIVE_PAIRS)
                .await?,
            server: ServerConfig {
                mode: Mode::Returning,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: SCOPE.to_vec(),
                private_key,
                store: Some(enrollment.clone()),
            },
            server_public_key,
            enrollment,
        })
    }

    /// Open pairs serially so the accepted stream gets the intended handler.
    /// Close a live pair before opening a third; each holds a listener permit.
    pub async fn open(
        &mut self,
        factory: Arc<dyn AuthenticatorFactory>,
        handler: Arc<dyn Handler>,
    ) -> Result<(ClientHandle, HostHandle), Error> {
        let client = client_config(&self.enrollment, self.server_public_key)?;
        tokio::try_join!(
            tcp::connect(
                self.listener.local_addr()?,
                client,
                CREDENTIAL.to_vec(),
                Default::default(),
                Default::default()
            ),
            self.accept(factory, handler)
        )
    }

    /// Accept the next stream with this handler. When handlers differ, start one
    /// dial and await its accept before starting the next pair: the listener
    /// matches arrival order, not connection purpose.
    pub async fn accept(
        &self,
        factory: Arc<dyn AuthenticatorFactory>,
        handler: Arc<dyn Handler>,
    ) -> Result<HostHandle, Error> {
        self.listener
            .accept(
                &self.server,
                factory,
                handler,
                Default::default(),
                Default::default(),
            )
            .await
    }

    #[cfg(feature = "managed-media")]
    pub fn address(&self) -> Result<std::net::SocketAddr, Error> {
        self.listener.local_addr()
    }

    #[cfg(feature = "managed-media")]
    pub fn lane_inputs(
        &self,
    ) -> impl Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static + use<> {
        let (enrollment, pin) = (self.enrollment.clone(), self.server_public_key);
        move || Ok((client_config(&enrollment, pin)?, CREDENTIAL.to_vec()))
    }
}

fn client_config(
    enrollment: &Enrollment,
    server_public_key: [u8; 32],
) -> Result<ClientConfig, Error> {
    let context = Context {
        mode: Mode::Returning,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: SCOPE.to_vec(),
        handle: [1; 8],
        epoch: 1,
    };
    Ok(ClientConfig {
        authorization_key: Some(enrollment.lookup(&context)?),
        context,
        server_public_key,
    })
}
