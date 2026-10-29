//! Delegates all cryptography to Snow's standard resolver. On destruction,
//! overwrite its retained DH/cipher keys through the provider interface.
//! Snow's internal handshake/KDF scratch copies have no erasure API.
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};

#[derive(Default)]
pub(crate) struct Resolver {
    #[cfg(test)]
    pub(crate) fail_rng: bool,
}

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        #[cfg(test)]
        if self.fail_rng {
            return Some(Box::new(FailedRandom));
        }
        DefaultResolver.resolve_rng()
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver
            .resolve_dh(choice)
            .map(|dh| Box::new(WipeDh(dh)) as Box<dyn Dh>)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver
            .resolve_cipher(choice)
            .map(|cipher| Box::new(WipeCipher(cipher)) as Box<dyn Cipher>)
    }
}

struct WipeDh(Box<dyn Dh>);
impl Drop for WipeDh {
    fn drop(&mut self) {
        self.0.set(&[0; 32]);
        // Keep the overwrite observable even with whole-program optimization.
        std::hint::black_box(&mut *self.0);
    }
}
impl Dh for WipeDh {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn pub_len(&self) -> usize {
        self.0.pub_len()
    }
    fn priv_len(&self) -> usize {
        self.0.priv_len()
    }
    fn set(&mut self, bytes: &[u8]) {
        self.0.set(bytes);
    }
    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        self.0.generate(rng)
    }
    fn pubkey(&self) -> &[u8] {
        self.0.pubkey()
    }
    fn privkey(&self) -> &[u8] {
        self.0.privkey()
    }
    fn dh(&self, public: &[u8], output: &mut [u8]) -> Result<(), snow::Error> {
        self.0.dh(public, output)?;
        // X25519's non-contributory result is never an acceptable shared secret.
        let nonzero = output[..32].iter().fold(0u8, |acc, byte| acc | byte);
        if nonzero == 0 {
            return Err(snow::Error::Dh);
        }
        Ok(())
    }
}

struct WipeCipher(Box<dyn Cipher>);
impl Drop for WipeCipher {
    fn drop(&mut self) {
        self.0.set(&[0; 32]);
        std::hint::black_box(&mut *self.0);
    }
}
impl Cipher for WipeCipher {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn set(&mut self, bytes: &[u8; 32]) {
        self.0.set(bytes);
    }
    fn encrypt(&self, nonce: u64, ad: &[u8], plain: &[u8], out: &mut [u8]) -> usize {
        self.0.encrypt(nonce, ad, plain, out)
    }
    fn decrypt(
        &self,
        nonce: u64,
        ad: &[u8],
        cipher: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        self.0.decrypt(nonce, ad, cipher, out)
    }
}

#[cfg(test)]
struct FailedRandom;
#[cfg(test)]
impl Random for FailedRandom {
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), snow::Error> {
        Err(snow::Error::Rng)
    }
}
