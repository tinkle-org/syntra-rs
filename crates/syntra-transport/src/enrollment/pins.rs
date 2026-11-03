//! Independently distributed pins; no peer-taught trust or TOFU entry point.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub key_id: u32,
    pub public_key: [u8; 32],
    pub activates_at: u64,
    pub retires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinUpdate {
    pub generation: u64,
    /// Must include all previously adopted pins with unchanged identity and
    /// activation, and non-increasing retirement. Tombstones are never removed.
    /// The finite history cap fails closed; migration is deployment-owned.
    pub pins: Vec<Pin>,
}

pub trait PinUpdateAuthority: Send + Sync {
    /// Verify independent configuration distribution, not the connecting peer.
    fn verify(&self, store_id: &str, update: &PinUpdate, evidence: &[u8]) -> Result<(), Error>;
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct PinState {
    generation: u64,
    pins: Vec<Pin>,
}

impl SqliteEnrollmentStore {
    pub fn update_pins(
        &self,
        update: PinUpdate,
        evidence: &[u8],
        authority: &dyn PinUpdateAuthority,
    ) -> Result<(), Error> {
        if evidence.len() > MAX_EVIDENCE || update.pins.len() > self.policy.max_pins as usize {
            return Err(Error::Denied);
        }
        authority
            .verify(&self.store_id, &update, evidence)
            .map_err(|_| Error::Denied)?;
        self.change(|state, now| {
            if update.generation <= state.pins.generation || update.pins.is_empty() {
                return Err(Error::Denied);
            }
            // Bootstrap or recover after expiry; active adopted pins still forbid backdating.
            let has_active_adopted_pin = state
                .pins
                .pins
                .iter()
                .any(|pin| pin.activates_at <= now && now < pin.retires_at);
            for (index, pin) in update.pins.iter().enumerate() {
                if pin.key_id == 0
                    || pin.public_key == [0; 32]
                    || pin.activates_at >= pin.retires_at
                    || pin.retires_at - pin.activates_at
                        > u64::from(state.policy.max_validity_seconds)
                    || update.pins[..index]
                        .iter()
                        .any(|p| p.key_id == pin.key_id || p.public_key == pin.public_key)
                {
                    return Err(Error::Denied);
                }
                if has_active_adopted_pin
                    && !state.pins.pins.iter().any(|p| p.key_id == pin.key_id)
                    && pin.activates_at < now
                {
                    return Err(Error::Denied);
                }
            }
            for old in &state.pins.pins {
                if !update.pins.iter().any(|pin| {
                    pin.key_id == old.key_id
                        && pin.public_key == old.public_key
                        && pin.activates_at == old.activates_at
                        && pin.retires_at <= old.retires_at
                }) {
                    return Err(Error::Denied);
                }
            }
            if !update
                .pins
                .iter()
                .any(|pin| pin.activates_at <= now && now < pin.retires_at)
            {
                return Err(Error::Denied);
            }
            state.pins = PinState {
                generation: update.generation,
                pins: update.pins,
            };
            state.audit(5);
            Ok(())
        })
    }

    /// Select a locally authenticated pin before constructing ClientConfig.
    /// The peer may name a key ID but cannot supply or change its public key.
    pub fn server_pin(&self, key_id: u32) -> Result<[u8; 32], Error> {
        self.inspect(|state, now| {
            state
                .pins
                .pins
                .iter()
                .find(|pin| pin.key_id == key_id && pin.activates_at <= now && now < pin.retires_at)
                .map(|pin| pin.public_key)
                .ok_or(Error::Denied)
        })
    }
}
