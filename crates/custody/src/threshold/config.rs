use std::collections::HashSet;

use decaf377_frost as frost;
use ed25519_consensus::{SigningKey, VerificationKey};
use penumbra_keys::FullViewingKey;

#[derive(Debug, Clone)]
pub struct Config {
    pub signing_share: frost::keys::SigningShare,
    pub signing_key: SigningKey,
    pub fvk: FullViewingKey,
    pub verification_keys: HashSet<VerificationKey>,
}

impl Config {
    pub fn deal(t: usize, n: usize) -> Vec<Config> {
        todo!()
    }

    pub fn key_package(&self) -> frost::keys::KeyPackage {
        todo!()
    }
}
