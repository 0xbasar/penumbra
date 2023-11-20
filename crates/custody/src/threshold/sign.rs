use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use decaf377_frost as frost;
use ed25519_consensus::{Signature, SigningKey, VerificationKey};
use frost::round1::SigningCommitments;
use penumbra_proto::{penumbra::custody::threshold::v1alpha1 as pb, DomainType, Message, TypeUrl};
use penumbra_transaction::plan::TransactionPlan;
use rand_core::CryptoRngCore;

use super::config::Config;

/// Represents the message sent by the coordinator at the start of the signing process.
///
/// This is nominally "round 1", even though it's the only message the coordinator ever sends.
#[derive(Debug, Clone)]
pub struct CoordinatorRound1 {
    plan: TransactionPlan,
}

impl From<CoordinatorRound1> for pb::CoordinatorRound1 {
    fn from(value: CoordinatorRound1) -> Self {
        Self {
            plan: Some(value.plan.into()),
        }
    }
}

impl TryFrom<pb::CoordinatorRound1> for CoordinatorRound1 {
    type Error = anyhow::Error;

    fn try_from(value: pb::CoordinatorRound1) -> Result<Self, Self::Error> {
        Ok(Self {
            plan: value.plan.ok_or(anyhow!("missing plan"))?.try_into()?,
        })
    }
}

impl TypeUrl for CoordinatorRound1 {
    const TYPE_URL: &'static str = "/penumbra.custody.threshold.v1alpha1.CoordinatorRound1";
}

impl DomainType for CoordinatorRound1 {
    type Proto = pb::CoordinatorRound1;
}

#[derive(Debug, Clone)]
pub struct CoordinatorRound2 {
    // For each thing to sign, a map from FROST identifiers to a pair of commitments.
    all_commitments: Vec<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>>,
}

fn commitments_to_pb(
    commitments: impl IntoIterator<Item = frost::round1::SigningCommitments>,
) -> pb::follower_round1::Inner {
    pb::follower_round1::Inner {
        commitments: commitments.into_iter().map(|x| x.into()).collect(),
    }
}

/// The message sent by the followers in round1 of signing.
#[derive(Debug, Clone)]
pub struct FollowerRound1 {
    /// A commitment for each spend we need to authorize.
    pub(self) commitments: Vec<frost::round1::SigningCommitments>,
    /// A verification key identifying who the sender is.
    pub(self) pk: VerificationKey,
    /// The signature over the protobuf encoding of the commitments.
    pub(self) sig: Signature,
}

impl From<FollowerRound1> for pb::FollowerRound1 {
    fn from(value: FollowerRound1) -> Self {
        Self {
            inner: Some(commitments_to_pb(value.commitments)),
            pk: Some(pb::VerificationKey {
                inner: value.pk.to_bytes().to_vec(),
            }),
            sig: Some(pb::Signature {
                inner: value.sig.to_bytes().to_vec(),
            }),
        }
    }
}

impl TryFrom<pb::FollowerRound1> for FollowerRound1 {
    type Error = anyhow::Error;

    fn try_from(value: pb::FollowerRound1) -> Result<Self, Self::Error> {
        Ok(Self {
            commitments: value
                .inner
                .ok_or(anyhow!("missing inner"))?
                .commitments
                .into_iter()
                .map(|x| x.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            pk: value
                .pk
                .ok_or(anyhow!("missing pk"))?
                .inner
                .as_slice()
                .try_into()?,
            sig: value
                .sig
                .ok_or(anyhow!("missing sig"))?
                .inner
                .as_slice()
                .try_into()?,
        })
    }
}

impl FollowerRound1 {
    // Make a round1 message, automatically signing the right bytes
    fn make(signing_key: &SigningKey, commitments: Vec<SigningCommitments>) -> Self {
        Self {
            commitments: commitments.clone(),
            pk: signing_key.verification_key(),
            sig: signing_key.sign(&commitments_to_pb(commitments).encode_to_vec()),
        }
    }

    // Extract the commitments from this struct, checking the signature
    fn checked_commitments(self) -> Result<(VerificationKey, Vec<SigningCommitments>)> {
        self.pk.verify(
            &self.sig,
            &commitments_to_pb(self.commitments.clone()).encode_to_vec(),
        )?;
        Ok((self.pk, self.commitments))
    }
}

impl TypeUrl for FollowerRound1 {
    const TYPE_URL: &'static str = "/penumbra.custody.threshold.v1alpha1.FollowerRound1";
}

impl DomainType for FollowerRound1 {
    type Proto = pb::FollowerRound1;
}

#[derive(Debug, Clone)]
pub struct FollowerRound2 {
    /// One share of the signature for each authorization we need
    shares: Vec<frost::round2::SignatureShare>,
}

impl From<FollowerRound2> for pb::FollowerRound2 {
    fn from(value: FollowerRound2) -> Self {
        Self {
            shares: value.shares.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl TryFrom<pb::FollowerRound2> for FollowerRound2 {
    type Error = anyhow::Error;

    fn try_from(value: pb::FollowerRound2) -> Result<Self, Self::Error> {
        Ok(Self {
            shares: value
                .shares
                .into_iter()
                .map(|x| x.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TypeUrl for FollowerRound2 {
    const TYPE_URL: &'static str = "/penumbra.custody.threshold.v1alpha1.FollowerRound2";
}

impl DomainType for FollowerRound2 {
    type Proto = pb::FollowerRound2;
}

/// Calculate the number of required signatures for a plan.
///
/// A plan can require more than one signature, hence the need for this method.
fn required_signatures(plan: &TransactionPlan) -> usize {
    plan.spend_plans().count() + plan.delegator_vote_plans().count()
}

pub struct CoordinatorState {
    my_round1_reply: FollowerRound1,
    my_round1_state: FollowerState,
}

pub struct FollowerState {
    plan: TransactionPlan,
    nonces: Vec<frost::round1::SigningNonces>,
}

pub fn coordinator_round1(
    rng: &mut impl CryptoRngCore,
    config: &Config,
    plan: TransactionPlan,
) -> Result<(CoordinatorRound1, CoordinatorState)> {
    let required = required_signatures(&plan);
    let message = CoordinatorRound1 { plan };
    let (my_round1_reply, my_round1_state) = follower_round1(rng, config, message.clone())?;
    let state = CoordinatorState {
        my_round1_reply,
        my_round1_state,
    };
    Ok((message, state))
}

pub fn coordinator_round2(
    config: &Config,
    state: CoordinatorState,
    follower_messages: &[FollowerRound1],
) -> Result<(CoordinatorRound2, FollowerRound2)> {
    todo!()
}

pub fn follower_round1(
    rng: &mut impl CryptoRngCore,
    config: &Config,
    coordinator: CoordinatorRound1,
) -> Result<(FollowerRound1, FollowerState)> {
    let required = required_signatures(&coordinator.plan);
    let (nonces, commitments) = (0..required)
        .map(|_| frost::round1::commit(&config.signing_share, rng))
        .unzip();
    let reply = FollowerRound1::make(&config.signing_key, commitments);
    let state = FollowerState {
        plan: coordinator.plan,
        nonces,
    };
    Ok((reply, state))
}

pub fn follower_round2(
    config: &Config,
    state: FollowerState,
    coordinator: CoordinatorRound2,
) -> Result<FollowerRound2> {
    let effect_hash = state.plan.effect_hash(&config.fvk);
    let signing_packages = coordinator
        .all_commitments
        .into_iter()
        .map(|tree| frost::SigningPackage::new(tree, effect_hash.as_ref()));
    let shares = state
        .plan
        .spend_plans()
        .map(|x| x.randomizer)
        .chain(state.plan.delegator_vote_plans().map(|x| x.randomizer))
        .zip(signing_packages)
        .zip(state.nonces.into_iter())
        .map(|((randomizer, signing_package), signer_nonces)| {
            frost::round2::sign_randomized(
                &signing_package,
                &signer_nonces,
                &config.key_package(),
                randomizer,
            )
        })
        .collect::<Result<_, _>>()?;
    Ok(FollowerRound2 { shares })
}

pub fn aggregate
