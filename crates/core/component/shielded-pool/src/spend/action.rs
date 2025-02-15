use std::convert::{TryFrom, TryInto};

use anyhow::{Context, Error};
use decaf377_rdsa::{Signature, SpendAuth, VerificationKey};
use penumbra_asset::balance;
use penumbra_proto::{core::component::shielded_pool::v1alpha1 as pb, DomainType, TypeUrl};
use penumbra_sct::Nullifier;
use serde::{Deserialize, Serialize};

use crate::SpendProof;

#[derive(Clone, Debug)]
pub struct Spend {
    pub body: Body,
    pub auth_sig: Signature<SpendAuth>,
    pub proof: SpendProof,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "pb::SpendBody", into = "pb::SpendBody")]
pub struct Body {
    pub balance_commitment: balance::Commitment,
    pub nullifier: Nullifier,
    pub rk: VerificationKey<SpendAuth>,
}

impl TypeUrl for Spend {
    const TYPE_URL: &'static str = "/penumbra.core.transaction.v1alpha1.Spend";
}

impl DomainType for Spend {
    type Proto = pb::Spend;
}

impl From<Spend> for pb::Spend {
    fn from(msg: Spend) -> Self {
        pb::Spend {
            body: Some(msg.body.into()),
            auth_sig: Some(msg.auth_sig.into()),
            proof: Some(msg.proof.into()),
        }
    }
}

impl TryFrom<pb::Spend> for Spend {
    type Error = Error;

    fn try_from(proto: pb::Spend) -> anyhow::Result<Self, Self::Error> {
        let body = proto
            .body
            .ok_or_else(|| anyhow::anyhow!("missing spend body"))?
            .try_into()
            .context("malformed spend body")?;
        let auth_sig = proto
            .auth_sig
            .ok_or_else(|| anyhow::anyhow!("missing auth sig"))?
            .try_into()
            .context("malformed auth sig")?;
        let proof = proto
            .proof
            .ok_or_else(|| anyhow::anyhow!("missing proof"))?
            .try_into()
            .context("malformed spend proof")?;

        Ok(Spend {
            body,
            auth_sig,
            proof,
        })
    }
}

impl TypeUrl for Body {
    const TYPE_URL: &'static str = "/penumbra.core.transaction.v1alpha1.SpendBody";
}

impl DomainType for Body {
    type Proto = pb::SpendBody;
}

impl From<Body> for pb::SpendBody {
    fn from(msg: Body) -> Self {
        let nullifier_bytes: [u8; 32] = msg.nullifier.into();
        let rk_bytes: [u8; 32] = msg.rk.into();
        pb::SpendBody {
            balance_commitment: Some(msg.balance_commitment.into()),
            nullifier: nullifier_bytes.to_vec(),
            rk: rk_bytes.to_vec(),
        }
    }
}

impl TryFrom<pb::SpendBody> for Body {
    type Error = Error;

    fn try_from(proto: pb::SpendBody) -> anyhow::Result<Self, Self::Error> {
        let balance_commitment: balance::Commitment = proto
            .balance_commitment
            .ok_or_else(|| anyhow::anyhow!("missing value commitment"))?
            .try_into()
            .context("malformed balance commitment")?;

        let nullifier = (proto.nullifier[..])
            .try_into()
            .context("malformed nullifier")?;

        let rk_bytes: [u8; 32] = (proto.rk[..])
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte rk"))?;
        let rk = rk_bytes.try_into().context("malformed rk")?;

        Ok(Body {
            balance_commitment,
            nullifier,
            rk,
        })
    }
}
