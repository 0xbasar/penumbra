/// A key one can use to verify signatures.
///
/// This key can also serve as a unique identifier for users.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerificationKey {
    #[prost(bytes = "vec", tag = "1")]
    pub inner: ::prost::alloc::vec::Vec<u8>,
}
/// A signature proving that a message was created by the owner of a verification key.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(bytes = "vec", tag = "1")]
    pub inner: ::prost::alloc::vec::Vec<u8>,
}
/// The message the coordinator sends in round 1 of the signing protocol.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CoordinatorRound1 {
    /// The plan that the coordinator would like the followers to sign.
    #[prost(message, optional, tag = "1")]
    pub plan: ::core::option::Option<
        super::super::super::core::transaction::v1alpha1::TransactionPlan,
    >,
}
/// The message the coordinator sends in round 2 of the signing protocol.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CoordinatorRound2 {
    /// The underlying signing packages being sent to the followers, for each signature.
    #[prost(message, repeated, tag = "1")]
    pub signing_packages: ::prost::alloc::vec::Vec<
        coordinator_round2::PartialSigningPackage,
    >,
}
/// Nested message and enum types in `CoordinatorRound2`.
pub mod coordinator_round2 {
    /// A commitment along with a FROST identifier.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct IdentifiedCommitments {
        /// The serialization of a FROST identifier.
        #[prost(bytes = "vec", tag = "1")]
        pub identifier: ::prost::alloc::vec::Vec<u8>,
        /// The commitments this person has produced for this round of signing.
        #[prost(message, optional, tag = "2")]
        pub commitments: ::core::option::Option<
            super::super::super::super::crypto::decaf377_frost::v1alpha1::SigningCommitments,
        >,
    }
    /// A FROST signing package without a message.
    ///
    /// We structure things this way because the message is derived from the transaction plan.
    /// FROST expects the signing package to include the identified commitments *and*
    /// the message, but we have no need to include the message.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PartialSigningPackage {
        #[prost(message, repeated, tag = "1")]
        pub all_commitments: ::prost::alloc::vec::Vec<IdentifiedCommitments>,
    }
}
/// The first message the followers send back to the coordinator when signing.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FollowerRound1 {
    #[prost(message, optional, tag = "1")]
    pub inner: ::core::option::Option<follower_round1::Inner>,
    /// The verification key identifying the sender.
    #[prost(message, optional, tag = "2")]
    pub pk: ::core::option::Option<VerificationKey>,
    /// A signature over the proto-encoded bytes of inner.
    #[prost(message, optional, tag = "3")]
    pub sig: ::core::option::Option<Signature>,
}
/// Nested message and enum types in `FollowerRound1`.
pub mod follower_round1 {
    /// The inner message that will be signed by the follower.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Inner {
        /// One signing commitment pair for each signature requested by the plan, in order.
        #[prost(message, repeated, tag = "1")]
        pub commitments: ::prost::alloc::vec::Vec<
            super::super::super::super::crypto::decaf377_frost::v1alpha1::SigningCommitments,
        >,
    }
}
/// The second message the followers send back to the coordinator when signing.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FollowerRound2 {
    /// One share for each signature requested by the plan, in order.
    ///
    /// These can be unsigned, since any shenanigans will be detected when the signature
    /// fails to verify.
    #[prost(message, repeated, tag = "1")]
    pub shares: ::prost::alloc::vec::Vec<
        super::super::super::crypto::decaf377_frost::v1alpha1::SignatureShare,
    >,
}
