//! Mosaic core is a core library supporting the
//! [Mosaic protocol](https://stevefarroll.github.io/mosaic-spec/)
//!
//! # Identity
//!
//! Users and Servers are known by their [`PublicKey`] proven by their
//! [`SecretKey`]. These are 32-byte packed data, and have to be unpacked
//! into their [`ed25519_dalek::VerifyingKey`] or [`ed25519_dalek::SigningKey`]
//! respectively in order to do cryptographic operations.
//!
//! # Bootstrap
//!
//! Server endpoints (URLs) are bootstrapped from Mainline DHT with
//! a [`ServerBootstrap`] record.
//!
//! The servers that a user uses are bootstrapped from Mainline DHT
//! with a [`UserBootstrap`] record.
//!
//! # Records
//!
//! [`Record`]s are of various [`Kind`]s and have [`Timestamp`]s and
//! [`RecordFlags`].
//!
//! [`Record`]s may have [`Tag`]s of varying [`TagType`]s.
//!
//! Every [`Record`] has an [`Id`] and an [`Address`] by which it can be
//! referred. In some contexts a [`Record`] may be referred to by either,
//! and so a [`Reference`] type can be used when it is unknown which kind
//! of reference is specified.
//!
//! # Protocol
//!
//! Protocol [`Message`]s are sent between client and server over some
//! transport. Many client-initiated messages include a [`Filter`]

#![warn(clippy::pedantic)]
#![deny(
    missing_debug_implementations,
    trivial_numeric_casts,
    clippy::string_slice,
    unused_import_braces,
    unused_results,
    unused_lifetimes,
    unused_labels,
    unused_extern_crates,
    non_ascii_idents,
    keyword_idents,
    deprecated_in_future,
    unstable_features,
    single_use_lifetimes,
    unreachable_pub,
    missing_copy_implementations,
    missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

macro_rules! padded_len {
    ($len:expr) => {
        ((($len) + 7) & !7)
    };
}

pub use ed25519_dalek;
pub use mainline;
pub use rand;
pub use secp256k1;

mod address;
pub use address::Address;

mod error;
pub use error::{Error, InnerError};

mod filter;
pub use filter::{
    FeIdPrefixesIter, FeKeysIter, FeKindsIter, FeTagsIter, FeTimestampsIter, Filter, FilterElement,
    FilterElementType, OwnedFilter, OwnedFilterElement,
};

mod hash;

mod id;
pub use id::Id;

mod kind;
pub use kind::Kind;

mod kind_flags;
pub use kind_flags::{DuplicateHandling, KindFlags, ReadAccess};

mod message;
pub use message::{Message, MessageType, QueryClosedCode, QueryId, SubmissionResultCode};

mod record;
pub use record::{
    OwnedRecord, Record, RecordAddressData, RecordFlags, RecordParts, RecordSigningData,
    SignatureScheme,
};

mod reference;
pub use reference::Reference;

mod server_bootstrap;
pub use server_bootstrap::ServerBootstrap;

mod signature;
pub use signature::{EncryptedSecretKey, PublicKey, SecretKey, Signature};

mod tag;
pub use tag::{OwnedTag, Tag, TagType};

mod tag_set;
pub use tag_set::{OwnedTagSet, TagSet, TagSetIter, EMPTY_TAG_SET};

mod timestamp;
pub use timestamp::{Timestamp, MAX_NANOSECONDS};

mod uri;

mod user_bootstrap;
pub use user_bootstrap::UserBootstrap;
