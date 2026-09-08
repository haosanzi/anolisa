//! Transport-independent daemon identity, authorization, and PAP orchestration.

#![forbid(unsafe_code)]

mod action;
mod identity;
mod pap;

pub use action::PromptScanning;
pub use identity::{
    PeerCredentials, Principal, PrincipalPolicy, PrincipalPolicyError, PrincipalRole,
    RootManagedPrincipalPolicy,
};
pub use pap::{
    NotFoundResource, PolicyAdministration, PolicyAdministrationError, PolicyInputError,
    ResourcePage,
};
