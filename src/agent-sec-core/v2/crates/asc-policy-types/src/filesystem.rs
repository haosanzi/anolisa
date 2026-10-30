//! Backend-independent filesystem permissions; capabilities require exact support, not approximation.

use serde::{Deserialize, Serialize};

/// Independent `filesystem-access@1` permissions; none implies another or grants authorization.
///
/// Enforcement must verify paths and direct parent-child relationships in the caller's namespace.
/// Directory access neither recurses nor follows symlinks; listings include hidden entries
/// but exclude `.` and `..`. Backends unable to enforce these boundaries must reject support,
/// never substitute a broad read-only mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FilesystemPermission {
    /// Read one bound file's contents without implying directory listing.
    #[serde(rename = "filesystem.read")]
    Read,
    /// List direct entry names without reading contents or recursing into subdirectories.
    #[serde(rename = "filesystem.list")]
    List,
    /// Inspect metadata of a bound object or direct entry; symlinks refer to the link itself.
    #[serde(rename = "filesystem.metadata")]
    Metadata,
}

impl FilesystemPermission {
    /// Action name matching the Cedar schema.
    pub const fn action(self) -> &'static str {
        match self {
            Self::Read => "filesystem.read",
            Self::List => "filesystem.list",
            Self::Metadata => "filesystem.metadata",
        }
    }
}
