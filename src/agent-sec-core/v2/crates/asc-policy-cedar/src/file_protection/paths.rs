//! Literal path ranges and target-owned exclusions; no filesystem inspection.

use asc_file_policy::{
    FileProtectionExclusion, FileProtectionExclusionKind, FileProtectionTarget,
    FileProtectionTargetKind,
};

use super::{Result, expressions::FileRule, protections};

#[derive(Clone, Debug, PartialEq, Eq)]
/// A literal file or directory-tree constraint on a Cedar path.
pub enum PathScope {
    /// A single path.
    Exact(String),
    /// A directory and its descendants.
    Tree(String),
}

impl PathScope {
    pub(super) fn path(&self) -> &str {
        match self {
            Self::Exact(path) | Self::Tree(path) => path,
        }
    }

    /// Whether every path in the other scope belongs to this scope.
    pub fn contains(&self, other: &Self) -> bool {
        self == other
            || matches!(self, Self::Tree(_))
                && (self.path() == other.path() || descendant(self.path(), other.path()))
    }
}

pub(super) fn descendant(parent: &str, path: &str) -> bool {
    if parent == "/" {
        return path != "/";
    }
    path.strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

pub(super) fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.contains("//")
        || path != "/" && path.ends_with('/')
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err("UNSUPPORTED_PATH");
    }
    Ok(())
}

impl FileRule {
    /// Materializes a target using the backend's chosen scope and the rule's exclusions.
    /// The selected scope must respect the rule's positive literal constraint.
    ///
    /// # Errors
    /// Returns an error for exclusions the structured target cannot represent.
    pub fn target(&self, range: &PathScope) -> Result<Option<FileProtectionTarget>> {
        let mut exclusions: Vec<FileProtectionExclusion> = Vec::new();
        for excluded in &self.excluded {
            if excluded.contains(range) {
                return Ok(None);
            }
            if !range.contains(excluded) {
                continue;
            }
            // Excluding only a directory root cannot be expressed as a strict
            // descendant exclusion without also dropping the protected root.
            if excluded.path() == range.path() {
                return Err("UNSUPPORTED_ROOT_EXCLUSION");
            }
            let kind = match excluded {
                PathScope::Exact(_) => FileProtectionExclusionKind::ExactEntry,
                PathScope::Tree(_) => FileProtectionExclusionKind::DirectorySubtree,
            };
            if exclusions
                .iter()
                .any(|item| item.path == excluded.path() && item.kind != kind)
            {
                return Err("CONFLICTING_EXCLUSIONS");
            }
            exclusions.push(FileProtectionExclusion {
                path: excluded.path().into(),
                kind,
            });
        }
        let kind = match range {
            PathScope::Exact(_) => FileProtectionTargetKind::ExactFile,
            PathScope::Tree(_) => FileProtectionTargetKind::DirectoryTree,
        };
        Ok(Some(FileProtectionTarget {
            path: range.path().into(),
            kind,
            protections: protections(self.operations),
            exclusions,
        }))
    }
}
