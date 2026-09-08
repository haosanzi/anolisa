//! Closed Action inventory.

use std::fmt;

/// Every Action this build can execute.
///
/// The set is closed on purpose: an Action name is only accepted once a
/// capability behind it exists, so no request can reach an unimplemented
/// branch. Adding a variant is therefore a deliberate protocol change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionId {
    /// Prompt injection, jailbreak, and multi-turn intent inspection.
    PromptScan,
}

impl ActionId {
    /// Returns the stable audit and log value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PromptScan => "prompt_scan",
        }
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
