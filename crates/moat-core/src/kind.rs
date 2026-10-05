//! The kinds of atomic action a rule can name.
//!
//! The same names appear in policy files (`fs.read:`), in `defaults`
//! (`net: deny`), in synthetic rule ids (`default.net`) and in user output, so
//! they are defined once here.

use std::fmt;
use std::str::FromStr;

/// One kind of atomic action. Ordered as policy files list them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A command or a whole pipeline.
    Shell,
    /// A file read.
    FsRead,
    /// A file write, create, delete or move.
    FsWrite,
    /// A network host.
    Net,
    /// An environment variable read.
    EnvRead,
    /// An environment variable set.
    EnvSet,
    /// An MCP tool name.
    Mcp,
}

impl Kind {
    /// Every kind, in policy-file order.
    pub const ALL: [Self; 7] = [
        Self::Shell,
        Self::FsRead,
        Self::FsWrite,
        Self::Net,
        Self::EnvRead,
        Self::EnvSet,
        Self::Mcp,
    ];

    /// The name used in policy files and rule ids (`fs.read`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::Net => "net",
            Self::EnvRead => "env.read",
            Self::EnvSet => "env.set",
            Self::Mcp => "mcp",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name that is not one of [`Kind::ALL`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown action kind `{0}`")]
pub struct UnknownKind(pub String);

impl FromStr for Kind {
    type Err = UnknownKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| UnknownKind(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for kind in Kind::ALL {
            assert_eq!(kind.as_str().parse::<Kind>(), Ok(kind));
        }
        assert_eq!(
            "network".parse::<Kind>(),
            Err(UnknownKind("network".into()))
        );
    }
}
