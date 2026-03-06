//! Error types for the qcow2-rescue tool.

use std::fmt;
use std::path::PathBuf;

/// All errors that can occur during rescue operations.
#[derive(Debug)]
pub enum RescueError {
    /// An I/O error occurred.
    Io(std::io::Error),

    /// A QCOW2 format/engine error occurred.
    Qcow2(qcow2::Error),

    /// JSON serialization/deserialization failed.
    Json(serde_json::Error),

    /// The input file was not found or not accessible.
    InputNotFound { path: PathBuf },

    /// The output directory could not be created.
    OutputDirFailed { path: PathBuf, reason: String },

    /// No valid QCOW2 header found in the image.
    NoHeaderFound,

    /// Could not determine cluster size (header corrupt, heuristic failed).
    ClusterSizeUnknown,

    /// The password was wrong or no key slot could be unlocked.
    WrongPassword,

    /// A resume state file is corrupt or incompatible.
    InvalidResumeState { path: PathBuf, reason: String },
}

impl fmt::Display for RescueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Qcow2(e) => write!(f, "qcow2 error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::InputNotFound { path } => write!(f, "input not found: {}", path.display()),
            Self::OutputDirFailed { path, reason } => {
                write!(f, "cannot create output dir {}: {reason}", path.display())
            }
            Self::NoHeaderFound => write!(f, "no valid QCOW2 header found in image"),
            Self::ClusterSizeUnknown => {
                write!(f, "could not determine cluster size (header corrupt)")
            }
            Self::WrongPassword => write!(f, "wrong password or no key slot could be unlocked"),
            Self::InvalidResumeState { path, reason } => {
                write!(f, "invalid resume state {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for RescueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RescueError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<qcow2::Error> for RescueError {
    fn from(e: qcow2::Error) -> Self {
        Self::Qcow2(e)
    }
}

impl From<serde_json::Error> for RescueError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, RescueError>;
