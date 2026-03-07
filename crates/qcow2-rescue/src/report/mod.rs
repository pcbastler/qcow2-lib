//! Serde-serializable report structures for all rescue phases.
//!
//! Every phase writes a JSON file with complete transparency about what
//! was found, what was damaged, and what decisions were made.

mod cluster;
mod mapping;
mod reconstruction;
mod recovery;
mod tree;

pub use cluster::*;
pub use mapping::*;
pub use reconstruction::*;
pub use recovery::*;
pub use tree::*;
