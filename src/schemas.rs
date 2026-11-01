//! The stable JSON outputs: what each is called, where its JSON Schema is
//! published, and the `metadata` block that says so in the output itself.
//!
//! The five outputs grew four ways of naming themselves: `schema`,
//! `schema_version`, `format` with `version`, and `_meta.schema`. Scripts read
//! those, so they stay. `metadata` is the one that reads the same everywhere,
//! at the top level of the document, or of the first line of the egress NDJSON.
//!
//! tests/schemas.rs checks each file under `schemas/` against what the code
//! writes. docs/REFERENCE.md has the rules a schema file follows.

use serde::{Deserialize, Serialize};

/// Where the files under `schemas/` are published, and the base of each file's
/// `$id`. A published file is never renamed or removed, so an output that names
/// one keeps working after a release moves on. Only additive edits reach an
/// existing file, and a break gets a new file.
const SCHEMA_BASE: &str = "https://raw.githubusercontent.com/matthart1983/netwatch/main/schemas/";

/// One stable output and the schema file that describes it.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    /// The name `metadata.schema` carries, its version included.
    pub schema: &'static str,
    /// The version alone, as a string because the egress export's has a minor.
    pub version: &'static str,
    /// The file's name under `schemas/`.
    pub file: &'static str,
}

/// `netwatch diagnose run --format json`.
pub const DIAGNOSE_RUN: Output = Output {
    schema: "netwatch.diagnose-run.v2",
    version: "2",
    file: "diagnose-run.v2.schema.json",
};
/// `netwatch doctor --json`, and any other printing of a capability snapshot.
pub const DOCTOR: Output = Output {
    schema: "netwatch.doctor.v1",
    version: "1",
    file: "doctor.v1.schema.json",
};
/// The Egress tab's NDJSON export. Each line validates on its own.
pub const EGRESS: Output = Output {
    schema: crate::collectors::egress::EGRESS_EXPORT_SCHEMA,
    version: "1.1",
    file: "egress.v1.1.schema.json",
};
/// The document inside the gzip file `netwatch diagnose export` writes.
pub const DIAGNOSE_EXPORT: Output = Output {
    schema: "netwatch.diagnose-export.v1",
    version: "1",
    file: "diagnose-export.v1.schema.json",
};
/// `netwatch uptime --json`.
pub const UPTIME: Output = Output {
    schema: "netwatch.uptime.v1",
    version: "1",
    file: "uptime.v1.schema.json",
};

pub const ALL: [Output; 5] = [DIAGNOSE_RUN, DOCTOR, EGRESS, DIAGNOSE_EXPORT, UPTIME];

/// The block each stable output carries. Empty only when read back from a
/// document older than the block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub schema: String,
    pub schema_version: String,
    pub schema_url: String,
    /// The netwatch that wrote the document.
    pub netwatch_version: String,
}

impl Output {
    pub fn url(&self) -> String {
        format!("{SCHEMA_BASE}{}", self.file)
    }

    pub fn metadata(&self) -> Metadata {
        Metadata {
            schema: self.schema.to_string(),
            schema_version: self.version.to_string(),
            schema_url: self.url(),
            netwatch_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Shared with tests/schemas.rs, for the outputs only a unit test can reach.
#[cfg(test)]
#[path = "../tests/support/schema.rs"]
pub(crate) mod test_support;
