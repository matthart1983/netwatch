//! The deterministic tier of drift adjudication — a shipped table of
//! well-known destinations.
//!
//! Most drift is boring: a package registry the build reached for the first
//! time, a CDN edge that moved, an OCSP responder. Resolving those in code
//! keeps them off the model's plate, keeps latency at zero for the common
//! case, and — more importantly — makes the answer *traceable*. A label from
//! this table can be explained by pointing at a line in this file. A label
//! from a model cannot.
//!
//! Deliberately not fetched, ever. A tool that phones home to decide whether
//! your traffic is suspicious has misunderstood its own threat model. The
//! table ships with the binary and `netwatch --egress-catalog` prints it.

use super::adjudicate::Label;

/// What kind of thing a destination is. The category carries the default
/// label, so adding an entry is a one-line decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    /// npm, crates.io, PyPI, Maven, Go module proxy.
    PackageRegistry,
    /// Shared content-delivery infrastructure.
    Cdn,
    /// Certificate transparency, OCSP, CRL.
    CertRevocation,
    /// Time synchronisation.
    Ntp,
    /// Source forges and developer platforms.
    DeveloperPlatform,
    /// Operating-system vendor endpoints — updates, activation, notarisation.
    OsVendor,
    /// Crash reporting, product analytics, error tracking.
    Telemetry,
    /// Model-inference APIs.
    AiProvider,
}

impl Category {
    /// The label an entry in this category carries.
    ///
    /// The split is `benign` for infrastructure that is unremarkable for
    /// *any* process, and `expected` for endpoints that are only reasonable
    /// when the right program reached them. The model tier and a human can
    /// both raise an `expected`; neither may lower a `benign`.
    fn label(self) -> Label {
        match self {
            Category::PackageRegistry
            | Category::Cdn
            | Category::CertRevocation
            | Category::Ntp
            | Category::DeveloperPlatform => Label::Benign,
            // Vendor telemetry and inference APIs are fine for the software
            // that owns them and a finding for anything else, so they never
            // get the unconditional label.
            Category::OsVendor | Category::Telemetry | Category::AiProvider => Label::Expected,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Category::PackageRegistry => "package-registry",
            Category::Cdn => "cdn",
            Category::CertRevocation => "cert-revocation",
            Category::Ntp => "ntp",
            Category::DeveloperPlatform => "developer-platform",
            Category::OsVendor => "os-vendor",
            Category::Telemetry => "telemetry",
            Category::AiProvider => "ai-provider",
        }
    }
}

/// How an entry matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// The hostname, exactly.
    Sni(&'static str),
    /// The hostname or any label-boundary subdomain of it. `github.com`
    /// matches `api.github.com` but never `notgithub.com`.
    SniSuffix(&'static str),
    /// The autonomous-system org, case-insensitively. Broad by construction —
    /// only used where the AS is single-purpose.
    AsnOrg(&'static str),
}

pub struct Entry {
    pub matcher: Match,
    pub category: Category,
}

/// A resolved catalog lookup.
pub struct CatalogHit {
    pub label: Label,
    pub category: Category,
    /// The pattern that matched, for the `source` field.
    pub matched: &'static str,
    pub reason: &'static str,
}

macro_rules! entries {
    ($($m:expr => $c:expr),* $(,)?) => {
        &[$(Entry { matcher: $m, category: $c }),*]
    };
}

/// The table.
///
/// Ordering does not matter for correctness — [`classify`] tries exact
/// matches before suffixes before ASNs regardless — but keep it grouped by
/// category so a reviewer can see the shape of what is claimed.
pub static CATALOG: &[Entry] = entries![
    // ---- package registries ----
    Match::SniSuffix("registry.npmjs.org") => Category::PackageRegistry,
    Match::SniSuffix("crates.io") => Category::PackageRegistry,
    Match::SniSuffix("static.crates.io") => Category::PackageRegistry,
    Match::SniSuffix("pypi.org") => Category::PackageRegistry,
    Match::SniSuffix("files.pythonhosted.org") => Category::PackageRegistry,
    Match::SniSuffix("repo.maven.apache.org") => Category::PackageRegistry,
    Match::SniSuffix("proxy.golang.org") => Category::PackageRegistry,
    Match::SniSuffix("sum.golang.org") => Category::PackageRegistry,
    Match::SniSuffix("rubygems.org") => Category::PackageRegistry,
    Match::SniSuffix("packagist.org") => Category::PackageRegistry,
    Match::SniSuffix("archive.ubuntu.com") => Category::PackageRegistry,
    Match::SniSuffix("security.ubuntu.com") => Category::PackageRegistry,
    Match::SniSuffix("deb.debian.org") => Category::PackageRegistry,
    Match::SniSuffix("cache.nixos.org") => Category::PackageRegistry,
    Match::SniSuffix("formulae.brew.sh") => Category::PackageRegistry,
    Match::SniSuffix("ghcr.io") => Category::PackageRegistry,
    Match::SniSuffix("registry-1.docker.io") => Category::PackageRegistry,
    Match::SniSuffix("auth.docker.io") => Category::PackageRegistry,

    // ---- developer platforms ----
    Match::SniSuffix("github.com") => Category::DeveloperPlatform,
    Match::SniSuffix("githubusercontent.com") => Category::DeveloperPlatform,
    Match::SniSuffix("githubassets.com") => Category::DeveloperPlatform,
    Match::SniSuffix("gitlab.com") => Category::DeveloperPlatform,
    Match::SniSuffix("bitbucket.org") => Category::DeveloperPlatform,
    Match::SniSuffix("sourceforge.net") => Category::DeveloperPlatform,

    // ---- CDNs ----
    Match::SniSuffix("cloudflare.com") => Category::Cdn,
    Match::SniSuffix("cdnjs.cloudflare.com") => Category::Cdn,
    Match::SniSuffix("jsdelivr.net") => Category::Cdn,
    Match::SniSuffix("unpkg.com") => Category::Cdn,
    Match::SniSuffix("akamaized.net") => Category::Cdn,
    Match::SniSuffix("akamaiedge.net") => Category::Cdn,
    Match::SniSuffix("fastly.net") => Category::Cdn,
    Match::SniSuffix("cloudfront.net") => Category::Cdn,
    Match::SniSuffix("gstatic.com") => Category::Cdn,
    Match::SniSuffix("googleapis.com") => Category::Cdn,

    // ---- certificate infrastructure ----
    Match::SniSuffix("ocsp.digicert.com") => Category::CertRevocation,
    Match::SniSuffix("ocsp.sectigo.com") => Category::CertRevocation,
    Match::SniSuffix("crl.identrust.com") => Category::CertRevocation,
    Match::SniSuffix("r3.o.lencr.org") => Category::CertRevocation,
    Match::SniSuffix("o.lencr.org") => Category::CertRevocation,
    Match::SniSuffix("letsencrypt.org") => Category::CertRevocation,

    // ---- time ----
    Match::SniSuffix("ntp.org") => Category::Ntp,
    Match::SniSuffix("time.apple.com") => Category::Ntp,
    Match::SniSuffix("time.windows.com") => Category::Ntp,
    Match::SniSuffix("time.google.com") => Category::Ntp,

    // ---- OS vendors ----
    Match::SniSuffix("apple.com") => Category::OsVendor,
    Match::SniSuffix("icloud.com") => Category::OsVendor,
    Match::SniSuffix("mzstatic.com") => Category::OsVendor,
    Match::SniSuffix("windowsupdate.com") => Category::OsVendor,
    Match::SniSuffix("microsoft.com") => Category::OsVendor,
    Match::SniSuffix("canonical.com") => Category::OsVendor,

    // ---- telemetry / error reporting ----
    Match::SniSuffix("sentry.io") => Category::Telemetry,
    Match::SniSuffix("ingest.sentry.io") => Category::Telemetry,
    Match::SniSuffix("bugsnag.com") => Category::Telemetry,
    Match::SniSuffix("datadoghq.com") => Category::Telemetry,
    Match::SniSuffix("segment.io") => Category::Telemetry,
    Match::SniSuffix("amplitude.com") => Category::Telemetry,
    Match::SniSuffix("posthog.com") => Category::Telemetry,
    Match::SniSuffix("google-analytics.com") => Category::Telemetry,
    Match::SniSuffix("crashlytics.com") => Category::Telemetry,

    // ---- inference APIs ----
    Match::SniSuffix("api.anthropic.com") => Category::AiProvider,
    Match::SniSuffix("api.openai.com") => Category::AiProvider,
    Match::SniSuffix("generativelanguage.googleapis.com") => Category::AiProvider,
    Match::SniSuffix("api.mistral.ai") => Category::AiProvider,
    Match::SniSuffix("huggingface.co") => Category::AiProvider,
    Match::SniSuffix("cdn-lfs.huggingface.co") => Category::AiProvider,
    Match::SniSuffix("ollama.com") => Category::AiProvider,
];

/// True when `host` is `suffix` or a label-boundary subdomain of it.
///
/// The boundary check is the whole point. A naive `ends_with` would let
/// `evil-github.com` match `github.com`, which hands an attacker a `benign`
/// label for the price of a domain registration.
fn suffix_matches(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    if host == suffix {
        return true;
    }
    host.len() > suffix.len()
        && host.ends_with(&suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

/// Resolve a destination against the table.
///
/// Order is exact SNI, then SNI suffix, then ASN org — most specific first, so
/// a precise entry always wins over a broad one.
pub fn classify(sni: Option<&str>, asn_org: Option<&str>, _port: u16) -> Option<CatalogHit> {
    if let Some(host) = sni {
        for e in CATALOG {
            if let Match::Sni(pat) = e.matcher {
                if host.eq_ignore_ascii_case(pat) {
                    return Some(hit(e, pat));
                }
            }
        }
        for e in CATALOG {
            if let Match::SniSuffix(pat) = e.matcher {
                if suffix_matches(host, pat) {
                    return Some(hit(e, pat));
                }
            }
        }
    }
    if let Some(org) = asn_org {
        for e in CATALOG {
            if let Match::AsnOrg(pat) = e.matcher {
                if org.eq_ignore_ascii_case(pat) {
                    return Some(hit(e, pat));
                }
            }
        }
    }
    None
}

fn hit(e: &'static Entry, matched: &'static str) -> CatalogHit {
    CatalogHit {
        label: e.category.label(),
        category: e.category,
        matched,
        reason: match e.category {
            Category::PackageRegistry => "package registry",
            Category::Cdn => "shared CDN",
            Category::CertRevocation => "certificate infrastructure",
            Category::Ntp => "time synchronisation",
            Category::DeveloperPlatform => "developer platform",
            Category::OsVendor => "OS vendor endpoint",
            Category::Telemetry => "telemetry / error reporting",
            Category::AiProvider => "model inference API",
        },
    }
}

/// Render the table for `--egress-catalog`. A label a user cannot inspect is
/// a label they cannot trust.
pub fn render() -> String {
    let mut out = format!(
        "netwatch egress catalog — {} entries\n\n{:<44} {:<20} {}\n",
        CATALOG.len(),
        "PATTERN",
        "CATEGORY",
        "LABEL"
    );
    for e in CATALOG {
        let (kind, pat) = match e.matcher {
            Match::Sni(p) => ("=", p),
            Match::SniSuffix(p) => ("*", p),
            Match::AsnOrg(p) => ("as", p),
        };
        out.push_str(&format!(
            "{:<44} {:<20} {}\n",
            format!("{kind} {pat}"),
            e.category.name(),
            e.category.label().tag()
        ));
    }
    out.push_str("\n= exact hostname   * hostname or subdomain   as autonomous-system org\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        assert!(suffix_matches("github.com", "github.com"));
        assert!(suffix_matches("api.github.com", "github.com"));
        assert!(suffix_matches("API.GitHub.COM", "github.com"));
        assert!(suffix_matches("api.github.com.", "github.com"));

        // The registrations an attacker would actually make.
        assert!(!suffix_matches("evil-github.com", "github.com"));
        assert!(!suffix_matches("notgithub.com", "github.com"));
        assert!(!suffix_matches("github.com.evil.io", "github.com"));
        assert!(!suffix_matches("xgithub.com", "github.com"));
        assert!(!suffix_matches("", "github.com"));
    }

    #[test]
    fn a_more_specific_entry_is_not_shadowed_by_a_broader_one() {
        // huggingface.co is an ai-provider; nothing in the CDN block should
        // claim it first.
        let hit = classify(Some("cdn-lfs.huggingface.co"), None, 443).unwrap();
        assert_eq!(hit.category, Category::AiProvider);
    }

    #[test]
    fn infrastructure_is_benign_and_vendor_endpoints_are_only_expected() {
        assert_eq!(
            classify(Some("crates.io"), None, 443).unwrap().label,
            Label::Benign
        );
        assert_eq!(
            classify(Some("api.anthropic.com"), None, 443)
                .unwrap()
                .label,
            Label::Expected,
            "an inference API is only reasonable for the software that owns it"
        );
        assert_eq!(
            classify(Some("ingest.sentry.io"), None, 443).unwrap().label,
            Label::Expected
        );
    }

    #[test]
    fn an_unknown_destination_resolves_to_nothing() {
        assert!(classify(Some("paste.ee"), None, 443).is_none());
        assert!(classify(None, None, 443).is_none());
        assert!(classify(None, Some("Some Hosting LLC"), 443).is_none());
    }

    #[test]
    fn every_entry_renders() {
        let out = render();
        assert!(out.contains(&format!("{} entries", CATALOG.len())));
        for e in CATALOG {
            let pat = match e.matcher {
                Match::Sni(p) | Match::SniSuffix(p) | Match::AsnOrg(p) => p,
            };
            assert!(
                out.contains(pat),
                "catalog entry {pat} missing from --egress-catalog"
            );
        }
    }
}
