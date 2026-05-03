//! Kernel command line parsing and manipulation.
//!
//! This module provides utilities for parsing and generating kernel command line arguments,
//! with specific support for composefs parameters. It handles the kernel's simple quoting
//! mechanism and provides functions to extract and create composefs= arguments with optional
//! insecure mode indicators.

use anyhow::{Context, Result};
use composefs::fsverity::FsVerityHashValue;

/// Kernel argument name for the V2 EROFS format: `composefs=<digest>`.
///
/// Used in existing sealed UKIs. The initramfs checks for [`KARG_V1`] first,
/// then falls back to this.
pub const KARG_V2: &str = "composefs";

/// Kernel argument name for the V1 EROFS format: `composefs.digest=<digest>`.
///
/// Newer karg added to distinguish V1 EROFS images from V2. The initramfs
/// checks for this before falling back to [`KARG_V2`].
pub const KARG_V1: &str = "composefs.digest";

/// A composefs kernel argument identifying which EROFS image to mount at boot.
///
/// Two variants exist to distinguish EROFS format versions:
/// - [`ComposefsCmdline::V2`]: legacy `composefs=<digest>` karg (V2 EROFS, existing sealed UKIs)
/// - [`ComposefsCmdline::V1`]: new `composefs.digest=<digest>` karg (V1 EROFS)
///
/// The initramfs checks for `composefs.digest=` first, then falls back to `composefs=`.
///
/// NOTE: The equivalent parsing logic in bootc's `crates/initramfs/src/lib.rs` must be
/// kept in sync with this file manually, since bootc does not yet depend on composefs-boot
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposefsCmdline<ObjectID: FsVerityHashValue> {
    /// V2 EROFS image: embedded as `composefs=<hex-digest>` in the UKI cmdline.
    ///
    /// The `insecure` flag, when `true`, means the digest is prefixed with `?`
    /// (e.g. `composefs=?<hex>`), making fs-verity verification optional.
    V2 {
        /// The fs-verity hash of the EROFS image.
        digest: ObjectID,
        /// If `true`, a `?` prefix is added to the digest, making fs-verity
        /// verification optional at boot.
        insecure: bool,
    },
    /// V1 EROFS image: embedded as `composefs.digest=<hex-digest>` in the UKI cmdline.
    ///
    /// The `insecure` flag, when `true`, means the digest is prefixed with `?`
    /// (e.g. `composefs.digest=?<hex>`), making fs-verity verification optional.
    V1 {
        /// The fs-verity hash of the EROFS image.
        digest: ObjectID,
        /// If `true`, a `?` prefix is added to the digest, making fs-verity
        /// verification optional at boot.
        insecure: bool,
    },
}

impl<ObjectID: FsVerityHashValue> ComposefsCmdline<ObjectID> {
    /// Returns a reference to the hex digest, regardless of variant.
    ///
    /// Useful for looking up the image in `composefs/images/<digest>`.
    pub fn digest(&self) -> &ObjectID {
        match self {
            ComposefsCmdline::V2 { digest, .. } | ComposefsCmdline::V1 { digest, .. } => digest,
        }
    }

    /// Returns whether this karg is in insecure mode (fs-verity verification skipped).
    pub fn is_insecure(&self) -> bool {
        match self {
            ComposefsCmdline::V1 { insecure, .. } | ComposefsCmdline::V2 { insecure, .. } => {
                *insecure
            }
        }
    }

    /// Constructs a V2 cmdline value (`composefs=<hex>`).
    pub fn new_v2(digest: ObjectID, insecure: bool) -> Self {
        ComposefsCmdline::V2 { digest, insecure }
    }

    /// Constructs a V1 cmdline value (`composefs.digest=<hex>`).
    pub fn new_v1(digest: ObjectID, insecure: bool) -> Self {
        ComposefsCmdline::V1 { digest, insecure }
    }

    /// Parses a [`ComposefsCmdline`] from a kernel command line string.
    ///
    /// Checks for `composefs.digest=` first (→ [`ComposefsCmdline::V1`]), then falls
    /// back to `composefs=` (→ [`ComposefsCmdline::V2`]). Returns `None` if neither
    /// is present.
    ///
    /// # Errors
    ///
    /// Returns an error if a matching karg is found but the hex digest cannot be parsed
    /// for the given `ObjectID` type.
    pub fn from_cmdline(cmdline: &str) -> Result<Option<Self>> {
        let expected_hex_len = size_of::<ObjectID>() * 2;

        // V1: composefs.digest=<hex>  (checked first per initramfs convention)
        // Optional '?' prefix for insecure mode: composefs.digest=?<hex>
        if let Some(val) = get_cmdline_value(cmdline, &format!("{KARG_V1}=")) {
            let (hex, insecure) = if let Some(stripped) = val.strip_prefix('?') {
                (stripped, true)
            } else {
                (val, false)
            };
            let digest = ObjectID::from_hex(hex).with_context(|| {
                format!(
                    "parsing {KARG_V1}= hash: got {} hex chars, expected {} for {}",
                    hex.len(),
                    expected_hex_len,
                    ObjectID::ALGORITHM,
                )
            })?;
            return Ok(Some(ComposefsCmdline::V1 { digest, insecure }));
        }

        // V2: composefs=<hex>  (optional '?' prefix for insecure mode)
        if let Some(val) = get_cmdline_value(cmdline, &format!("{KARG_V2}=")) {
            let (hex, insecure) = if let Some(stripped) = val.strip_prefix('?') {
                (stripped, true)
            } else {
                (val, false)
            };
            let digest = ObjectID::from_hex(hex).with_context(|| {
                format!(
                    "parsing {KARG_V2}= hash: got {} hex chars, expected {} for {}",
                    hex.len(),
                    expected_hex_len,
                    ObjectID::ALGORITHM,
                )
            })?;
            return Ok(Some(ComposefsCmdline::V2 { digest, insecure }));
        }

        Ok(None)
    }

    /// Renders this value as a kernel command line fragment.
    ///
    /// - [`ComposefsCmdline::V1`] (secure)   → `"composefs.digest=<hex>"`
    /// - [`ComposefsCmdline::V1`] (insecure) → `"composefs.digest=?<hex>"`
    /// - [`ComposefsCmdline::V2`] (secure)   → `"composefs=<hex>"`
    /// - [`ComposefsCmdline::V2`] (insecure) → `"composefs=?<hex>"`
    pub fn to_cmdline_arg(&self) -> String {
        match self {
            ComposefsCmdline::V1 {
                digest,
                insecure: false,
            } => format!("{KARG_V1}={}", digest.to_hex()),
            ComposefsCmdline::V1 {
                digest,
                insecure: true,
            } => format!("{KARG_V1}=?{}", digest.to_hex()),
            ComposefsCmdline::V2 {
                digest,
                insecure: false,
            } => {
                format!("{KARG_V2}={}", digest.to_hex())
            }
            ComposefsCmdline::V2 {
                digest,
                insecure: true,
            } => {
                format!("{KARG_V2}=?{}", digest.to_hex())
            }
        }
    }
}

/// Perform kernel command line splitting.
///
/// The way this works in the kernel is to split on whitespace with an extremely simple quoting
/// mechanism: whitespace inside of double quotes is literal, but there is no escaping mechanism.
/// That means that having a literal double quote in the cmdline is effectively impossible.
pub(crate) fn split_cmdline(cmdline: &str) -> impl Iterator<Item = &str> {
    let mut in_quotes = false;

    cmdline.split(move |c: char| {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        !in_quotes && c.is_ascii_whitespace()
    })
}

/// Gets the value of an entry from the kernel cmdline.
///
/// The prefix should be something like "composefs=".
///
/// This iterates the entries in the provided cmdline string searching for an entry that starts
/// with the provided prefix.  This will successfully handle quoting of other items in the cmdline,
/// but the value of the searched entry is returned verbatim (ie: not dequoted).
pub fn get_cmdline_value<'a>(cmdline: &'a str, prefix: &str) -> Option<&'a str> {
    split_cmdline(cmdline).find_map(|item| item.strip_prefix(prefix))
}

/// Creates a composefs kernel command line argument string.
///
/// # Arguments
///
/// * `id` - The composefs object ID as a hex string
/// * `insecure` - If true, prepends '?' to make fs-verity verification optional
/// * `version` - Which EROFS format version karg to emit
///
/// # Returns
///
/// A string like `"composefs.digest=abc123"` (V1) or `"composefs=abc123"` (V2),
/// with optional `?` prefix for insecure mode.
pub fn make_cmdline_composefs(
    id: &str,
    insecure: bool,
    version: composefs::erofs::format::FormatVersion,
) -> String {
    use composefs::erofs::format::FormatVersion;
    let prefix = match version {
        FormatVersion::V1 => KARG_V1,
        FormatVersion::V2 => KARG_V2,
    };
    match insecure {
        true => format!("{prefix}=?{id}"),
        false => format!("{prefix}={id}"),
    }
}

#[cfg(test)]
mod tests {
    use composefs::fsverity::Sha256HashValue;

    use super::*;

    const SHA256_HEX: &str = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";

    #[test]
    fn test_composefs_cmdline_v2_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v2(digest.clone(), false);
        assert_eq!(karg.to_cmdline_arg(), format!("composefs={SHA256_HEX}"));

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V2 {
                digest,
                insecure: false
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v2_insecure_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v2(digest.clone(), true);
        assert_eq!(karg.to_cmdline_arg(), format!("composefs=?{SHA256_HEX}"));

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V2 {
                digest,
                insecure: true
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v1(digest.clone(), false);
        assert_eq!(
            karg.to_cmdline_arg(),
            format!("composefs.digest={SHA256_HEX}")
        );

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V1 {
                digest,
                insecure: false
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_insecure_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v1(digest.clone(), true);
        assert_eq!(
            karg.to_cmdline_arg(),
            format!("composefs.digest=?{SHA256_HEX}")
        );

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V1 {
                digest,
                insecure: true
            }
        );
        assert!(parsed.is_insecure());
    }

    #[test]
    fn test_composefs_cmdline_v1_takes_priority_over_v2() {
        // When both kargs are present, V1 (composefs.digest=) should win.
        let hex_v1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hex_v2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let cmdline = format!("composefs={hex_v2} composefs.digest={hex_v1}");

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(
            matches!(&parsed, ComposefsCmdline::V1 { digest, .. } if digest.to_hex() == hex_v1),
            "expected V1 variant with hex_v1, got {parsed:?}"
        );
    }

    #[test]
    fn test_composefs_cmdline_absent_returns_none() {
        assert!(
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("quiet splash rw")
                .unwrap()
                .is_none()
        );
        assert!(
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_composefs_cmdline_invalid_hex_errors() {
        // Valid key present but digest is garbage.
        let err = ComposefsCmdline::<Sha256HashValue>::from_cmdline("composefs.digest=notahex")
            .unwrap_err();
        assert!(err.to_string().contains("composefs.digest="));

        let err =
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("composefs=notahex").unwrap_err();
        assert!(err.to_string().contains("composefs="));
    }

    #[test]
    fn test_digest_accessor() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let v1 = ComposefsCmdline::new_v1(digest.clone(), false);
        let v2 = ComposefsCmdline::new_v2(digest.clone(), false);
        assert_eq!(v1.digest(), &digest);
        assert_eq!(v2.digest(), &digest);
    }

    #[test]
    fn test_from_cmdline_v1() {
        let cmdline = format!("root=UUID=abc composefs.digest={SHA256_HEX} rw");
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(matches!(result, ComposefsCmdline::V1 { .. }));
        assert_eq!(result.digest().to_hex(), SHA256_HEX);
        assert!(!result.is_insecure());
    }

    #[test]
    fn test_from_cmdline_v2_fallback() {
        let cmdline = format!("root=UUID=abc composefs={SHA256_HEX} rw");
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(matches!(result, ComposefsCmdline::V2 { .. }));
        assert_eq!(result.digest().to_hex(), SHA256_HEX);
        assert!(!result.is_insecure());
    }

    #[test]
    fn test_from_cmdline_missing_returns_none() {
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline("root=UUID=abc rw").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_from_cmdline_insecure_prefix() {
        let cmdline = format!("composefs=?{SHA256_HEX}");
        let result = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(result.is_insecure());
        assert_eq!(result.digest().to_hex(), SHA256_HEX);
    }

    #[test]
    fn test_make_cmdline_composefs_v1() {
        use composefs::erofs::format::FormatVersion;
        let result = make_cmdline_composefs(SHA256_HEX, false, FormatVersion::V1);
        assert_eq!(result, format!("composefs.digest={SHA256_HEX}"));
    }

    #[test]
    fn test_make_cmdline_composefs_v2_insecure() {
        use composefs::erofs::format::FormatVersion;
        let result = make_cmdline_composefs(SHA256_HEX, true, FormatVersion::V2);
        assert_eq!(result, format!("composefs=?{SHA256_HEX}"));
    }
}

#[cfg(test)]
mod tests {
    use composefs::fsverity::Sha256HashValue;

    use super::*;

    const SHA256_HEX: &str = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";

    #[test]
    fn test_composefs_cmdline_v2_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v2(digest.clone(), false);
        assert_eq!(karg.to_cmdline_arg(), format!("composefs={SHA256_HEX}"));

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V2 {
                digest,
                insecure: false
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v2_insecure_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v2(digest.clone(), true);
        assert_eq!(karg.to_cmdline_arg(), format!("composefs=?{SHA256_HEX}"));

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V2 {
                digest,
                insecure: true
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v1(digest.clone(), false);
        assert_eq!(
            karg.to_cmdline_arg(),
            format!("composefs.digest={SHA256_HEX}")
        );

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V1 {
                digest,
                insecure: false
            }
        );
    }

    #[test]
    fn test_composefs_cmdline_v1_insecure_round_trip() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let karg = ComposefsCmdline::new_v1(digest.clone(), true);
        assert_eq!(
            karg.to_cmdline_arg(),
            format!("composefs.digest=?{SHA256_HEX}")
        );

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&karg.to_cmdline_arg())
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed,
            ComposefsCmdline::V1 {
                digest,
                insecure: true
            }
        );
        assert!(parsed.is_insecure());
    }

    #[test]
    fn test_composefs_cmdline_v1_takes_priority_over_v2() {
        // When both kargs are present, V1 (composefs.digest=) should win.
        let hex_v1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hex_v2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let cmdline = format!("composefs={hex_v2} composefs.digest={hex_v1}");

        let parsed = ComposefsCmdline::<Sha256HashValue>::from_cmdline(&cmdline)
            .unwrap()
            .unwrap();
        assert!(
            matches!(&parsed, ComposefsCmdline::V1 { digest, .. } if digest.to_hex() == hex_v1),
            "expected V1 variant with hex_v1, got {parsed:?}"
        );
    }

    #[test]
    fn test_composefs_cmdline_absent_returns_none() {
        assert!(
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("quiet splash rw")
                .unwrap()
                .is_none()
        );
        assert!(
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_composefs_cmdline_invalid_hex_errors() {
        // Valid key present but digest is garbage.
        let err = ComposefsCmdline::<Sha256HashValue>::from_cmdline("composefs.digest=notahex")
            .unwrap_err();
        assert!(err.to_string().contains("composefs.digest="));

        let err =
            ComposefsCmdline::<Sha256HashValue>::from_cmdline("composefs=notahex").unwrap_err();
        assert!(err.to_string().contains("composefs="));
    }

    #[test]
    fn test_digest_accessor() {
        let digest = Sha256HashValue::from_hex(SHA256_HEX).unwrap();
        let v1 = ComposefsCmdline::new_v1(digest.clone(), false);
        let v2 = ComposefsCmdline::new_v2(digest.clone(), false);
        assert_eq!(v1.digest(), &digest);
        assert_eq!(v2.digest(), &digest);
    }
}
