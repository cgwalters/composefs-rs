//! Composefs signature artifact construction and verification.
//!
//! Builds OCI artifact manifests containing composefs fsverity digests
//! (and optionally PKCS#7 signatures) per the OCI sealing specification.
//! Signature artifacts reference the source image via the OCI referrer
//! pattern (`subject` field) and are discoverable via the `/referrers` API.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use composefs::fsverity::algorithm::ComposeFsAlgorithm;
use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use containers_image_proxy::oci_spec::image::{
    Descriptor, DescriptorBuilder, Digest as OciDigest, ImageManifest, ImageManifestBuilder,
    MediaType,
};

/// Artifact type for composefs signature manifests.
pub const ARTIFACT_TYPE: &str = "application/vnd.composefs.signature.v1";

/// Media type for PKCS#7 DER signature layers.
pub const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.composefs.signature.v1+pkcs7";

/// Annotation key for the composefs signature type on each layer.
pub const ANN_SIGNATURE_TYPE: &str = "composefs.signature.type";

/// Annotation key for the composefs fsverity digest on each layer.
pub const ANN_DIGEST: &str = "composefs.digest";

/// Annotation key for the composefs algorithm on the artifact manifest.
pub const ANN_ALGORITHM: &str = "composefs.algorithm";

/// The type of object a signature layer refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    /// Signature for the OCI manifest JSON.
    Manifest,
    /// Signature for the OCI config JSON.
    Config,
    /// Signature for an individual composefs layer EROFS.
    Layer,
    /// Signature for a merged (rolling) composefs filesystem.
    Merged,
}

impl SignatureType {
    /// The annotation value string for this type.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureType::Manifest => "manifest",
            SignatureType::Config => "config",
            SignatureType::Layer => "layer",
            SignatureType::Merged => "merged",
        }
    }

    /// Parse from an annotation value string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "manifest" => Some(SignatureType::Manifest),
            "config" => Some(SignatureType::Config),
            "layer" => Some(SignatureType::Layer),
            "merged" => Some(SignatureType::Merged),
            _ => None,
        }
    }

    /// Ordering rank for enforcing canonical entry order.
    fn rank(self) -> u8 {
        match self {
            SignatureType::Manifest => 0,
            SignatureType::Config => 1,
            SignatureType::Layer => 2,
            SignatureType::Merged => 3,
        }
    }
}

impl std::fmt::Display for SignatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SignatureType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| anyhow::anyhow!("unknown signature type: {s}"))
    }
}

/// A single entry in a composefs signature artifact.
///
/// Contains the composefs fsverity digest and optionally a PKCS#7 signature blob.
/// When no signature is present, the entry is "digest-only" — the digest can be
/// verified against the EROFS blob but without kernel signature enforcement.
#[derive(Debug)]
pub struct SignatureEntry {
    /// What this entry signs (manifest, config, layer, or merged).
    pub sig_type: SignatureType,
    /// The composefs fsverity digest as a hex string.
    pub digest: String,
    /// Raw PKCS#7 DER signature blob, if available.
    pub signature: Option<Vec<u8>>,
}

/// The result of parsing a composefs signature artifact manifest.
#[derive(Debug)]
pub struct ParsedSignatureArtifact {
    /// The composefs algorithm used for fsverity digests.
    pub algorithm: ComposeFsAlgorithm,
    /// The subject descriptor (the image this artifact refers to).
    pub subject: Descriptor,
    /// Signature entries in artifact layer order.
    pub entries: Vec<SignatureEntry>,
}

/// Builder for composefs signature artifacts.
///
/// Collects signature entries and produces an OCI image manifest
/// following the OCI artifacts guidance pattern.
#[derive(Debug)]
pub struct SignatureArtifactBuilder {
    /// Algorithm identifier (e.g. SHA512_12).
    algorithm: ComposeFsAlgorithm,
    /// The subject descriptor (the source image manifest).
    subject: Descriptor,
    /// Signature entries in order: manifest, config, layers, merged.
    entries: Vec<SignatureEntry>,
    /// Rank of the last entry added, for ordering enforcement.
    last_rank: Option<u8>,
}

/// The result of building a signature artifact.
#[derive(Debug)]
pub struct SignatureArtifact {
    /// The OCI image manifest for the artifact.
    pub manifest: ImageManifest,
    /// The raw layer blobs (PKCS#7 signatures or empty placeholders).
    /// One per entry, in the same order as the manifest layers.
    pub blobs: Vec<Vec<u8>>,
}

/// The sha256 digest of `{}` (empty JSON object), per OCI artifacts guidance.
const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

impl SignatureArtifactBuilder {
    /// Create a new builder for a signature artifact.
    ///
    /// `algorithm` is the composefs algorithm identifier (e.g. `ComposeFsAlgorithm::SHA512_12`).
    /// `subject` is the descriptor of the source image manifest being signed.
    pub fn new(algorithm: ComposeFsAlgorithm, subject: Descriptor) -> Self {
        SignatureArtifactBuilder {
            algorithm,
            subject,
            entries: Vec::new(),
            last_rank: None,
        }
    }

    /// Add a signature entry.
    ///
    /// Entries MUST be added in the spec-defined order:
    /// manifest, config, layers (in manifest order), merged (in manifest order).
    /// Returns an error if the entry would violate this ordering, or if a
    /// `Manifest` or `Config` entry is duplicated.
    pub fn add_entry(&mut self, entry: SignatureEntry) -> Result<()> {
        let rank = entry.sig_type.rank();

        if let Some(last) = self.last_rank {
            if rank < last {
                bail!(
                    "out-of-order entry: {} after {}",
                    entry.sig_type,
                    rank_to_name(last)
                );
            }
            // Reject duplicate Manifest or Config (at most one each)
            if rank == last && rank <= 1 {
                bail!("duplicate {} entry", entry.sig_type);
            }
        }

        self.last_rank = Some(rank);
        self.entries.push(entry);
        Ok(())
    }

    /// Add digest-only entries for per-layer composefs digests.
    ///
    /// Convenience method that adds one `Layer` entry per digest.
    pub fn add_layer_digests<ObjectID: FsVerityHashValue>(
        &mut self,
        digests: &[ObjectID],
    ) -> Result<()> {
        for digest in digests {
            self.add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: digest.to_hex(),
                signature: None,
            })?;
        }
        Ok(())
    }

    /// Add a digest-only entry for a merged composefs digest.
    pub fn add_merged_digest<ObjectID: FsVerityHashValue>(
        &mut self,
        digest: &ObjectID,
    ) -> Result<()> {
        self.add_entry(SignatureEntry {
            sig_type: SignatureType::Merged,
            digest: digest.to_hex(),
            signature: None,
        })
    }

    /// Build the signature artifact.
    ///
    /// Produces an OCI image manifest and the associated layer blobs.
    pub fn build(self) -> Result<SignatureArtifact> {
        let mut layers = Vec::with_capacity(self.entries.len());
        let mut blobs = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            // The layer blob is the PKCS#7 signature, or empty for digest-only entries
            let blob = entry.signature.clone().unwrap_or_default();
            let blob_digest = sha256_digest(&blob);

            let mut annotations = HashMap::new();
            annotations.insert(
                ANN_SIGNATURE_TYPE.to_string(),
                entry.sig_type.as_str().to_string(),
            );
            annotations.insert(ANN_DIGEST.to_string(), entry.digest.clone());

            let descriptor = DescriptorBuilder::default()
                .media_type(MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string()))
                .digest(OciDigest::from_str(&blob_digest).context("parsing blob digest")?)
                .size(blob.len() as u64)
                .annotations(annotations)
                .build()
                .context("building layer descriptor")?;

            layers.push(descriptor);
            blobs.push(blob);
        }

        // Empty config per OCI artifacts guidance
        let config = DescriptorBuilder::default()
            .media_type(MediaType::Other(
                "application/vnd.oci.empty.v1+json".to_string(),
            ))
            .digest(
                OciDigest::from_str(EMPTY_CONFIG_DIGEST).context("parsing empty config digest")?,
            )
            .size(2u64)
            .build()
            .context("building config descriptor")?;

        let mut annotations = HashMap::new();
        annotations.insert(ANN_ALGORITHM.to_string(), self.algorithm.to_string());

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .artifact_type(MediaType::Other(ARTIFACT_TYPE.to_string()))
            .config(config)
            .layers(layers)
            .subject(self.subject)
            .annotations(annotations)
            .build()
            .context("building signature artifact manifest")?;

        Ok(SignatureArtifact { manifest, blobs })
    }
}

/// Parse a composefs signature artifact manifest and extract digest entries.
///
/// Validates artifact type, layer media types, digest format/length, entry
/// ordering, and the presence of a subject descriptor.
pub fn parse_signature_artifact(manifest: &ImageManifest) -> Result<ParsedSignatureArtifact> {
    // Validate artifact type
    match manifest.artifact_type() {
        Some(MediaType::Other(s)) if s == ARTIFACT_TYPE => {}
        other => bail!(
            "wrong artifact type: expected {ARTIFACT_TYPE}, got {}",
            match other {
                Some(t) => format!("{t:?}"),
                None => "none".to_string(),
            }
        ),
    }

    // A referrer artifact MUST have a subject
    let subject = manifest
        .subject()
        .as_ref()
        .context("signature artifact missing subject descriptor")?
        .clone();

    let annotations = manifest
        .annotations()
        .as_ref()
        .context("signature artifact missing annotations")?;

    let algorithm: ComposeFsAlgorithm = annotations
        .get(ANN_ALGORITHM)
        .context("signature artifact missing composefs.algorithm annotation")?
        .parse()
        .context("parsing composefs.algorithm annotation")?;

    let expected_digest_bytes = algorithm.digest_size();

    let mut entries = Vec::with_capacity(manifest.layers().len());

    for layer in manifest.layers() {
        // Validate layer media type
        if *layer.media_type() != MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string()) {
            bail!(
                "wrong layer media type: expected {SIGNATURE_MEDIA_TYPE}, got {:?}",
                layer.media_type()
            );
        }

        let layer_annotations = layer
            .annotations()
            .as_ref()
            .context("signature layer missing annotations")?;

        let sig_type_str = layer_annotations
            .get(ANN_SIGNATURE_TYPE)
            .context("signature layer missing composefs.signature.type")?;

        let sig_type = SignatureType::parse(sig_type_str)
            .context(format!("unknown signature type: {sig_type_str}"))?;

        let digest = layer_annotations
            .get(ANN_DIGEST)
            .context("signature layer missing composefs.digest")?
            .clone();

        // Validate digest: must be valid hex with correct length for the algorithm
        let decoded = hex::decode(&digest)
            .context(format!("invalid composefs.digest: not valid hex: {digest}"))?;
        if decoded.len() != expected_digest_bytes {
            bail!(
                "invalid composefs.digest: expected {} bytes for {}, got {}",
                expected_digest_bytes,
                algorithm,
                decoded.len()
            );
        }

        entries.push(SignatureEntry {
            sig_type,
            digest,
            // Signature blob must be fetched separately by the caller
            signature: None,
        });
    }

    // Validate entry ordering and uniqueness
    validate_entry_ordering(&entries)?;

    Ok(ParsedSignatureArtifact {
        algorithm,
        subject,
        entries,
    })
}

/// Validate that entries follow the required ordering and uniqueness constraints.
///
/// Required order: Manifest (0..=1), Config (0..=1), Layer (0..), Merged (0..).
fn validate_entry_ordering(entries: &[SignatureEntry]) -> Result<()> {
    let mut prev_rank: Option<u8> = None;
    let mut manifest_count = 0u32;
    let mut config_count = 0u32;

    for entry in entries {
        let rank = entry.sig_type.rank();
        if let Some(prev) = prev_rank {
            if rank < prev {
                bail!(
                    "out-of-order entry: {} after {}",
                    entry.sig_type,
                    rank_to_name(prev)
                );
            }
        }

        match entry.sig_type {
            SignatureType::Manifest => {
                manifest_count += 1;
                if manifest_count > 1 {
                    bail!("duplicate manifest entry");
                }
            }
            SignatureType::Config => {
                config_count += 1;
                if config_count > 1 {
                    bail!("duplicate config entry");
                }
            }
            _ => {}
        }

        prev_rank = Some(rank);
    }
    Ok(())
}

/// Map a rank value back to a type name for error messages.
fn rank_to_name(rank: u8) -> &'static str {
    match rank {
        0 => "manifest",
        1 => "config",
        2 => "layer",
        3 => "merged",
        _ => "unknown",
    }
}

// =============================================================================
// Repository Storage and Discovery
// =============================================================================

/// Stores a signature artifact in the repository and indexes it as a referrer.
///
/// Writes the artifact's layer blobs and manifest, then creates a referrer
/// index entry linking it to its subject image. The subject is extracted from
/// the manifest's `subject` field.
///
/// Returns `(manifest_digest, manifest_verity)` for the stored artifact.
pub fn store_signature_artifact<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    artifact: SignatureArtifact,
) -> Result<(String, ObjectID)> {
    // Write the empty config "{}"
    let empty_config = b"{}";
    let config_digest = sha256_digest(empty_config);
    let config_id = crate::config_identifier(&config_digest);

    let config_verity = match repo.has_stream(&config_id)? {
        Some(v) => v,
        None => {
            let mut config_stream = repo.create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE);
            config_stream.write_inline(empty_config);
            repo.write_stream(config_stream, &config_id, None)?
        }
    };

    // Write each layer blob and collect verity mappings
    let mut layer_verities = HashMap::new();
    for (descriptor, blob) in artifact.manifest.layers().iter().zip(&artifact.blobs) {
        let (blob_digest, blob_verity) = crate::oci_image::write_blob(repo, blob)?;
        // For artifacts, the layer descriptor's digest is the key
        let desc_digest = descriptor.digest().to_string();

        // Sanity check: the blob digest we computed should match the descriptor
        if blob_digest != desc_digest {
            anyhow::bail!(
                "Layer blob digest mismatch: descriptor says {desc_digest}, \
                 computed {blob_digest}"
            );
        }

        layer_verities.insert(desc_digest.into_boxed_str(), blob_verity);
    }

    // Compute the manifest digest
    let manifest_json = artifact.manifest.to_string()?;
    let manifest_digest = sha256_digest(manifest_json.as_bytes());

    // Write the manifest (no tag — referrer artifacts aren't typically tagged)
    let (digest, verity) = crate::oci_image::write_manifest(
        repo,
        &artifact.manifest,
        &manifest_digest,
        &config_verity,
        &layer_verities,
        None,
    )?;

    // Extract the subject digest and create the referrer index entry
    let subject = artifact
        .manifest
        .subject()
        .as_ref()
        .context("Signature artifact has no subject")?;
    let subject_digest = subject.digest().to_string();

    crate::oci_image::add_referrer(repo, &subject_digest, &digest)?;

    Ok((digest, verity))
}

/// Finds and parses composefs signature artifacts referencing the given image.
///
/// Searches the local referrer index for artifacts with the composefs signature
/// artifact type, then parses each one. Non-signature referrers are silently
/// skipped.
pub fn find_signature_artifacts<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    subject_digest: &str,
) -> Result<Vec<ParsedSignatureArtifact>> {
    use crate::oci_image::{list_referrers, OciImage};

    let referrers = list_referrers(repo, subject_digest)?;
    let mut results = Vec::new();

    for (artifact_digest, artifact_verity) in &referrers {
        // Open the artifact manifest
        let image = match OciImage::open(repo, artifact_digest, Some(artifact_verity)) {
            Ok(img) => img,
            Err(e) => {
                eprintln!("Warning: failed to open referrer artifact {artifact_digest}: {e:#}");
                continue;
            }
        };

        // Check if this is a composefs signature artifact
        let manifest = image.manifest();
        match manifest.artifact_type() {
            Some(MediaType::Other(t)) if t == ARTIFACT_TYPE => {}
            _ => continue, // Not a composefs signature artifact, skip
        }

        // Parse the signature artifact
        match parse_signature_artifact(manifest) {
            Ok(parsed) => results.push(parsed),
            Err(e) => {
                eprintln!("Warning: failed to parse signature artifact {artifact_digest}: {e:#}");
            }
        }
    }

    Ok(results)
}

fn sha256_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a realistic-length fake SHA-512 hex digest (128 hex chars = 64 bytes).
    fn fake_sha512_digest(seed: u8) -> String {
        std::iter::repeat(format!("{seed:02x}")).take(64).collect()
    }

    /// Generate a realistic-length fake SHA-256 hex digest (64 hex chars = 32 bytes).
    fn fake_sha256_digest(seed: u8) -> String {
        std::iter::repeat(format!("{seed:02x}")).take(32).collect()
    }

    fn sample_subject() -> Descriptor {
        DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(
                OciDigest::from_str(
                    "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
                )
                .unwrap(),
            )
            .size(7682u64)
            .build()
            .unwrap()
    }

    #[test]
    fn build_digest_only_artifact() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let layer_digest = fake_sha512_digest(0xab);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: layer_digest.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        assert_eq!(artifact.manifest.schema_version(), 2);
        assert_eq!(
            artifact.manifest.artifact_type().as_ref().unwrap(),
            &MediaType::Other(ARTIFACT_TYPE.to_string())
        );
        assert_eq!(artifact.manifest.layers().len(), 1);
        assert_eq!(artifact.blobs.len(), 1);

        let subject = artifact.manifest.subject().as_ref().unwrap();
        assert_eq!(subject.media_type(), &MediaType::ImageManifest);

        let layer = &artifact.manifest.layers()[0];
        let ann = layer.annotations().as_ref().unwrap();
        assert_eq!(ann.get(ANN_SIGNATURE_TYPE).unwrap(), "layer");
        assert_eq!(ann.get(ANN_DIGEST).unwrap(), &layer_digest);

        let manifest_ann = artifact.manifest.annotations().as_ref().unwrap();
        assert_eq!(manifest_ann.get(ANN_ALGORITHM).unwrap(), "sha512-12");
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let d_manifest = fake_sha512_digest(0xaa);
        let d_config = fake_sha512_digest(0xbb);
        let d_layer0 = fake_sha512_digest(0xcc);
        let d_layer1 = fake_sha512_digest(0xdd);
        let d_merged = fake_sha512_digest(0xee);

        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: d_manifest.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Config,
                digest: d_config.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer0.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer1.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: d_merged.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();
        let parsed = parse_signature_artifact(&artifact.manifest).unwrap();

        assert_eq!(parsed.algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert_eq!(parsed.entries.len(), 5);
        assert_eq!(parsed.entries[0].sig_type, SignatureType::Manifest);
        assert_eq!(parsed.entries[0].digest, d_manifest);
        assert_eq!(parsed.entries[1].sig_type, SignatureType::Config);
        assert_eq!(parsed.entries[1].digest, d_config);
        assert_eq!(parsed.entries[2].sig_type, SignatureType::Layer);
        assert_eq!(parsed.entries[2].digest, d_layer0);
        assert_eq!(parsed.entries[3].sig_type, SignatureType::Layer);
        assert_eq!(parsed.entries[3].digest, d_layer1);
        assert_eq!(parsed.entries[4].sig_type, SignatureType::Merged);
        assert_eq!(parsed.entries[4].digest, d_merged);

        // Subject should be preserved
        assert_eq!(parsed.subject.media_type(), &MediaType::ImageManifest);
    }

    #[test]
    fn test_build_with_signature_blobs() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let d_manifest = fake_sha512_digest(0x11);
        let d_layer = fake_sha512_digest(0x22);
        let d_merged = fake_sha512_digest(0x33);

        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: d_manifest.clone(),
                signature: None,
            })
            .unwrap();

        let fake_sig = vec![0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD, 0xEF];
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer.clone(),
                signature: Some(fake_sig.clone()),
            })
            .unwrap();

        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: d_merged.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        assert_eq!(artifact.blobs.len(), 3);
        assert!(artifact.blobs[0].is_empty());
        assert_eq!(artifact.blobs[1], fake_sig);
        assert!(artifact.blobs[2].is_empty());

        let layers = artifact.manifest.layers();
        assert_eq!(layers[0].size(), 0);
        assert_eq!(layers[1].size(), fake_sig.len() as u64);
        assert_eq!(layers[2].size(), 0);

        for layer in layers {
            assert_eq!(
                layer.media_type(),
                &MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string())
            );
        }

        let parsed = parse_signature_artifact(&artifact.manifest).unwrap();
        assert_eq!(parsed.entries[0].digest, d_manifest);
        assert_eq!(parsed.entries[1].digest, d_layer);
        assert_eq!(parsed.entries[2].digest, d_merged);
    }

    #[test]
    fn test_parse_error_missing_annotations() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x44),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        let mut manifest = artifact.manifest.clone();
        manifest.set_annotations(None);

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing annotations"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_parse_error_unknown_signature_type() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x55),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        let mut manifest = artifact.manifest.clone();
        let layer = &mut manifest.layers_mut()[0];
        let mut ann = layer.annotations().clone().unwrap();
        ann.insert(ANN_SIGNATURE_TYPE.to_string(), "unknown_type".to_string());
        layer.set_annotations(Some(ann));

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unknown signature type"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        let d_manifest = fake_sha512_digest(0x66);
        let d_layer = fake_sha512_digest(0x77);

        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: d_manifest.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: d_layer.clone(),
                signature: Some(vec![1, 2, 3]),
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        let json = artifact
            .manifest
            .to_string()
            .expect("manifest serialization");

        let parsed_manifest =
            ImageManifest::from_reader(json.as_bytes()).expect("manifest deserialization");

        let parsed = parse_signature_artifact(&parsed_manifest).unwrap();
        assert_eq!(parsed.algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].sig_type, SignatureType::Manifest);
        assert_eq!(parsed.entries[0].digest, d_manifest);
        assert_eq!(parsed.entries[1].sig_type, SignatureType::Layer);
        assert_eq!(parsed.entries[1].digest, d_layer);
    }

    #[test]
    fn test_empty_config_digest_correctness() {
        let computed = sha256_digest(b"{}");
        assert_eq!(
            computed, EMPTY_CONFIG_DIGEST,
            "EMPTY_CONFIG_DIGEST doesn't match sha256 of '{{}}'"
        );
    }

    #[test]
    fn test_subject_preserved() {
        let subject = sample_subject();
        let expected_digest = subject.digest().clone();
        let expected_media_type = subject.media_type().clone();

        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x88),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        let json = artifact
            .manifest
            .to_string()
            .expect("manifest serialization");
        let parsed_manifest =
            ImageManifest::from_reader(json.as_bytes()).expect("manifest deserialization");

        let parsed = parse_signature_artifact(&parsed_manifest).unwrap();
        assert_eq!(parsed.subject.digest(), &expected_digest);
        assert_eq!(parsed.subject.media_type(), &expected_media_type);
    }

    // --- Validation tests ---

    #[test]
    fn test_parse_rejects_wrong_artifact_type() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0xab),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        let mut manifest = artifact.manifest.clone();
        manifest.set_artifact_type(Some(MediaType::Other("wrong/type".to_string())));

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("wrong artifact type"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_parse_rejects_bad_digest_hex() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0xab),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        let mut manifest = artifact.manifest.clone();
        let layer = &mut manifest.layers_mut()[0];
        let mut ann = layer.annotations().clone().unwrap();
        ann.insert(ANN_DIGEST.to_string(), "not-valid-hex!@#$".to_string());
        layer.set_annotations(Some(ann));

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not valid hex"), "unexpected error: {msg}");
    }

    #[test]
    fn test_parse_rejects_wrong_digest_length() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0xab),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        // Use a 32-byte (SHA-256 length) hex for a SHA-512 artifact
        let mut manifest = artifact.manifest.clone();
        let layer = &mut manifest.layers_mut()[0];
        let mut ann = layer.annotations().clone().unwrap();
        ann.insert(ANN_DIGEST.to_string(), fake_sha256_digest(0xcd));
        layer.set_annotations(Some(ann));

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("expected 64 bytes") && msg.contains("got 32"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_parse_rejects_out_of_order() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x01),
                signature: None,
            })
            .unwrap();
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: fake_sha512_digest(0x02),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        // Swap the layer annotations so merged comes before layer
        let mut manifest = artifact.manifest.clone();
        let layers = manifest.layers_mut();
        let ann0 = layers[0].annotations().clone().unwrap();
        let ann1 = layers[1].annotations().clone().unwrap();
        layers[0].set_annotations(Some(ann1));
        layers[1].set_annotations(Some(ann0));

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("out-of-order"), "unexpected error: {msg}");
    }

    #[test]
    fn test_parse_requires_subject() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0xab),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        let mut manifest = artifact.manifest.clone();
        manifest.set_subject(None);

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing subject"), "unexpected error: {msg}");
    }

    #[test]
    fn test_builder_rejects_out_of_order() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x01),
                signature: None,
            })
            .unwrap();

        let err = builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: fake_sha512_digest(0x02),
                signature: None,
            })
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("out-of-order"), "unexpected error: {msg}");
    }

    #[test]
    fn test_builder_rejects_duplicate_manifest() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: fake_sha512_digest(0x01),
                signature: None,
            })
            .unwrap();

        let err = builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Manifest,
                digest: fake_sha512_digest(0x02),
                signature: None,
            })
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("duplicate"), "unexpected error: {msg}");
    }

    #[test]
    fn test_parse_rejects_wrong_layer_media_type() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0xab),
                signature: None,
            })
            .unwrap();
        let artifact = builder.build().unwrap();

        // Tamper via JSON roundtrip to change the layer media type
        let json = artifact.manifest.to_string().unwrap();
        let tampered = json.replace(SIGNATURE_MEDIA_TYPE, "application/octet-stream");
        let manifest = ImageManifest::from_reader(tampered.as_bytes()).unwrap();

        let err = parse_signature_artifact(&manifest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("wrong layer media type"),
            "unexpected error: {msg}"
        );
    }

    // ==================== Repository Integration Tests ====================

    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;

    /// Helper to create a minimal subject image in a test repository.
    /// Returns (manifest_digest, manifest_verity).
    fn create_subject_image(
        repo: &std::sync::Arc<Repository<Sha256HashValue>>,
    ) -> (String, Sha256HashValue) {
        use containers_image_proxy::oci_spec::image::{
            ConfigBuilder, ImageConfigurationBuilder, ImageManifestBuilder, RootFsBuilder,
        };

        let layer_data = b"fake-subject-layer";
        let layer_digest = sha256_digest(layer_data);

        let mut layer_stream = repo.create_stream(crate::skopeo::TAR_LAYER_CONTENT_TYPE);
        layer_stream.write_inline(layer_data);
        let layer_verity = repo
            .write_stream(layer_stream, &crate::layer_identifier(&layer_digest), None)
            .unwrap();

        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec![layer_digest.clone()])
            .build()
            .unwrap();
        let cfg = ConfigBuilder::default().build().unwrap();
        let config = ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(rootfs)
            .config(cfg)
            .build()
            .unwrap();

        let config_json = config.to_string().unwrap();
        let config_digest = sha256_digest(config_json.as_bytes());

        let mut config_stream = repo.create_stream(crate::skopeo::OCI_CONFIG_CONTENT_TYPE);
        config_stream.add_named_stream_ref(&layer_digest, &layer_verity);
        config_stream.write_inline(config_json.as_bytes());
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(OciDigest::from_str(&config_digest).unwrap())
            .size(config_json.len() as u64)
            .build()
            .unwrap();
        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayerGzip)
            .digest(OciDigest::from_str(&layer_digest).unwrap())
            .size(layer_data.len() as u64)
            .build()
            .unwrap();

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        let mut layer_verities = std::collections::HashMap::new();
        layer_verities.insert(layer_digest.into_boxed_str(), layer_verity);

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = sha256_digest(manifest_json.as_bytes());

        let (digest, verity) = crate::oci_image::write_manifest(
            repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            Some("subject:v1"),
        )
        .unwrap();

        (digest, verity)
    }

    #[test]
    fn test_store_and_find_signature_artifact() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a subject image
        let (subject_digest, _subject_verity) = create_subject_image(repo);

        // Build a signature artifact referencing the subject
        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(OciDigest::from_str(&subject_digest).unwrap())
            .size(100u64)
            .build()
            .unwrap();

        let layer_digest = fake_sha512_digest(0xab);
        let merged_digest = fake_sha512_digest(0xcd);

        let mut builder = SignatureArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA512_12,
            subject_descriptor,
        );
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: layer_digest.clone(),
                signature: None,
            })
            .unwrap();
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Merged,
                digest: merged_digest.clone(),
                signature: None,
            })
            .unwrap();

        let artifact = builder.build().unwrap();

        // Store it
        let (artifact_digest, _artifact_verity) = store_signature_artifact(repo, artifact).unwrap();

        // Verify the manifest was stored
        assert!(crate::oci_image::has_manifest(repo, &artifact_digest)
            .unwrap()
            .is_some());

        // Find it by subject
        let found = find_signature_artifacts(repo, &subject_digest).unwrap();
        assert_eq!(found.len(), 1);

        let parsed = &found[0];
        assert_eq!(parsed.algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].sig_type, SignatureType::Layer);
        assert_eq!(parsed.entries[0].digest, layer_digest);
        assert_eq!(parsed.entries[1].sig_type, SignatureType::Merged);
        assert_eq!(parsed.entries[1].digest, merged_digest);

        // Subject descriptor should be preserved
        assert_eq!(parsed.subject.digest().to_string(), subject_digest);

        // Querying a different subject should return empty
        let other = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let found = find_signature_artifacts(repo, other).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn test_store_multiple_signature_artifacts() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (subject_digest, _) = create_subject_image(repo);

        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(OciDigest::from_str(&subject_digest).unwrap())
            .size(100u64)
            .build()
            .unwrap();

        // Store two signature artifacts for the same subject
        for seed in [0xaau8, 0xbbu8] {
            let mut builder = SignatureArtifactBuilder::new(
                composefs::fsverity::algorithm::SHA512_12,
                subject_descriptor.clone(),
            );
            builder
                .add_entry(SignatureEntry {
                    sig_type: SignatureType::Layer,
                    digest: fake_sha512_digest(seed),
                    signature: None,
                })
                .unwrap();
            let artifact = builder.build().unwrap();
            store_signature_artifact(repo, artifact).unwrap();
        }

        let found = find_signature_artifacts(repo, &subject_digest).unwrap();
        assert_eq!(found.len(), 2);

        let digests: Vec<&str> = found.iter().map(|p| p.entries[0].digest.as_str()).collect();
        assert!(digests.contains(&fake_sha512_digest(0xaa).as_str()));
        assert!(digests.contains(&fake_sha512_digest(0xbb).as_str()));
    }

    #[test]
    fn test_store_signature_with_blobs() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (subject_digest, _) = create_subject_image(repo);

        let subject_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(OciDigest::from_str(&subject_digest).unwrap())
            .size(100u64)
            .build()
            .unwrap();

        let fake_sig = vec![0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD, 0xEF];
        let mut builder = SignatureArtifactBuilder::new(
            composefs::fsverity::algorithm::SHA512_12,
            subject_descriptor,
        );
        builder
            .add_entry(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: fake_sha512_digest(0x11),
                signature: Some(fake_sig.clone()),
            })
            .unwrap();

        let artifact = builder.build().unwrap();
        let (artifact_digest, _) = store_signature_artifact(repo, artifact).unwrap();

        // Find it and verify the parsed result
        let found = find_signature_artifacts(repo, &subject_digest).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entries[0].sig_type, SignatureType::Layer);
        assert_eq!(found[0].entries[0].digest, fake_sha512_digest(0x11));

        // Verify we can open the artifact as an OciImage and read the blob
        let image = crate::oci_image::OciImage::open(repo, &artifact_digest, None).unwrap();
        assert!(!image.is_container_image());

        // The layer blob should be retrievable
        let layer_desc = &image.layer_descriptors()[0];
        let blob_digest = layer_desc.digest().to_string();
        let blob_verity = image.layer_verity(&blob_digest).unwrap();
        let blob_data = crate::oci_image::open_blob(repo, &blob_digest, Some(blob_verity)).unwrap();
        assert_eq!(blob_data, fake_sig);
    }
}
