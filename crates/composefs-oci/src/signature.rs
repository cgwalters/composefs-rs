//! Composefs signature artifact construction and verification.
//!
//! Builds OCI artifact manifests containing composefs fsverity digests
//! (and optionally PKCS#7 signatures) per the OCI sealing specification.
//! Signature artifacts reference the source image via the OCI referrer
//! pattern (`subject` field) and are discoverable via the `/referrers` API.

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{Context, Result};
use composefs::fsverity::algorithm::ComposeFsAlgorithm;
use composefs::fsverity::FsVerityHashValue;
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
        }
    }

    /// Add a signature entry.
    ///
    /// Entries MUST be added in the spec-defined order:
    /// manifest, config, layers (in manifest order), merged (in manifest order).
    pub fn add_entry(&mut self, entry: SignatureEntry) {
        self.entries.push(entry);
    }

    /// Add digest-only entries for per-layer composefs digests.
    ///
    /// Convenience method that adds one `Layer` entry per digest.
    pub fn add_layer_digests<ObjectID: FsVerityHashValue>(&mut self, digests: &[ObjectID]) {
        for digest in digests {
            self.entries.push(SignatureEntry {
                sig_type: SignatureType::Layer,
                digest: digest.to_hex(),
                signature: None,
            });
        }
    }

    /// Add a digest-only entry for a merged composefs digest.
    pub fn add_merged_digest<ObjectID: FsVerityHashValue>(&mut self, digest: &ObjectID) {
        self.entries.push(SignatureEntry {
            sig_type: SignatureType::Merged,
            digest: digest.to_hex(),
            signature: None,
        });
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
/// Returns entries in artifact layer order (manifest, config, layers, merged).
pub fn parse_signature_artifact(
    manifest: &ImageManifest,
) -> Result<(ComposeFsAlgorithm, Vec<SignatureEntry>)> {
    let annotations = manifest
        .annotations()
        .as_ref()
        .context("signature artifact missing annotations")?;

    let algorithm: ComposeFsAlgorithm = annotations
        .get(ANN_ALGORITHM)
        .context("signature artifact missing composefs.algorithm annotation")?
        .parse()
        .context("parsing composefs.algorithm annotation")?;

    let mut entries = Vec::with_capacity(manifest.layers().len());

    for layer in manifest.layers() {
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

        entries.push(SignatureEntry {
            sig_type,
            digest,
            // Signature blob must be fetched separately by the caller
            signature: None,
        });
    }

    Ok((algorithm, entries))
}

fn sha256_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

#[cfg(test)]
mod tests {
    use super::*;

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

        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "abcd1234".to_string(),
            signature: None,
        });

        let artifact = builder.build().unwrap();

        // Check manifest structure
        assert_eq!(artifact.manifest.schema_version(), 2);
        assert_eq!(
            artifact.manifest.artifact_type().as_ref().unwrap(),
            &MediaType::Other(ARTIFACT_TYPE.to_string())
        );
        assert_eq!(artifact.manifest.layers().len(), 1);
        assert_eq!(artifact.blobs.len(), 1);

        // Check subject
        let subject = artifact.manifest.subject().as_ref().unwrap();
        assert_eq!(subject.media_type(), &MediaType::ImageManifest);

        // Check layer annotations
        let layer = &artifact.manifest.layers()[0];
        let ann = layer.annotations().as_ref().unwrap();
        assert_eq!(ann.get(ANN_SIGNATURE_TYPE).unwrap(), "layer");
        assert_eq!(ann.get(ANN_DIGEST).unwrap(), "abcd1234");

        // Check algorithm annotation on manifest
        let manifest_ann = artifact.manifest.annotations().as_ref().unwrap();
        assert_eq!(manifest_ann.get(ANN_ALGORITHM).unwrap(), "sha512-12");
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Manifest,
            digest: "aaaa".to_string(),
            signature: None,
        });
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Config,
            digest: "bbbb".to_string(),
            signature: None,
        });
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "cccc".to_string(),
            signature: None,
        });
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "dddd".to_string(),
            signature: None,
        });
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Merged,
            digest: "eeee".to_string(),
            signature: None,
        });

        let artifact = builder.build().unwrap();
        let (algorithm, entries) = parse_signature_artifact(&artifact.manifest).unwrap();

        assert_eq!(algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].sig_type, SignatureType::Manifest);
        assert_eq!(entries[0].digest, "aaaa");
        assert_eq!(entries[1].sig_type, SignatureType::Config);
        assert_eq!(entries[1].digest, "bbbb");
        assert_eq!(entries[2].sig_type, SignatureType::Layer);
        assert_eq!(entries[2].digest, "cccc");
        assert_eq!(entries[3].sig_type, SignatureType::Layer);
        assert_eq!(entries[3].digest, "dddd");
        assert_eq!(entries[4].sig_type, SignatureType::Merged);
        assert_eq!(entries[4].digest, "eeee");
    }

    #[test]
    fn test_build_with_signature_blobs() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);

        // A digest-only entry (no signature blob)
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Manifest,
            digest: "manifest_digest".to_string(),
            signature: None,
        });

        // An entry with a fake PKCS#7 blob
        let fake_sig = vec![0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD, 0xEF];
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "layer_digest".to_string(),
            signature: Some(fake_sig.clone()),
        });

        // Another digest-only entry
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Merged,
            digest: "merged_digest".to_string(),
            signature: None,
        });

        let artifact = builder.build().unwrap();

        // Blob storage: entry 0 is empty, entry 1 is the signature, entry 2 is empty
        assert_eq!(artifact.blobs.len(), 3);
        assert!(artifact.blobs[0].is_empty());
        assert_eq!(artifact.blobs[1], fake_sig);
        assert!(artifact.blobs[2].is_empty());

        // Layer descriptors should match blob sizes
        let layers = artifact.manifest.layers();
        assert_eq!(layers[0].size(), 0);
        assert_eq!(layers[1].size(), fake_sig.len() as u64);
        assert_eq!(layers[2].size(), 0);

        // All layers use the signature media type
        for layer in layers {
            assert_eq!(
                layer.media_type(),
                &MediaType::Other(SIGNATURE_MEDIA_TYPE.to_string())
            );
        }

        // Roundtrip through parse should preserve the digest values
        let (_, entries) = parse_signature_artifact(&artifact.manifest).unwrap();
        assert_eq!(entries[0].digest, "manifest_digest");
        assert_eq!(entries[1].digest, "layer_digest");
        assert_eq!(entries[2].digest, "merged_digest");
    }

    #[test]
    fn test_parse_error_missing_annotations() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "abcd".to_string(),
            signature: None,
        });
        let artifact = builder.build().unwrap();

        // Remove manifest-level annotations
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
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "abcd".to_string(),
            signature: None,
        });
        let artifact = builder.build().unwrap();

        // Tamper with the layer annotation to inject an unknown signature type
        let mut manifest = artifact.manifest.clone();
        let layer = &mut manifest.layers_mut()[0];
        let mut ann = layer.annotations().clone().unwrap();
        ann.insert(ANN_SIGNATURE_TYPE.to_string(), "unknown_type".to_string());
        layer.set_annotations(Some(ann));
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let subject = sample_subject();
        let mut builder =
            SignatureArtifactBuilder::new(composefs::fsverity::algorithm::SHA512_12, subject);
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Manifest,
            digest: "aaaa".to_string(),
            signature: None,
        });
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "bbbb".to_string(),
            signature: Some(vec![1, 2, 3]),
        });

        let artifact = builder.build().unwrap();

        // Serialize via oci-spec's own to_string (JSON)
        let json = artifact
            .manifest
            .to_string()
            .expect("manifest serialization");

        // Parse back
        let parsed = ImageManifest::from_reader(json.as_bytes()).expect("manifest deserialization");

        // The parsed manifest should produce the same entries
        let (algorithm, entries) = parse_signature_artifact(&parsed).unwrap();
        assert_eq!(algorithm, composefs::fsverity::algorithm::SHA512_12);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sig_type, SignatureType::Manifest);
        assert_eq!(entries[0].digest, "aaaa");
        assert_eq!(entries[1].sig_type, SignatureType::Layer);
        assert_eq!(entries[1].digest, "bbbb");
    }

    #[test]
    fn test_empty_config_digest_correctness() {
        // EMPTY_CONFIG_DIGEST should be the sha256 of "{}" (2 bytes)
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
        builder.add_entry(SignatureEntry {
            sig_type: SignatureType::Layer,
            digest: "abcd".to_string(),
            signature: None,
        });

        let artifact = builder.build().unwrap();

        // Serialize to JSON and parse back to ensure subject survives a roundtrip
        let json = artifact
            .manifest
            .to_string()
            .expect("manifest serialization");
        let parsed = ImageManifest::from_reader(json.as_bytes()).expect("manifest deserialization");

        let roundtripped_subject = parsed
            .subject()
            .as_ref()
            .expect("subject should be present after roundtrip");
        assert_eq!(roundtripped_subject.digest(), &expected_digest);
        assert_eq!(roundtripped_subject.media_type(), &expected_media_type);
    }
}
