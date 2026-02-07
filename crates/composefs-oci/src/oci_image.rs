//! OCI image and artifact storage for composefs.
//!
//! This module provides native OCI storage in composefs repositories. The key insight
//! is that OCI is a simple, extensible format that can represent any content - not just
//! container images. By standardizing on OCI, we get:
//!
//! - A well-defined manifest format with content-addressed blobs
//! - Built-in support for signatures (cosign, notation)
//! - Existing tooling (skopeo, crane, oras)
//! - A clear GC model: manifests are roots, everything else is garbage-collectable
//!
//! # Storage Model
//!
//! ```text
//! streams/
//!   oci-manifest-sha256:abc...  -> objects/XX/YYY  (manifest splitstream)
//!   oci-config-sha256:def...    -> objects/XX/YYY  (config splitstream)  
//!   oci-layer-sha256:ghi...     -> objects/XX/YYY  (layer splitstream)
//!   refs/
//!     oci/
//!       myimage:latest          -> ../../oci-manifest-sha256:abc...  (GC root!)
//!       myimage:v1.0            -> ../../oci-manifest-sha256:xyz...
//! ```
//!
//! Named references under `refs/oci/` act as GC roots. Manifests without references
//! will be garbage collected along with their unreferenced configs and layers.
//!
//! # Container Images vs Artifacts
//!
//! Container images have:
//! - Config with `application/vnd.oci.image.config.v1+json` mediaType
//! - Layers that are tar archives (gzip, zstd, or uncompressed)
//!
//! Artifacts can have:
//! - Any config mediaType (or empty config)
//! - Any blob types as "layers"
//!
//! This module handles both transparently. Use `is_container_image()` to check.

use std::{collections::HashMap, io::Read, sync::Arc};

use anyhow::{ensure, Context, Result};
use containers_image_proxy::oci_spec::image::{
    Descriptor, ImageConfiguration, ImageManifest, MediaType,
};
use rustix::fs::{openat, readlinkat, unlinkat, AtFlags, Dir, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use composefs::{fsverity::FsVerityHashValue, repository::Repository};

use crate::skopeo::{OCI_BLOB_CONTENT_TYPE, OCI_CONFIG_CONTENT_TYPE, OCI_MANIFEST_CONTENT_TYPE};

/// Prefix for OCI image references in the repository.
pub const OCI_REF_PREFIX: &str = "oci/";

/// An OCI image or artifact stored in a composefs repository.
///
/// This type provides access to the complete OCI structure including
/// manifest, config, and layer/blob references. All metadata is stored
/// locally, eliminating network access for queries.
#[derive(Debug)]
pub struct OciImage<ObjectID: FsVerityHashValue> {
    /// The manifest digest (sha256 content hash)
    manifest_digest: String,
    /// The parsed OCI manifest
    manifest: ImageManifest,
    /// The config digest (sha256 content hash)
    config_digest: String,
    /// The parsed OCI config (may be empty for artifacts)
    config: Option<ImageConfiguration>,
    /// Map from layer diff_id to its fs-verity object ID
    layer_refs: HashMap<Box<str>, ObjectID>,
    /// The fs-verity ID of the manifest splitstream
    manifest_verity: ObjectID,
}

impl<ObjectID: FsVerityHashValue> OciImage<ObjectID> {
    /// Opens an OCI image by its manifest digest.
    ///
    /// If `verity` is provided, it's used directly for fast lookup.
    /// Otherwise, the content is verified against the digest.
    pub fn open(
        repo: &Repository<ObjectID>,
        manifest_digest: &str,
        verity: Option<&ObjectID>,
    ) -> Result<Self> {
        let manifest_id = manifest_identifier(manifest_digest);
        let mut stream = repo.open_stream(&manifest_id, verity, Some(OCI_MANIFEST_CONTENT_TYPE))?;

        // Read and parse the manifest
        let manifest = if verity.is_none() {
            let mut data = vec![];
            stream.read_to_end(&mut data)?;
            let computed = hash(&data);
            ensure!(
                manifest_digest == computed,
                "Manifest integrity failed: expected {manifest_digest}, got {computed}"
            );
            ImageManifest::from_reader(&data[..])?
        } else {
            ImageManifest::from_reader(&mut stream)?
        };

        let named_refs = stream.into_named_refs();

        // Get the config digest and verity from named refs
        let config_digest = manifest.config().digest().to_string();
        let config_key = format!("config:{config_digest}");
        let config_verity = named_refs
            .get(config_key.as_str())
            .context("Manifest missing config reference")?;

        // Open and parse the config (may fail for some artifacts)
        let config_id = crate::config_identifier(&config_digest);
        let config_stream = repo.open_stream(
            &config_id,
            Some(config_verity),
            Some(OCI_CONFIG_CONTENT_TYPE),
        )?;

        // Try to parse as ImageConfiguration, but don't fail for artifacts
        let (config, layer_refs) = match manifest.config().media_type() {
            MediaType::ImageConfig => {
                let mut stream = config_stream;
                let config = ImageConfiguration::from_reader(&mut stream)?;
                // For container images, layer refs are in the config stream
                let refs = stream.into_named_refs();
                (Some(config), refs)
            }
            _ => {
                // Artifact - layer refs are in the manifest's named refs
                // (the config stream has no named refs for artifacts)
                let mut refs = named_refs.clone();
                refs.remove(config_key.as_str());
                (None, refs)
            }
        };

        // Get manifest verity
        let manifest_verity = if let Some(v) = verity {
            v.clone()
        } else {
            repo.has_stream(&manifest_id)?
                .context("Manifest not found")?
        };

        Ok(Self {
            manifest_digest: manifest_digest.to_string(),
            manifest,
            config_digest,
            config,
            layer_refs,
            manifest_verity,
        })
    }

    /// Opens an OCI image by its tag/reference name.
    pub fn open_ref(repo: &Repository<ObjectID>, name: &str) -> Result<Self> {
        let (manifest_digest, verity) = resolve_ref(repo, name)?;
        Self::open(repo, &manifest_digest, Some(&verity))
    }

    /// Returns true if this is a container image (vs an artifact).
    pub fn is_container_image(&self) -> bool {
        matches!(self.manifest.config().media_type(), MediaType::ImageConfig)
    }

    /// Returns the manifest digest.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Returns the manifest fs-verity hash.
    pub fn manifest_verity(&self) -> &ObjectID {
        &self.manifest_verity
    }

    /// Returns the OCI manifest.
    pub fn manifest(&self) -> &ImageManifest {
        &self.manifest
    }

    /// Returns the config digest.
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Returns the OCI config, if this is a container image.
    pub fn config(&self) -> Option<&ImageConfiguration> {
        self.config.as_ref()
    }

    /// Returns the image architecture (empty string for artifacts).
    pub fn architecture(&self) -> String {
        self.config
            .as_ref()
            .map(|c| c.architecture().to_string())
            .unwrap_or_default()
    }

    /// Returns the image OS (empty string for artifacts).
    pub fn os(&self) -> String {
        self.config
            .as_ref()
            .map(|c| c.os().to_string())
            .unwrap_or_default()
    }

    /// Returns the creation timestamp.
    pub fn created(&self) -> Option<&str> {
        self.config.as_ref().and_then(|c| c.created().as_deref())
    }

    /// Returns the composefs seal digest, if sealed.
    pub fn seal_digest(&self) -> Option<&str> {
        self.config
            .as_ref()
            .and_then(|c| c.get_config_annotation("containers.composefs.fsverity"))
    }

    /// Returns whether this image has been sealed.
    pub fn is_sealed(&self) -> bool {
        self.seal_digest().is_some()
    }

    /// Opens an artifact layer's backing object by index, returning a
    /// read-only file descriptor to the raw blob data.
    ///
    /// This only works for non-tar layers (OCI artifacts). Returns an
    /// error for tar layers — use the splitstream API for those.
    pub fn open_layer_fd(
        &self,
        repo: &Repository<ObjectID>,
        index: usize,
    ) -> Result<rustix::fd::OwnedFd> {
        let descriptor = self
            .manifest
            .layers()
            .get(index)
            .with_context(|| format!("Layer index {index} out of range"))?;

        ensure!(
            !is_tar_media_type(descriptor.media_type()),
            "open_layer_fd does not support tar layers (media type: {}); \
             use the splitstream API instead",
            descriptor.media_type()
        );

        let diff_id: &str = descriptor.digest().as_ref();
        let layer_verity = self
            .layer_verity(diff_id)
            .with_context(|| format!("No verity for layer {diff_id}"))?;

        let content_id = crate::layer_identifier(diff_id);
        let mut stream = repo.open_stream(&content_id, Some(layer_verity), None)?;

        // Artifact layers are stored as a single object; the splitstream
        // exists only for GC tracking.
        let mut object_refs = vec![];
        stream.get_object_refs(|id| object_refs.push(id.clone()))?;
        ensure!(
            object_refs.len() == 1,
            "Expected exactly 1 external ref for artifact layer, got {}",
            object_refs.len()
        );
        repo.open_object(&object_refs[0])
    }

    /// Returns the layer diff_ids (for container images).
    pub fn layer_diff_ids(&self) -> Vec<&str> {
        self.config
            .as_ref()
            .map(|c| c.rootfs().diff_ids().iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Returns the fs-verity ID for a layer.
    pub fn layer_verity(&self, diff_id: &str) -> Option<&ObjectID> {
        self.layer_refs.get(diff_id)
    }

    /// Returns layer descriptors from the manifest.
    pub fn layer_descriptors(&self) -> &[Descriptor] {
        self.manifest.layers()
    }

    /// Returns a label from the config.
    pub fn label(&self, key: &str) -> Option<&str> {
        self.config.as_ref().and_then(|c| {
            c.config()
                .as_ref()
                .and_then(|cfg| cfg.labels().as_ref())
                .and_then(|labels| labels.get(key).map(|s| s.as_str()))
        })
    }

    /// Returns all labels from the config.
    pub fn labels(&self) -> Option<&HashMap<String, String>> {
        self.config
            .as_ref()
            .and_then(|c| c.config().as_ref())
            .and_then(|cfg| cfg.labels().as_ref())
    }
}

// =============================================================================
// Reference Management (GC Roots)
// =============================================================================

/// Tags an image with a name, making it a GC root.
///
/// The name should be in the format `image:tag` or just `image` (implies `:latest`).
pub fn tag_image<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    manifest_digest: &str,
    name: &str,
) -> Result<()> {
    let manifest_id = manifest_identifier(manifest_digest);
    let ref_name = oci_ref_path(name);
    repo.name_stream(&manifest_id, &ref_name)
}

/// Removes a tag from an image.
///
/// The image data is not deleted; it becomes eligible for garbage collection
/// if no other references point to it.
pub fn untag_image<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
) -> Result<()> {
    let ref_path = format!("streams/refs/{}", oci_ref_path(name));
    unlinkat(repo.repo_fd(), &ref_path, AtFlags::empty())
        .with_context(|| format!("Failed to remove tag {name}"))?;
    Ok(())
}

/// Resolves a reference name to (manifest_digest, verity).
pub fn resolve_ref<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    name: &str,
) -> Result<(String, ObjectID)> {
    let ref_path = format!("streams/refs/{}", oci_ref_path(name));

    // Read the symlink to get the manifest path
    let target = readlinkat(repo.repo_fd(), &ref_path, vec![])
        .with_context(|| format!("Reference {name} not found"))?;

    let target_str = target
        .to_str()
        .context("Invalid UTF-8 in reference target")?;

    // Extract manifest digest from path like "../../oci-manifest-sha256:abc"
    let manifest_part = target_str
        .rsplit('/')
        .next()
        .context("Invalid reference target")?;

    let digest = manifest_part
        .strip_prefix("oci-manifest-")
        .with_context(|| format!("Invalid manifest reference: {manifest_part}"))?;

    // Get the verity by looking up the manifest
    let verity = repo
        .has_stream(&manifest_identifier(digest))?
        .with_context(|| format!("Manifest {digest} not found"))?;

    Ok((digest.to_string(), verity))
}

/// Lists all tagged OCI images.
///
/// Returns (name, manifest_digest) pairs for each tag.
pub fn list_refs<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
) -> Result<Vec<(String, String)>> {
    let mut refs = Vec::new();

    // Use the repository's ref listing method
    for (name, target) in repo.list_stream_refs("oci")? {
        // Extract manifest digest from target path
        let manifest_part = target.rsplit('/').next().unwrap_or(&target);
        if let Some(digest) = manifest_part.strip_prefix("oci-manifest-") {
            // Decode the tag name from filesystem-safe encoding
            refs.push((decode_tag(&name), digest.to_string()));
        }
    }

    Ok(refs)
}

/// Summary information about a stored OCI image.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// The tag/name of the image
    pub name: String,
    /// The manifest digest
    pub manifest_digest: String,
    /// Whether this is a container image (vs artifact)
    pub is_container: bool,
    /// Architecture (empty for artifacts)
    pub architecture: String,
    /// OS (empty for artifacts)
    pub os: String,
    /// Creation timestamp
    pub created: Option<String>,
    /// Whether sealed with composefs
    pub sealed: bool,
    /// Number of layers/blobs
    pub layer_count: usize,
}

/// Lists all tagged images with their metadata.
pub fn list_images<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
) -> Result<Vec<ImageInfo>> {
    let mut images = Vec::new();

    for (name, digest) in list_refs(repo)? {
        match OciImage::open(repo, &digest, None) {
            Ok(img) => {
                images.push(ImageInfo {
                    name,
                    manifest_digest: digest,
                    is_container: img.is_container_image(),
                    architecture: img.architecture(),
                    os: img.os(),
                    created: img.created().map(String::from),
                    sealed: img.is_sealed(),
                    layer_count: img.layer_descriptors().len(),
                });
            }
            Err(_) => {
                continue;
            }
        }
    }

    Ok(images)
}

// =============================================================================
// Manifest Storage
// =============================================================================

/// Writes a manifest to the repository.
///
/// The manifest becomes a GC root only if a `reference` name is provided.
pub fn write_manifest<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    manifest: &ImageManifest,
    manifest_digest: &str,
    config_verity: &ObjectID,
    layer_verities: &HashMap<Box<str>, ObjectID>,
    reference: Option<&str>,
) -> Result<(String, ObjectID)> {
    let content_id = manifest_identifier(manifest_digest);

    if let Some(verity) = repo.has_stream(&content_id)? {
        // Already exists - just add the reference if requested
        if let Some(name) = reference {
            tag_image(repo, manifest_digest, name)?;
        }
        return Ok((manifest_digest.to_string(), verity));
    }

    let json = manifest.to_string()?;
    let json_bytes = json.as_bytes();

    let computed = hash(json_bytes);
    ensure!(
        manifest_digest == computed,
        "Manifest digest mismatch: expected {manifest_digest}, got {computed}"
    );

    let mut stream = repo.create_stream(OCI_MANIFEST_CONTENT_TYPE);

    // Reference to config
    let config_key = format!("config:{}", manifest.config().digest());
    stream.add_named_stream_ref(&config_key, config_verity);

    // References to layers
    for (diff_id, verity) in layer_verities {
        stream.add_named_stream_ref(diff_id, verity);
    }

    stream.write_inline(json_bytes);

    // Write with OCI reference if provided
    let oci_ref = reference.map(oci_ref_path);
    let id = repo.write_stream(stream, &content_id, oci_ref.as_deref())?;

    Ok((manifest_digest.to_string(), id))
}

/// Checks if a manifest exists.
pub fn has_manifest<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    manifest_digest: &str,
) -> Result<Option<ObjectID>> {
    repo.has_stream(&manifest_identifier(manifest_digest))
}

/// Returns the content identifier for a manifest.
pub fn manifest_identifier(digest: &str) -> String {
    format!("oci-manifest-{digest}")
}

/// Returns true if this is a tar-based layer media type.
fn is_tar_media_type(media_type: &MediaType) -> bool {
    matches!(
        media_type,
        MediaType::ImageLayer
            | MediaType::ImageLayerGzip
            | MediaType::ImageLayerZstd
            | MediaType::ImageLayerNonDistributable
            | MediaType::ImageLayerNonDistributableGzip
            | MediaType::ImageLayerNonDistributableZstd
    )
}

/// Returns the reference path for an OCI name.
fn oci_ref_path(name: &str) -> String {
    format!("{OCI_REF_PREFIX}{}", encode_tag(name))
}

/// Encode a tag name for safe filesystem storage.
///
/// Uses percent-encoding for characters that are problematic in paths:
/// - `/` becomes `%2F`
/// - `%` becomes `%25` (must be first to avoid double-encoding)
fn encode_tag(name: &str) -> String {
    name.replace('%', "%25").replace('/', "%2F")
}

/// Decode a tag name from filesystem storage.
fn decode_tag(encoded: &str) -> String {
    encoded.replace("%2F", "/").replace("%25", "%")
}

/// Computes sha256 hash.
fn hash(bytes: &[u8]) -> String {
    let mut context = Sha256::new();
    context.update(bytes);
    format!("sha256:{}", hex::encode(context.finalize()))
}

// =============================================================================
// Arbitrary Blob Storage (for OCI Artifacts)
// =============================================================================

/// Returns the content identifier for an arbitrary blob.
pub fn blob_identifier(digest: &str) -> String {
    format!("oci-blob-{digest}")
}

/// Writes an arbitrary blob to the repository.
///
/// This is used for OCI artifacts with non-tar media types. The blob is stored
/// as-is without any tar processing.
///
/// Returns (sha256 digest, fs-verity hash).
pub fn write_blob<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    data: &[u8],
) -> Result<(String, ObjectID)> {
    let digest = hash(data);
    let content_id = blob_identifier(&digest);

    if let Some(verity) = repo.has_stream(&content_id)? {
        return Ok((digest, verity));
    }

    let mut stream = repo.create_stream(OCI_BLOB_CONTENT_TYPE);
    stream.write_inline(data);
    let verity = repo.write_stream(stream, &content_id, None)?;

    Ok((digest, verity))
}

/// Opens an arbitrary blob from the repository.
///
/// Returns the blob data. If verity is provided, it's used for fast lookup;
/// otherwise, the content hash is verified against the digest.
pub fn open_blob<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    digest: &str,
    verity: Option<&ObjectID>,
) -> Result<Vec<u8>> {
    let content_id = blob_identifier(digest);
    let mut stream = repo.open_stream(&content_id, verity, Some(OCI_BLOB_CONTENT_TYPE))?;

    let mut data = vec![];
    stream.read_to_end(&mut data)?;

    if verity.is_none() {
        let computed = hash(&data);
        ensure!(
            digest == computed,
            "Blob integrity failed: expected {digest}, got {computed}"
        );
    }

    Ok(data)
}

// =============================================================================
// Referrer Index (for OCI Artifacts with subject field)
// =============================================================================

/// Prefix for referrer index references.
const REFERRER_REF_PREFIX: &str = "oci-referrers/";

/// Records a referrer relationship: an artifact references a subject image.
///
/// Creates a symlink at `streams/refs/oci-referrers/{subject_digest}/{artifact_digest}`
/// pointing to the artifact's manifest stream. This enables discovery of all artifacts
/// that reference a given image (e.g. finding all signature artifacts for an image).
///
/// Both digests should be in the `sha256:...` format used by OCI.
pub fn add_referrer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    subject_digest: &str,
    artifact_manifest_digest: &str,
) -> Result<()> {
    let ref_name = format!(
        "{REFERRER_REF_PREFIX}{}/{}",
        encode_tag(subject_digest),
        encode_tag(artifact_manifest_digest)
    );
    let manifest_id = manifest_identifier(artifact_manifest_digest);
    repo.name_stream(&manifest_id, &ref_name)
}

/// Lists all artifacts that reference the given subject manifest digest.
///
/// Returns `(artifact_manifest_digest, artifact_manifest_verity)` pairs for
/// each artifact that declared the subject as its referrer. The digests are
/// in `sha256:...` format.
pub fn list_referrers<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    subject_digest: &str,
) -> Result<Vec<(String, ObjectID)>> {
    let prefix = format!("{REFERRER_REF_PREFIX}{}", encode_tag(subject_digest));

    let mut referrers = Vec::new();

    for (name, target) in repo.list_stream_refs(&prefix)? {
        // The name is the encoded artifact manifest digest
        let artifact_digest = decode_tag(&name);

        // Extract verity from the symlink target — it points to
        // a manifest stream path like "../../oci-manifest-sha256:abc..."
        let manifest_part = target.rsplit('/').next().unwrap_or(&target);
        if let Some(digest) = manifest_part.strip_prefix("oci-manifest-") {
            // Verify consistency: the ref name should match the target
            if digest != artifact_digest {
                continue;
            }
        }

        // Look up the verity for this manifest
        match repo.has_stream(&manifest_identifier(&artifact_digest))? {
            Some(verity) => referrers.push((artifact_digest, verity)),
            None => {
                continue;
            }
        }
    }

    Ok(referrers)
}

/// Removes a specific referrer index entry.
///
/// Idempotent — returns Ok if the entry doesn't exist.
pub fn remove_referrer<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    subject_digest: &str,
    artifact_digest: &str,
) -> Result<()> {
    let ref_path = format!(
        "streams/refs/{REFERRER_REF_PREFIX}{}/{}",
        encode_tag(subject_digest),
        encode_tag(artifact_digest)
    );
    match unlinkat(repo.repo_fd(), &ref_path, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to remove referrer {artifact_digest}")),
    }
}

/// Removes all referrer index entries for a subject.
///
/// Removes each referrer symlink and tries to remove the empty subject
/// directory afterwards. Idempotent — returns Ok if no entries exist.
pub fn remove_referrers_for_subject<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    subject_digest: &str,
) -> Result<()> {
    let referrers = list_referrers(repo, subject_digest)?;
    for (artifact_digest, _verity) in &referrers {
        remove_referrer(repo, subject_digest, artifact_digest)?;
    }
    // Try to remove the now-empty subject directory (ignore errors)
    let subject_dir = format!(
        "streams/refs/{REFERRER_REF_PREFIX}{}",
        encode_tag(subject_digest)
    );
    let _ = unlinkat(repo.repo_fd(), &subject_dir, AtFlags::REMOVEDIR);
    Ok(())
}

/// Removes referrer index entries whose subject manifest no longer exists.
///
/// When a subject image is untagged and garbage collected, its referrer
/// artifacts become orphaned — their referrer symlinks under
/// `streams/refs/oci-referrers/{subject_digest}/` still act as GC roots,
/// preventing the artifact manifests from being collected.
///
/// Call this **before** running GC to ensure orphaned referrer artifacts
/// are also eligible for collection. The typical workflow is:
///
/// ```text
/// cleanup_dangling_referrers(&repo)?;
/// repo.gc(&[])?;
/// ```
///
/// Returns the number of referrer entries removed.
pub fn cleanup_dangling_referrers<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
) -> Result<u64> {
    let referrers_path = format!("streams/refs/{REFERRER_REF_PREFIX}");

    // Open the oci-referrers directory; if it doesn't exist, there's nothing to do
    let referrers_dir = match openat(
        repo.repo_fd(),
        &*referrers_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(0),
        Err(e) => return Err(e).context("Opening oci-referrers directory")?,
    };

    let mut removed = 0u64;

    // Collect subject directory names first to avoid borrowing issues
    let mut subject_dirs = Vec::new();
    for item in Dir::read_from(&referrers_dir).context("Reading oci-referrers directory")? {
        let entry = item.context("Reading oci-referrers entry")?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(name.to_bytes()) {
            subject_dirs.push(s.to_string());
        }
    }

    for encoded_subject in &subject_dirs {
        let subject_digest = decode_tag(encoded_subject);

        // Check if the subject manifest still exists in the repository
        if has_manifest(repo, &subject_digest)?.is_some() {
            continue;
        }

        // Subject is gone — remove all referrer entries in this directory
        let subject_dir_fd = match openat(
            &referrers_dir,
            encoded_subject.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => continue,
            Err(e) => {
                return Err(e).context(format!("Opening referrer subject dir {encoded_subject}"))?
            }
        };

        for item in Dir::read_from(&subject_dir_fd).context("Reading referrer subject directory")? {
            let entry = item.context("Reading referrer entry")?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            unlinkat(&subject_dir_fd, name, AtFlags::empty())
                .with_context(|| format!("Removing referrer entry {name:?}"))?;
            removed += 1;
        }

        // Remove the now-empty subject directory
        unlinkat(&referrers_dir, encoded_subject.as_str(), AtFlags::REMOVEDIR)
            .with_context(|| format!("Removing empty referrer subject dir {encoded_subject}"))?;
    }

    Ok(removed)
}

#[cfg(test)]
mod test {
    use super::*;
    use composefs::fsverity::Sha256HashValue;
    use composefs::test::TestRepo;
    use containers_image_proxy::oci_spec::image::{
        ConfigBuilder, DescriptorBuilder, Digest as OciDigest, ImageConfigurationBuilder,
        ImageManifestBuilder, RootFsBuilder,
    };
    use std::fs::File;
    use std::io::Read;
    use std::str::FromStr;

    /// Helper to create a synthetic container image in the repository.
    ///
    /// Creates a minimal but valid container image with:
    /// - A single "layer" (stored as inline data in the config)
    /// - Proper OCI manifest and config structure
    /// - Optional tag
    ///
    /// Returns (manifest_digest, manifest_verity, config_digest).
    fn create_test_image(
        repo: &Arc<Repository<Sha256HashValue>>,
        tag: Option<&str>,
        arch: &str,
    ) -> (String, Sha256HashValue, String) {
        // Create a fake layer - in real usage this would be a tar splitstream
        // For testing the manifest/config storage, we just need valid references
        let layer_data = format!("fake-layer-{arch}").into_bytes();
        let layer_digest = hash(&layer_data);

        // Write the layer as a blob (simulating what import_layer would do)
        let mut layer_stream = repo.create_stream(crate::skopeo::TAR_LAYER_CONTENT_TYPE);
        layer_stream.write_inline(&layer_data);
        let layer_verity = repo
            .write_stream(layer_stream, &crate::layer_identifier(&layer_digest), None)
            .unwrap();

        // Create OCI config
        let rootfs = RootFsBuilder::default()
            .typ("layers")
            .diff_ids(vec![layer_digest.clone()])
            .build()
            .unwrap();

        let cfg = ConfigBuilder::default().build().unwrap();

        let config = ImageConfigurationBuilder::default()
            .architecture(arch)
            .os("linux")
            .rootfs(rootfs)
            .config(cfg)
            .build()
            .unwrap();

        // Write config with layer refs
        let config_json = config.to_string().unwrap();
        let config_digest = hash(config_json.as_bytes());

        let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
        config_stream.add_named_stream_ref(&layer_digest, &layer_verity);
        config_stream.write_inline(config_json.as_bytes());
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        // Build manifest
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

        // Write manifest
        let mut layer_verities = HashMap::new();
        layer_verities.insert(layer_digest.into_boxed_str(), layer_verity);

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = hash(manifest_json.as_bytes());

        let (_stored_digest, manifest_verity) = write_manifest(
            repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            tag,
        )
        .unwrap();

        (manifest_digest, manifest_verity, config_digest)
    }

    #[test]
    fn test_manifest_identifier() {
        assert_eq!(
            manifest_identifier("sha256:abc123"),
            "oci-manifest-sha256:abc123"
        );
    }

    #[test]
    fn test_oci_ref_path() {
        assert_eq!(oci_ref_path("myimage:latest"), "oci/myimage:latest");
        // Slashes get encoded
        assert_eq!(oci_ref_path("library/nginx"), "oci/library%2Fnginx");
        assert_eq!(oci_ref_path("docker://busybox"), "oci/docker:%2F%2Fbusybox");
    }

    #[test]
    fn test_encode_decode_tag() {
        // Simple names pass through
        assert_eq!(encode_tag("myimage:latest"), "myimage:latest");
        assert_eq!(decode_tag("myimage:latest"), "myimage:latest");

        // Slashes get encoded
        assert_eq!(encode_tag("library/nginx"), "library%2Fnginx");
        assert_eq!(decode_tag("library%2Fnginx"), "library/nginx");

        // Double slashes
        assert_eq!(encode_tag("docker://busybox"), "docker:%2F%2Fbusybox");
        assert_eq!(decode_tag("docker:%2F%2Fbusybox"), "docker://busybox");

        // Percent signs get encoded first to avoid conflicts
        assert_eq!(encode_tag("test%2F"), "test%252F");
        assert_eq!(decode_tag("test%252F"), "test%2F");

        // Round-trip
        let names = [
            "simple",
            "with:tag",
            "registry.io/image:v1",
            "docker://busybox:latest",
            "containers-storage:myimage",
            "weird%name/with/slashes",
        ];
        for name in names {
            assert_eq!(
                decode_tag(&encode_tag(name)),
                name,
                "round-trip failed for {name}"
            );
        }
    }

    #[test]
    fn test_hash() {
        assert_eq!(
            hash(b"hello world"),
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_blob_identifier() {
        assert_eq!(blob_identifier("sha256:abc123"), "oci-blob-sha256:abc123");
    }

    #[test]
    fn test_write_and_read_blob() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let data = b"This is some arbitrary blob data for an OCI artifact.";
        let (digest, verity) = write_blob(repo, data).unwrap();

        assert!(digest.starts_with("sha256:"));

        // Read back with verity (fast path)
        let read_data = open_blob(&repo, &digest, Some(&verity)).unwrap();
        assert_eq!(read_data, data);

        // Read back without verity (verifies content hash)
        let read_data2 = open_blob(&repo, &digest, None).unwrap();
        assert_eq!(read_data2, data);
    }

    #[test]
    fn test_write_blob_deduplication() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let data = b"duplicate blob content";

        let (digest1, verity1) = write_blob(repo, data).unwrap();
        let (digest2, verity2) = write_blob(repo, data).unwrap();

        // Same content should produce same digest and verity
        assert_eq!(digest1, digest2);
        assert_eq!(verity1, verity2);
    }

    #[test]
    fn test_open_blob_bad_digest() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let data = b"some blob data";
        let (_digest, _verity) = write_blob(repo, data).unwrap();

        // Try to open with wrong digest - should fail (blob doesn't exist)
        let bad_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let result = open_blob::<Sha256HashValue>(&repo, bad_digest, None);
        assert!(result.is_err());
    }

    /// Test storing and retrieving an OCI artifact with non-tar media type.
    ///
    /// This simulates what would happen when storing something like a
    /// Helm chart, WASM module, or other non-container artifact.
    #[test]
    fn test_oci_artifact_roundtrip() {
        use containers_image_proxy::oci_spec::image::{
            DescriptorBuilder, Digest as OciDigest, ImageManifestBuilder,
        };
        use std::str::FromStr;

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create an artifact with a custom media type (simulating a WASM module)
        let wasm_bytes = b"\x00asm\x01\x00\x00\x00"; // WASM magic header
        let (blob_digest, blob_verity) = write_blob(repo, wasm_bytes).unwrap();

        // Create an empty config (common for artifacts)
        let empty_config = b"{}";
        let config_digest = hash(empty_config);

        // Write the config as a blob (artifacts often have empty or minimal configs)
        let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
        config_stream.write_inline(empty_config);
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        // Build the manifest with artifact media types
        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other(
                "application/vnd.wasm.config.v1+json".to_string(),
            ))
            .digest(OciDigest::from_str(&config_digest).unwrap())
            .size(empty_config.len() as u64)
            .build()
            .unwrap();

        let blob_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other("application/wasm".to_string()))
            .digest(OciDigest::from_str(&blob_digest).unwrap())
            .size(wasm_bytes.len() as u64)
            .build()
            .unwrap();

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![blob_descriptor])
            .build()
            .unwrap();

        // Store the manifest
        let mut layer_verities = HashMap::new();
        // For artifacts, we use the blob digest as the "diff_id" equivalent
        layer_verities.insert(blob_digest.clone().into_boxed_str(), blob_verity.clone());

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = hash(manifest_json.as_bytes());

        let (stored_digest, manifest_verity) = write_manifest(
            &repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            Some("my-wasm-artifact:v1"),
        )
        .unwrap();

        assert_eq!(stored_digest, manifest_digest);

        // Now open the artifact and verify
        let opened = OciImage::open(&repo, &manifest_digest, Some(&manifest_verity)).unwrap();

        assert!(!opened.is_container_image()); // Not a container image
        assert_eq!(opened.manifest_digest(), manifest_digest);
        assert_eq!(opened.config_digest(), config_digest);
        assert_eq!(opened.layer_descriptors().len(), 1);
        assert_eq!(
            opened.layer_descriptors()[0].media_type(),
            &MediaType::Other("application/wasm".to_string())
        );

        // Verify we can look it up by tag
        let by_tag = OciImage::open_ref(&repo, "my-wasm-artifact:v1").unwrap();
        assert_eq!(by_tag.manifest_digest(), manifest_digest);

        // Verify listing shows the artifact
        let images = list_images(&repo).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "my-wasm-artifact:v1");
        assert!(!images[0].is_container); // Artifact, not container

        // Verify we can read the blob back
        let read_wasm = open_blob(&repo, &blob_digest, Some(&blob_verity)).unwrap();
        assert_eq!(read_wasm, wasm_bytes);
    }

    /// Test the OCI 1.1 empty config artifact pattern from the spec:
    /// config is `application/vnd.oci.empty.v1+json`, layers use custom
    /// media types, and layer digests are used as diff_ids.
    /// See: https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md
    #[test]
    fn test_oci_artifact_empty_config() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let sbom_data = br#"{"spdxVersion":"SPDX-2.3","name":"example"}"#;
        let layer_digest = hash(sbom_data);

        // Store the raw layer as an object with external ref splitstream
        let blob_object_id = repo.ensure_object(sbom_data).unwrap();
        let layer_content_id = crate::layer_identifier(&layer_digest);
        let mut layer_stream = repo.create_stream(crate::skopeo::OCI_BLOB_CONTENT_TYPE);
        layer_stream.add_external_size(sbom_data.len() as u64);
        layer_stream
            .write_reference(blob_object_id.clone())
            .unwrap();
        let layer_verity = repo
            .write_stream(layer_stream, &layer_content_id, None)
            .unwrap();

        // The OCI 1.1 empty config: `{}` with the well-known digest
        let empty_config = b"{}";
        let config_digest = hash(empty_config);
        assert_eq!(
            config_digest,
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );

        // Store the config — for artifacts we still write it as a config
        // splitstream, but it contains no diff_ids-derived named refs.
        // Instead, the layer refs come from the manifest layer digests.
        let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
        config_stream.write_inline(empty_config);
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        // Build a spec-conformant artifact manifest with EmptyJSON config
        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::EmptyJSON)
            .digest(OciDigest::from_str(&config_digest).unwrap())
            .size(empty_config.len() as u64)
            .build()
            .unwrap();

        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other("text/spdx+json".to_string()))
            .digest(OciDigest::from_str(&layer_digest).unwrap())
            .size(sbom_data.len() as u64)
            .build()
            .unwrap();

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor.clone())
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        // Verify: EmptyJSON config is NOT an image config
        assert_ne!(*config_descriptor.media_type(), MediaType::ImageConfig);

        // Store manifest — layer_verities uses the layer digest as key
        // (same logic as ensure_config_with_layers when !is_image_config)
        let mut layer_verities = HashMap::new();
        layer_verities.insert(layer_digest.clone().into_boxed_str(), layer_verity.clone());

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = hash(manifest_json.as_bytes());

        let (_stored_digest, manifest_verity) = write_manifest(
            &repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            Some("my-sbom:v1"),
        )
        .unwrap();

        // Verify the image opens and is not a container image
        let opened = OciImage::open(&repo, &manifest_digest, Some(&manifest_verity)).unwrap();
        assert!(!opened.is_container_image());
        assert_eq!(opened.layer_descriptors().len(), 1);
        assert_eq!(
            opened.layer_descriptors()[0].media_type(),
            &MediaType::Other("text/spdx+json".to_string())
        );

        // Verify open_layer_fd gives us a readable fd to the raw blob
        let fd = opened.open_layer_fd(&repo, 0).unwrap();
        let mut recovered = vec![];
        File::from(fd).read_to_end(&mut recovered).unwrap();
        assert_eq!(recovered, sbom_data);

        // Out of range index should fail
        assert!(opened.open_layer_fd(&repo, 1).is_err());

        // Verify GC keeps everything when tagged
        let gc = repo.gc(&[]).unwrap();
        assert_eq!(gc.objects_removed, 0);

        // Verify untagging makes it collectible
        untag_image(&repo, "my-sbom:v1").unwrap();
        let gc = repo.gc(&[]).unwrap();
        assert!(gc.objects_removed > 0);
    }

    /// Test that open_layer_fd rejects tar layers.
    #[test]
    fn test_open_layer_fd_rejects_tar() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (digest, verity, _) = create_test_image(repo, Some("myimage:v1"), "amd64");
        let img = OciImage::open(&repo, &digest, Some(&verity)).unwrap();
        assert!(img.is_container_image());

        // Tar layer should be rejected
        let err = img.open_layer_fd(&repo, 0).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("does not support tar layers"), "got: {msg}");
    }

    /// Test storing a non-tar layer as a splitstream with a single
    /// external reference, simulating how `ensure_layer` handles
    /// non-tar media types. The raw bytes go into objects/ and a
    /// tiny splitstream holds the reference for GC tracking.
    #[test]
    fn test_non_tar_layer_storage() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let sbom_data = br#"{"spdxVersion":"SPDX-2.3","name":"example"}"#;
        let diff_id = hash(sbom_data);

        // Store the raw bytes as a repository object
        let object_id = repo.ensure_object(sbom_data).unwrap();

        // Create a splitstream with a single external ref (matches ensure_layer)
        let content_id = crate::layer_identifier(&diff_id);
        let mut stream = repo.create_stream(crate::skopeo::OCI_BLOB_CONTENT_TYPE);
        stream.add_external_size(sbom_data.len() as u64);
        stream.write_reference(object_id.clone()).unwrap();
        let stream_verity = repo.write_stream(stream, &content_id, None).unwrap();

        // Verify has_stream finds it
        let found = repo.has_stream(&content_id).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap(), stream_verity);

        // Verify we can get the external ref back from the splitstream
        let mut reader = repo
            .open_stream(
                &content_id,
                Some(&stream_verity),
                Some(crate::skopeo::OCI_BLOB_CONTENT_TYPE),
            )
            .unwrap();
        let mut refs = vec![];
        reader.get_object_refs(|id| refs.push(id.clone())).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], object_id);

        // Verify we can open the raw object and read the data back
        let mut recovered = vec![];
        File::from(repo.open_object(&object_id).unwrap())
            .read_to_end(&mut recovered)
            .unwrap();
        assert_eq!(recovered, sbom_data);
    }

    /// Test that a non-tar artifact layer (stored as an external ref)
    /// is preserved by GC when referenced from a tagged manifest.
    #[test]
    fn test_non_tar_artifact_gc() {
        use containers_image_proxy::oci_spec::image::{
            DescriptorBuilder, Digest as OciDigest, ImageManifestBuilder,
        };
        use std::str::FromStr;

        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Store the raw blob as an object
        let sbom_data = br#"{"spdxVersion":"SPDX-2.3","name":"example"}"#;
        let diff_id = hash(sbom_data);
        let blob_object_id = repo.ensure_object(sbom_data).unwrap();

        // Create a splitstream with external ref (matches ensure_layer)
        let layer_content_id = crate::layer_identifier(&diff_id);
        let mut layer_stream = repo.create_stream(crate::skopeo::OCI_BLOB_CONTENT_TYPE);
        layer_stream.add_external_size(sbom_data.len() as u64);
        layer_stream
            .write_reference(blob_object_id.clone())
            .unwrap();
        let layer_verity = repo
            .write_stream(layer_stream, &layer_content_id, None)
            .unwrap();

        // Store a minimal config
        let config_bytes = b"{}";
        let config_digest = hash(config_bytes);
        let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
        config_stream.write_inline(config_bytes);
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        // Build and store a manifest referencing both
        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(OciDigest::from_str(&config_digest).unwrap())
            .size(config_bytes.len() as u64)
            .build()
            .unwrap();
        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other("text/spdx+json".to_string()))
            .digest(OciDigest::from_str(&diff_id).unwrap())
            .size(sbom_data.len() as u64)
            .build()
            .unwrap();
        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        let mut layer_verities = HashMap::new();
        layer_verities.insert(diff_id.clone().into_boxed_str(), layer_verity);

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = hash(manifest_json.as_bytes());

        let (_stored_digest, _manifest_verity) = write_manifest(
            &repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            Some("my-sbom:v1"),
        )
        .unwrap();

        // GC should preserve everything — the blob object is reachable via
        // manifest → config named ref → layer splitstream → external ref
        let gc = repo.gc(&[]).unwrap();
        assert_eq!(gc.objects_removed, 0, "tagged artifact should be preserved");

        // Verify we can still get an fd to the raw blob object
        let mut recovered = vec![];
        File::from(repo.open_object(&blob_object_id).unwrap())
            .read_to_end(&mut recovered)
            .unwrap();
        assert_eq!(recovered, sbom_data);
    }

    /// Test storing and listing multiple container images.
    #[test]
    fn test_multiple_images() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create three images with different tags
        let (digest1, verity1, _) = create_test_image(repo, Some("app:v1"), "amd64");
        let (digest2, verity2, _) = create_test_image(repo, Some("app:v2"), "amd64");
        let (digest3, verity3, _) = create_test_image(repo, Some("other:latest"), "arm64");

        // List all images
        let images = list_images(repo).unwrap();
        assert_eq!(images.len(), 3);

        // Verify we have all three tags
        let names: Vec<_> = images.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"app:v1"));
        assert!(names.contains(&"app:v2"));
        assert!(names.contains(&"other:latest"));

        // Verify architectures
        for img in &images {
            if img.name == "other:latest" {
                assert_eq!(img.architecture, "arm64");
            } else {
                assert_eq!(img.architecture, "amd64");
            }
            assert!(img.is_container);
        }

        // Verify we can open each by tag
        let img1 = OciImage::open_ref(repo, "app:v1").unwrap();
        assert_eq!(img1.manifest_digest(), digest1);
        assert_eq!(img1.manifest_verity(), &verity1);

        let img2 = OciImage::open_ref(repo, "app:v2").unwrap();
        assert_eq!(img2.manifest_digest(), digest2);
        assert_eq!(img2.manifest_verity(), &verity2);

        let img3 = OciImage::open_ref(repo, "other:latest").unwrap();
        assert_eq!(img3.manifest_digest(), digest3);
        assert_eq!(img3.manifest_verity(), &verity3);
    }

    /// Test that untagging removes the image from listing but preserves data.
    #[test]
    fn test_untag_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create two images
        let (digest1, verity1, _) = create_test_image(repo, Some("myapp:v1"), "amd64");
        let (digest2, _verity2, _) = create_test_image(repo, Some("myapp:v2"), "amd64");

        // Verify both are listed
        let images = list_images(repo).unwrap();
        assert_eq!(images.len(), 2);

        // Untag v1
        untag_image(repo, "myapp:v1").unwrap();

        // Now only v2 should be listed
        let images = list_images(repo).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "myapp:v2");
        assert_eq!(images[0].manifest_digest, digest2);

        // But we can still open the image by digest (data is preserved)
        let img = OciImage::open(repo, &digest1, Some(&verity1)).unwrap();
        assert_eq!(img.manifest_digest(), digest1);

        // Opening by the removed tag should fail
        let result = OciImage::open_ref(repo, "myapp:v1");
        assert!(result.is_err());
    }

    /// Test resolving refs and listing refs.
    #[test]
    fn test_refs() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create an image
        let (digest, verity, _) = create_test_image(repo, Some("test:latest"), "amd64");

        // List refs
        let refs = list_refs(repo).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "test:latest");
        assert_eq!(refs[0].1, digest);

        // Resolve ref
        let (resolved_digest, resolved_verity) = resolve_ref(repo, "test:latest").unwrap();
        assert_eq!(resolved_digest, digest);
        assert_eq!(resolved_verity, verity);

        // Resolve non-existent ref should fail
        let result = resolve_ref::<Sha256HashValue>(repo, "nonexistent:tag");
        assert!(result.is_err());
    }

    /// Test that tagging an existing manifest with a new name works.
    #[test]
    fn test_tag_existing_manifest() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create an image with one tag
        let (digest, verity, _) = create_test_image(repo, Some("original:v1"), "amd64");

        // Add a second tag to the same manifest
        tag_image(repo, &digest, "alias:latest").unwrap();

        // Both tags should resolve to the same manifest
        let (d1, v1) = resolve_ref(repo, "original:v1").unwrap();
        let (d2, v2) = resolve_ref(repo, "alias:latest").unwrap();
        assert_eq!(d1, d2);
        assert_eq!(v1, v2);
        assert_eq!(d1, digest);
        assert_eq!(v1, verity);

        // Both should appear in list
        let images = list_images(repo).unwrap();
        assert_eq!(images.len(), 2);

        // Untag original, alias should still work
        untag_image(repo, "original:v1").unwrap();
        let (d3, _) = resolve_ref(repo, "alias:latest").unwrap();
        assert_eq!(d3, digest);

        let images = list_images(repo).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].name, "alias:latest");
    }

    /// Test opening image by manifest digest (no tag required).
    #[test]
    fn test_open_by_digest() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create image without a tag
        let (digest, verity, config_digest) = create_test_image(repo, None, "amd64");

        // No images should be listed (no tag)
        let images = list_images(repo).unwrap();
        assert!(images.is_empty());

        // But we can open by digest with verity
        let img = OciImage::open(repo, &digest, Some(&verity)).unwrap();
        assert_eq!(img.manifest_digest(), digest);
        assert_eq!(img.config_digest(), config_digest);
        assert!(img.is_container_image());
        assert_eq!(img.architecture(), "amd64");

        // We can also open by digest without verity (verifies hash)
        let img2 = OciImage::open(repo, &digest, None).unwrap();
        assert_eq!(img2.manifest_digest(), digest);
    }

    /// Test fetching manifest and config from stored image.
    #[test]
    fn test_fetch_manifest_config() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (digest, verity, config_digest) =
            create_test_image(repo, Some("fetchtest:v1"), "amd64");

        // Open the image
        let img = OciImage::open_ref(repo, "fetchtest:v1").unwrap();

        // Verify manifest fields
        assert_eq!(img.manifest_digest(), digest);
        assert_eq!(img.manifest_verity(), &verity);
        let manifest = img.manifest();
        assert_eq!(manifest.schema_version(), 2u32);
        assert_eq!(manifest.layers().len(), 1);

        // Verify config fields
        assert_eq!(img.config_digest(), config_digest);
        let config = img.config().expect("should have config");
        assert_eq!(config.architecture().to_string(), "amd64");
        assert_eq!(config.os().to_string(), "linux");
        assert_eq!(config.rootfs().diff_ids().len(), 1);

        // Verify layer refs are accessible
        let diff_ids = img.layer_diff_ids();
        assert_eq!(diff_ids.len(), 1);
        let layer_verity = img.layer_verity(diff_ids[0]);
        assert!(layer_verity.is_some());
    }

    /// Test that has_manifest correctly detects existing manifests.
    #[test]
    fn test_has_manifest() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Before creating any image
        let nonexistent = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(has_manifest(repo, nonexistent).unwrap().is_none());

        // Create an image
        let (digest, verity, _) = create_test_image(repo, None, "amd64");

        // Now it should exist
        let found = has_manifest(repo, &digest).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap(), verity);

        // Non-existent still returns None
        assert!(has_manifest(repo, nonexistent).unwrap().is_none());
    }

    /// Test empty repository behavior.
    #[test]
    fn test_empty_repo() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // List should return empty vec, not error
        let images = list_images(repo).unwrap();
        assert!(images.is_empty());

        let refs = list_refs(repo).unwrap();
        assert!(refs.is_empty());
    }

    /// Test untagging non-existent tag.
    #[test]
    fn test_untag_nonexistent() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Should fail gracefully
        let result = untag_image(repo, "nonexistent:tag");
        assert!(result.is_err());
    }

    // ==================== GC Integration Tests ====================
    //
    // These tests verify that garbage collection correctly handles OCI images:
    // - Tagged images are preserved (tags act as GC roots)
    // - Untagged images can be collected
    // - Shared layers between images are handled correctly

    /// Test that GC preserves a tagged OCI image and all its components.
    #[test]
    fn test_gc_preserves_tagged_oci_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a tagged image
        let (manifest_digest, manifest_verity, config_digest) =
            create_test_image(repo, Some("myapp:v1"), "amd64");

        // Run GC
        let gc_result = repo.gc(&[]).unwrap();

        // Nothing should be removed - the tag protects everything
        assert_eq!(gc_result.objects_removed, 0);
        assert_eq!(gc_result.streams_pruned, 0);

        // Verify the image is still fully accessible
        let img = OciImage::open_ref(repo, "myapp:v1").unwrap();
        assert_eq!(img.manifest_digest(), manifest_digest);
        assert_eq!(img.manifest_verity(), &manifest_verity);
        assert_eq!(img.config_digest(), config_digest);

        // Verify layer is still accessible
        let diff_ids = img.layer_diff_ids();
        assert_eq!(diff_ids.len(), 1);
        assert!(img.layer_verity(diff_ids[0]).is_some());
    }

    /// Test that GC removes an untagged OCI image.
    #[test]
    fn test_gc_removes_untagged_oci_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create an image WITHOUT a tag
        let (manifest_digest, manifest_verity, _config_digest) =
            create_test_image(repo, None, "amd64");

        // Verify we can access it before GC
        let img = OciImage::open(repo, &manifest_digest, Some(&manifest_verity)).unwrap();
        let diff_ids = img.layer_diff_ids();
        assert_eq!(diff_ids.len(), 1);
        drop(img);

        // Run GC - should remove the untagged image
        let gc_result = repo.gc(&[]).unwrap();

        // Objects should have been removed (manifest, config, layer objects)
        assert!(gc_result.objects_removed > 0);

        // The manifest stream should be gone (broken symlink cleaned up)
        let result = has_manifest(repo, &manifest_digest);
        assert!(
            result.unwrap().is_none(),
            "manifest should be gone after GC"
        );
    }

    /// Test that untagging an image makes it eligible for GC.
    #[test]
    fn test_gc_after_untag_removes_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a tagged image
        let (manifest_digest, manifest_verity, _) =
            create_test_image(repo, Some("temporary:v1"), "amd64");

        // Verify it exists and run initial GC (should keep everything)
        let gc_result = repo.gc(&[]).unwrap();
        assert_eq!(gc_result.objects_removed, 0);

        // Untag the image
        untag_image(repo, "temporary:v1").unwrap();

        // Verify tag is gone
        assert!(OciImage::open_ref(repo, "temporary:v1").is_err());

        // But image data still exists (just not tagged)
        assert!(OciImage::open(repo, &manifest_digest, Some(&manifest_verity)).is_ok());

        // Run GC - now it should be removed
        let gc_result = repo.gc(&[]).unwrap();
        assert!(gc_result.objects_removed > 0);

        // Image should be gone
        assert!(has_manifest(repo, &manifest_digest).unwrap().is_none());
    }

    /// Test GC with two images sharing layers - removing one preserves shared layers.
    #[test]
    fn test_gc_with_shared_layers() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a shared layer
        let shared_layer_data = b"shared-base-layer-content";
        let shared_layer_digest = hash(shared_layer_data);

        let mut shared_layer_stream = repo.create_stream(crate::skopeo::TAR_LAYER_CONTENT_TYPE);
        shared_layer_stream.write_inline(shared_layer_data);
        let shared_layer_verity = repo
            .write_stream(
                shared_layer_stream,
                &crate::layer_identifier(&shared_layer_digest),
                None,
            )
            .unwrap();

        // Helper to create an image using the shared layer
        let create_image_with_shared_layer = |repo: &Arc<Repository<Sha256HashValue>>,
                                              tag: Option<&str>,
                                              extra_data: &[u8]|
         -> (String, Sha256HashValue) {
            // Create OCI config referencing the shared layer
            let rootfs = RootFsBuilder::default()
                .typ("layers")
                .diff_ids(vec![shared_layer_digest.clone()])
                .build()
                .unwrap();

            let cfg = ConfigBuilder::default().build().unwrap();

            // Add unique data to make configs different
            let config = ImageConfigurationBuilder::default()
                .architecture("amd64")
                .os("linux")
                .rootfs(rootfs)
                .config(cfg)
                .created(String::from_utf8_lossy(extra_data).to_string())
                .build()
                .unwrap();

            let config_json = config.to_string().unwrap();
            let config_digest = hash(config_json.as_bytes());

            let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
            config_stream.add_named_stream_ref(&shared_layer_digest, &shared_layer_verity);
            config_stream.write_inline(config_json.as_bytes());
            let config_verity = repo
                .write_stream(
                    config_stream,
                    &crate::config_identifier(&config_digest),
                    None,
                )
                .unwrap();

            // Build manifest
            let config_descriptor = DescriptorBuilder::default()
                .media_type(MediaType::ImageConfig)
                .digest(OciDigest::from_str(&config_digest).unwrap())
                .size(config_json.len() as u64)
                .build()
                .unwrap();

            let layer_descriptor = DescriptorBuilder::default()
                .media_type(MediaType::ImageLayerGzip)
                .digest(OciDigest::from_str(&shared_layer_digest).unwrap())
                .size(shared_layer_data.len() as u64)
                .build()
                .unwrap();

            let manifest = ImageManifestBuilder::default()
                .schema_version(2u32)
                .media_type(MediaType::ImageManifest)
                .config(config_descriptor)
                .layers(vec![layer_descriptor])
                .build()
                .unwrap();

            let mut layer_verities = HashMap::new();
            layer_verities.insert(
                shared_layer_digest.clone().into_boxed_str(),
                shared_layer_verity.clone(),
            );

            let manifest_json = manifest.to_string().unwrap();
            let manifest_digest = hash(manifest_json.as_bytes());

            let (_stored_digest, manifest_verity) = write_manifest(
                repo,
                &manifest,
                &manifest_digest,
                &config_verity,
                &layer_verities,
                tag,
            )
            .unwrap();

            (manifest_digest, manifest_verity)
        };

        // Create two images sharing the layer - only one is tagged
        let (digest1, verity1) = create_image_with_shared_layer(repo, Some("tagged:v1"), b"image1");
        let (digest2, _verity2) = create_image_with_shared_layer(repo, None, b"image2");

        // Verify both exist
        assert!(has_manifest(repo, &digest1).unwrap().is_some());
        assert!(has_manifest(repo, &digest2).unwrap().is_some());

        // Run GC
        let gc_result = repo.gc(&[]).unwrap();

        // Some objects removed (untagged image's unique objects)
        assert!(gc_result.objects_removed > 0);

        // Tagged image should still work completely
        let img1 = OciImage::open(repo, &digest1, Some(&verity1)).unwrap();
        assert_eq!(img1.layer_diff_ids().len(), 1);
        assert!(img1.layer_verity(&shared_layer_digest).is_some());

        // Untagged image should be gone
        assert!(has_manifest(repo, &digest2).unwrap().is_none());

        // Shared layer should still exist (protected by tagged image)
        assert!(repo
            .has_stream(&crate::layer_identifier(&shared_layer_digest))
            .unwrap()
            .is_some());
    }

    /// Test that multiple tags on the same manifest are handled correctly.
    #[test]
    fn test_gc_with_multiple_tags_same_manifest() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create an image with one tag
        let (manifest_digest, manifest_verity, _) =
            create_test_image(repo, Some("original:v1"), "amd64");

        // Add a second tag pointing to the same manifest
        tag_image(repo, &manifest_digest, "alias:latest").unwrap();

        // Verify both tags exist
        assert_eq!(list_images(repo).unwrap().len(), 2);

        // Remove one tag
        untag_image(repo, "original:v1").unwrap();

        // Run GC
        let gc_result = repo.gc(&[]).unwrap();

        // Nothing should be removed - alias:latest still protects everything
        assert_eq!(gc_result.objects_removed, 0);

        // Image should still be fully accessible via remaining tag
        let img = OciImage::open_ref(repo, "alias:latest").unwrap();
        assert_eq!(img.manifest_digest(), manifest_digest);
        assert_eq!(img.manifest_verity(), &manifest_verity);

        // Layer should still be accessible
        let diff_ids = img.layer_diff_ids();
        assert!(img.layer_verity(diff_ids[0]).is_some());

        // Now remove the last tag
        untag_image(repo, "alias:latest").unwrap();

        // Run GC again
        let gc_result = repo.gc(&[]).unwrap();

        // Now everything should be removed
        assert!(gc_result.objects_removed > 0);
        assert!(has_manifest(repo, &manifest_digest).unwrap().is_none());
    }

    /// Test gc_dry_run with OCI images.
    #[test]
    fn test_gc_dry_run_oci_image() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create one tagged and one untagged image with DIFFERENT architectures
        // to ensure they have unique layer content (create_test_image uses arch in layer data)
        let (tagged_digest, tagged_verity, _) = create_test_image(repo, Some("keep:v1"), "amd64");
        let (untagged_digest, _untagged_verity, _) = create_test_image(repo, None, "arm64");

        // Verify both exist
        assert!(has_manifest(repo, &tagged_digest).unwrap().is_some());
        assert!(has_manifest(repo, &untagged_digest).unwrap().is_some());

        // Run dry-run GC
        let dry_run_result = repo.gc_dry_run(&[]).unwrap();

        // Should report objects that would be removed (untagged image's unique objects)
        assert!(
            dry_run_result.objects_removed > 0,
            "dry-run should report objects to remove, got {:?}",
            dry_run_result
        );

        // But nothing should actually be removed
        assert!(has_manifest(repo, &tagged_digest).unwrap().is_some());
        assert!(has_manifest(repo, &untagged_digest).unwrap().is_some());

        // Tagged image still fully accessible
        let img = OciImage::open(repo, &tagged_digest, Some(&tagged_verity)).unwrap();
        assert!(img.layer_verity(img.layer_diff_ids()[0]).is_some());

        // Now do real GC
        let real_result = repo.gc(&[]).unwrap();

        // Should match dry-run results
        assert_eq!(real_result.objects_removed, dry_run_result.objects_removed);

        // Now untagged is gone
        assert!(has_manifest(repo, &untagged_digest).unwrap().is_none());
        // Tagged still exists
        assert!(has_manifest(repo, &tagged_digest).unwrap().is_some());
    }

    /// Test referrer index: store an artifact, add a referrer entry,
    /// then discover it via list_referrers.
    #[test]
    fn test_referrer_index_roundtrip() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a "subject" image that will be referenced
        let (subject_digest, _subject_verity, _) =
            create_test_image(repo, Some("subject:v1"), "amd64");

        // Create a simple artifact manifest that references the subject
        let blob_data = b"signature-blob";
        let (blob_digest, blob_verity) = write_blob(repo, blob_data).unwrap();

        let empty_config = b"{}";
        let config_digest = hash(empty_config);

        let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
        config_stream.write_inline(empty_config);
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::EmptyJSON)
            .digest(OciDigest::from_str(&config_digest).unwrap())
            .size(empty_config.len() as u64)
            .build()
            .unwrap();

        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other("application/octet-stream".to_string()))
            .digest(OciDigest::from_str(&blob_digest).unwrap())
            .size(blob_data.len() as u64)
            .build()
            .unwrap();

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        let mut layer_verities = HashMap::new();
        layer_verities.insert(blob_digest.into_boxed_str(), blob_verity);

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = hash(manifest_json.as_bytes());

        let (_stored_digest, _manifest_verity) = write_manifest(
            repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            None,
        )
        .unwrap();

        // Before adding the referrer, list should be empty
        let referrers = list_referrers(repo, &subject_digest).unwrap();
        assert!(referrers.is_empty());

        // Add the referrer index entry
        add_referrer(repo, &subject_digest, &manifest_digest).unwrap();

        // Now list_referrers should find it
        let referrers = list_referrers(repo, &subject_digest).unwrap();
        assert_eq!(referrers.len(), 1);
        assert_eq!(referrers[0].0, manifest_digest);

        // Querying a different subject should return empty
        let other = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let referrers = list_referrers(repo, other).unwrap();
        assert!(referrers.is_empty());
    }

    /// Test referrer index with multiple artifacts referencing the same subject.
    #[test]
    fn test_referrer_index_multiple() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (subject_digest, _, _) = create_test_image(repo, Some("subject:v1"), "amd64");

        let empty_config = b"{}";
        let config_digest = hash(empty_config);
        let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
        config_stream.write_inline(empty_config);
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        // Create two artifact manifests referencing the same subject
        let mut artifact_digests = Vec::new();
        for i in 0..2u8 {
            let blob_data = format!("artifact-blob-{i}").into_bytes();
            let (blob_digest, blob_verity) = write_blob(repo, &blob_data).unwrap();

            let config_descriptor = DescriptorBuilder::default()
                .media_type(MediaType::EmptyJSON)
                .digest(OciDigest::from_str(&config_digest).unwrap())
                .size(empty_config.len() as u64)
                .build()
                .unwrap();

            let layer_descriptor = DescriptorBuilder::default()
                .media_type(MediaType::Other("application/octet-stream".to_string()))
                .digest(OciDigest::from_str(&blob_digest).unwrap())
                .size(blob_data.len() as u64)
                .build()
                .unwrap();

            let manifest = ImageManifestBuilder::default()
                .schema_version(2u32)
                .media_type(MediaType::ImageManifest)
                .config(config_descriptor)
                .layers(vec![layer_descriptor])
                .build()
                .unwrap();

            let mut layer_verities = HashMap::new();
            layer_verities.insert(blob_digest.into_boxed_str(), blob_verity);

            let manifest_json = manifest.to_string().unwrap();
            let manifest_digest = hash(manifest_json.as_bytes());

            write_manifest(
                repo,
                &manifest,
                &manifest_digest,
                &config_verity,
                &layer_verities,
                None,
            )
            .unwrap();

            add_referrer(repo, &subject_digest, &manifest_digest).unwrap();
            artifact_digests.push(manifest_digest);
        }

        let referrers = list_referrers(repo, &subject_digest).unwrap();
        assert_eq!(referrers.len(), 2);

        let found_digests: Vec<&str> = referrers.iter().map(|(d, _)| d.as_str()).collect();
        for expected in &artifact_digests {
            assert!(
                found_digests.contains(&expected.as_str()),
                "Missing artifact {expected} in referrers"
            );
        }
    }

    /// Helper to create a minimal OCI artifact manifest in the repository.
    ///
    /// Returns (manifest_digest, manifest_verity).
    fn create_test_artifact(
        repo: &Arc<Repository<Sha256HashValue>>,
        blob_data: &[u8],
    ) -> (String, Sha256HashValue) {
        let (blob_digest, blob_verity) = write_blob(repo, blob_data).unwrap();

        let empty_config = b"{}";
        let config_digest = hash(empty_config);

        let mut config_stream = repo.create_stream(OCI_CONFIG_CONTENT_TYPE);
        config_stream.write_inline(empty_config);
        let config_verity = repo
            .write_stream(
                config_stream,
                &crate::config_identifier(&config_digest),
                None,
            )
            .unwrap();

        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::EmptyJSON)
            .digest(OciDigest::from_str(&config_digest).unwrap())
            .size(empty_config.len() as u64)
            .build()
            .unwrap();

        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other("application/octet-stream".to_string()))
            .digest(OciDigest::from_str(&blob_digest).unwrap())
            .size(blob_data.len() as u64)
            .build()
            .unwrap();

        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();

        let mut layer_verities = HashMap::new();
        layer_verities.insert(blob_digest.into_boxed_str(), blob_verity);

        let manifest_json = manifest.to_string().unwrap();
        let manifest_digest = hash(manifest_json.as_bytes());

        let (_stored_digest, manifest_verity) = write_manifest(
            repo,
            &manifest,
            &manifest_digest,
            &config_verity,
            &layer_verities,
            None,
        )
        .unwrap();

        (manifest_digest, manifest_verity)
    }

    /// Test that GC collects referrer artifacts when their subject is untagged.
    ///
    /// Referrer symlinks under `streams/refs/oci-referrers/` act as GC roots,
    /// so orphaned referrer entries must be cleaned up before GC to allow
    /// the artifact manifests and their objects to be collected.
    #[test]
    fn test_gc_cleans_referrer_artifacts() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // 1. Create a subject image with a tag
        let (subject_digest, _subject_verity, _) =
            create_test_image(repo, Some("subject:v1"), "amd64");

        // 2. Create an artifact referencing the subject
        let (artifact_digest, _artifact_verity) =
            create_test_artifact(repo, b"fake-signature-data");

        // 3. Register the referrer relationship
        add_referrer(repo, &subject_digest, &artifact_digest).unwrap();

        // 4. Verify the referrer is discoverable
        let referrers = list_referrers(repo, &subject_digest).unwrap();
        assert_eq!(referrers.len(), 1);
        assert_eq!(referrers[0].0, artifact_digest);

        // Verify GC preserves everything while subject is tagged
        let gc = repo.gc(&[]).unwrap();
        assert_eq!(gc.objects_removed, 0, "nothing should be collected yet");

        // Artifact should still be accessible
        assert!(
            has_manifest(repo, &artifact_digest).unwrap().is_some(),
            "artifact manifest should exist"
        );

        // 5. Untag the subject image
        untag_image(repo, "subject:v1").unwrap();

        // 6. First GC pass: collects the subject's objects and cleans up
        //    its broken stream symlink. The artifact survives because the
        //    referrer symlink still acts as a GC root.
        let gc1 = repo.gc(&[]).unwrap();
        assert!(gc1.objects_removed > 0, "should collect subject objects");
        assert!(
            has_manifest(repo, &subject_digest).unwrap().is_none(),
            "subject manifest should be gone after first GC"
        );
        // Artifact is still alive — rooted by referrer symlink
        assert!(
            has_manifest(repo, &artifact_digest).unwrap().is_some(),
            "artifact should survive first GC (referrer symlink roots it)"
        );

        // 7. Clean up dangling referrers (subject no longer exists)
        let cleaned = cleanup_dangling_referrers(repo).unwrap();
        assert_eq!(cleaned, 1, "should remove 1 dangling referrer entry");

        // 8. Second GC pass: now collects the artifact (no longer rooted)
        let gc2 = repo.gc(&[]).unwrap();
        assert!(gc2.objects_removed > 0, "should collect artifact objects");

        // 9. Verify the artifact manifest is gone
        assert!(
            has_manifest(repo, &artifact_digest).unwrap().is_none(),
            "artifact manifest should be collected"
        );

        // 10. Verify list_referrers returns empty
        let referrers = list_referrers(repo, &subject_digest).unwrap();
        assert!(referrers.is_empty(), "no referrers should remain after GC");

        // Also verify the subject manifest is gone
        assert!(
            has_manifest(repo, &subject_digest).unwrap().is_none(),
            "subject manifest should be collected"
        );
    }

    /// Test that cleanup_dangling_referrers preserves referrers for tagged subjects.
    #[test]
    fn test_cleanup_referrers_preserves_tagged_subjects() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create a tagged subject
        let (subject_digest, _, _) = create_test_image(repo, Some("subject:v1"), "amd64");

        // Create an artifact and register it as a referrer
        let (artifact_digest, _) = create_test_artifact(repo, b"sig-data");
        add_referrer(repo, &subject_digest, &artifact_digest).unwrap();

        // Cleanup should not remove anything — subject is still tagged
        let cleaned = cleanup_dangling_referrers(repo).unwrap();
        assert_eq!(cleaned, 0, "should not remove referrers for tagged subject");

        // Referrer should still be discoverable
        let referrers = list_referrers(repo, &subject_digest).unwrap();
        assert_eq!(referrers.len(), 1);
    }

    /// Test that cleanup handles multiple subjects, only removing dangling ones.
    #[test]
    fn test_cleanup_referrers_mixed_subjects() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        // Create two subjects
        let (subject1_digest, _, _) = create_test_image(repo, Some("subject1:v1"), "amd64");
        let (subject2_digest, _, _) = create_test_image(repo, Some("subject2:v1"), "arm64");

        // Create artifacts for both
        let (artifact1_digest, _) = create_test_artifact(repo, b"sig-for-subject1");
        let (artifact2_digest, _) = create_test_artifact(repo, b"sig-for-subject2");

        add_referrer(repo, &subject1_digest, &artifact1_digest).unwrap();
        add_referrer(repo, &subject2_digest, &artifact2_digest).unwrap();

        // Untag only subject1
        untag_image(repo, "subject1:v1").unwrap();

        // First GC pass to actually remove subject1's manifest stream
        // (cleanup_dangling_referrers checks has_manifest, which checks the
        // stream symlink; GC removes the broken symlink after object deletion)
        repo.gc(&[]).unwrap();

        // Now cleanup should only remove referrers for subject1
        let cleaned = cleanup_dangling_referrers(repo).unwrap();
        assert_eq!(cleaned, 1, "should remove 1 referrer for untagged subject");

        // Run GC again to collect the now-unrooted artifact1
        let gc = repo.gc(&[]).unwrap();
        assert!(gc.objects_removed > 0);

        // subject2's referrer should still exist
        let referrers2 = list_referrers(repo, &subject2_digest).unwrap();
        assert_eq!(referrers2.len(), 1);
        assert_eq!(referrers2[0].0, artifact2_digest);

        // subject1's artifact should be gone
        assert!(has_manifest(repo, &artifact1_digest).unwrap().is_none());
        // subject2's artifact should still exist
        assert!(has_manifest(repo, &artifact2_digest).unwrap().is_some());
    }

    /// Test that cleanup_dangling_referrers is a no-op on an empty repository.
    #[test]
    fn test_cleanup_referrers_empty_repo() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let cleaned = cleanup_dangling_referrers(repo).unwrap();
        assert_eq!(cleaned, 0);
    }

    /// Test removing a single referrer: add, remove, verify gone, and
    /// confirm that a second remove is idempotent (no error).
    #[test]
    fn test_remove_referrer() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (subject_digest, _, _) = create_test_image(repo, Some("subject:v1"), "amd64");
        let (artifact_digest, _) = create_test_artifact(repo, b"sig-remove-test");

        add_referrer(repo, &subject_digest, &artifact_digest).unwrap();
        assert_eq!(list_referrers(repo, &subject_digest).unwrap().len(), 1);

        // Remove the referrer
        remove_referrer(repo, &subject_digest, &artifact_digest).unwrap();
        assert!(list_referrers(repo, &subject_digest).unwrap().is_empty());

        // Second remove is idempotent
        remove_referrer(repo, &subject_digest, &artifact_digest).unwrap();
    }

    /// Test removing all referrers for a subject at once.
    #[test]
    fn test_remove_referrers_for_subject() {
        let test_repo = TestRepo::<Sha256HashValue>::new();
        let repo = &test_repo.repo;

        let (subject_digest, _, _) = create_test_image(repo, Some("subject:v1"), "amd64");
        let (artifact1_digest, _) = create_test_artifact(repo, b"sig-bulk-1");
        let (artifact2_digest, _) = create_test_artifact(repo, b"sig-bulk-2");

        add_referrer(repo, &subject_digest, &artifact1_digest).unwrap();
        add_referrer(repo, &subject_digest, &artifact2_digest).unwrap();
        assert_eq!(list_referrers(repo, &subject_digest).unwrap().len(), 2);

        // Remove all referrers for this subject
        remove_referrers_for_subject(repo, &subject_digest).unwrap();
        assert!(list_referrers(repo, &subject_digest).unwrap().is_empty());

        // Idempotent: calling again on an already-empty subject is fine
        remove_referrers_for_subject(repo, &subject_digest).unwrap();
    }
}
