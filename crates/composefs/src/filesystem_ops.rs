//! High-level filesystem operations for composefs trees.
//!
//! This module provides convenience methods for common operations on
//! FileSystem objects, including computing image IDs, committing to
//! repositories, and generating dumpfiles.

use std::collections::HashMap;

use anyhow::Result;
use fn_error_context::context;

use crate::{
    dumpfile::write_dumpfile,
    erofs::format::{FormatSet, FormatVersion},
    fsverity::{FsVerityHashValue, compute_verity},
    repository::Repository,
    tree::FileSystem,
};

impl<ObjectID: FsVerityHashValue> FileSystem<ObjectID> {
    /// Commits this filesystem as EROFS images for each version in `formats`.
    ///
    /// Returns a map from [`FormatVersion`] to the fsverity digest of the
    /// stored image for that version.
    ///
    /// The `image_name` named ref (if provided) is assigned to the **first**
    /// version yielded by `formats.iter()` (i.e. V1 when the set includes V1).
    /// All subsequent versions are stored anonymously (no named ref).  This
    /// prevents the ref from silently being overwritten and left pointing at the
    /// last written version.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Committing filesystem as EROFS images")]
    pub fn commit_images(
        &self,
        repository: &Repository<ObjectID>,
        image_name: Option<&str>,
        formats: FormatSet,
    ) -> Result<HashMap<FormatVersion, ObjectID>> {
        let mut result = HashMap::new();
        let mut first = true;
        for version in formats.iter() {
            // Only the primary (first) version claims the named ref.
            let name = if first { image_name } else { None };
            first = false;
            let image_data = crate::erofs::writer::mkfs_erofs_versioned(self, version);
            let id = repository.write_image(name, &image_data)?;
            result.insert(version, id);
        }
        Ok(result)
    }

    /// Commits this filesystem as an EROFS image to the repository.
    ///
    /// Generates an EROFS filesystem image using the repository's configured
    /// EROFS format version and writes it with the optional name. Returns the
    /// fsverity digest of the committed image.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Committing filesystem as EROFS image")]
    pub fn commit_image(
        &self,
        repository: &Repository<ObjectID>,
        image_name: Option<&str>,
    ) -> Result<ObjectID> {
        let version = repository.erofs_version();
        let formats = FormatSet::from(version);
        let mut map = self.commit_images(repository, image_name, formats)?;
        Ok(map.remove(&version).expect("format version must be in map"))
    }

    /// Computes the fsverity digest for this filesystem as an EROFS image.
    ///
    /// The digest depends on the EROFS format version: V1 and V2 produce
    /// different on-disk layouts and therefore different digests.  Callers
    /// must supply the version explicitly so that the digest matches what is
    /// actually stored (or will be stored) in the repository.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    pub fn compute_image_id(&self, version: FormatVersion) -> ObjectID {
        compute_verity(&crate::erofs::writer::mkfs_erofs_versioned(self, version))
    }

    /// Generate the EROFS image and compute its fs-verity digest.
    ///
    /// Returns the raw EROFS image bytes alongside the fs-verity digest.
    /// Unlike `compute_image_id()` which discards the bytes, this preserves
    /// them for inclusion in composefs artifacts.
    pub fn generate_erofs_image(&self) -> (Box<[u8]>, ObjectID) {
        let erofs_bytes = crate::erofs::writer::mkfs_erofs(self);
        let digest = compute_verity(&erofs_bytes);
        (erofs_bytes, digest)
    }

    /// Prints this filesystem in dumpfile format to stdout.
    ///
    /// Serializes the entire filesystem tree to stdout in composefs dumpfile
    /// text format.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    #[context("Printing filesystem as dumpfile")]
    pub fn print_dumpfile(&self) -> Result<()> {
        write_dumpfile(&mut std::io::stdout(), self)
    }
}
