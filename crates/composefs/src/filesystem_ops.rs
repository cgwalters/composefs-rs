//! High-level filesystem operations for composefs trees.
//!
//! This module provides convenience methods for common operations on
//! FileSystem objects, including computing image IDs, committing to
//! repositories, and generating dumpfiles.

use anyhow::Result;
use fn_error_context::context;

use crate::{
    dumpfile::write_dumpfile,
    fsverity::{FsVerityHashValue, compute_verity},
    repository::Repository,
    tree::FileSystem,
};

impl<ObjectID: FsVerityHashValue> FileSystem<ObjectID> {
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
        repository.write_image(
            image_name,
            &crate::erofs::writer::mkfs_erofs_versioned(self, version),
        )
    }

    /// Computes the fsverity digest for this filesystem as an EROFS image.
    ///
    /// Reads the EROFS format version from the repository (matching the behaviour
    /// of [`commit_image`](Self::commit_image)) and returns the fsverity digest
    /// without writing anything to the repository.
    ///
    /// Note: Callers should ensure root metadata is set before calling this,
    /// typically via `copy_root_metadata_from_usr()` or `set_root_stat()`.
    pub fn compute_image_id(&self, repository: &Repository<ObjectID>) -> ObjectID {
        let version = repository.erofs_version();
        compute_verity(&crate::erofs::writer::mkfs_erofs_versioned(self, version))
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
