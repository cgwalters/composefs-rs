//! EROFS digest stability tests for the OCI → composefs pipeline.

use anyhow::{Result, bail};
use xshell::{Shell, cmd};

use crate::{cfsctl, integration_test};

/// A pinned container image for digest stability testing.
struct ContainerImage {
    /// Human-readable label for test output.
    label: &'static str,
    /// Primary OCI image reference — the ghcr.io mirror (docker:// prefix).
    ///
    /// The mirror is populated by the `mirror-fixture-images.yml` workflow after
    /// a PR that adds a new entry to `ci/fixture-images.txt` is merged to main.
    /// During the PR itself the mirror does not exist yet, so the test falls back
    /// to `upstream_ref` when this pull fails.
    image_ref: &'static str,
    /// Upstream OCI image reference used as a fallback when `image_ref` is
    /// unavailable (e.g. a PR that adds a new mirror entry before it has been
    /// pushed).  Should be pinned by digest for reproducibility.
    upstream_ref: &'static str,
    /// Expected composefs image ID without `--bootable`.
    expected_id: &'static str,
    /// Expected composefs image ID with `--bootable`, or `None` if the
    /// image lacks /sysroot and doesn't support bootable transformation.
    expected_bootable_id: Option<&'static str>,
}

// RHEL UBI 10.1, build 1772441712 (amd64).
// Mirrored from registry.access.redhat.com/ubi10/ubi:10.1-1772441712
// via ci/fixture-images.txt.  UBI is a general-purpose container image
// without /sysroot, so `--bootable` is not supported.
const UBI10: ContainerImage = ContainerImage {
    label: "ubi10",
    image_ref: "docker://ghcr.io/composefs/ci-fixture-ubi10:10.1-1772441712",
    upstream_ref: "docker://registry.access.redhat.com/ubi10/ubi:10.1-1772441712",
    expected_id: "ff8dad033a3e6015d63d6b00c16918da27bf96cc8ddd824e521549db01013227\
                  87c30a3f49e5716f8f6052d78b46308dfaaccf0dfc504d26fe58d468810c0b0e",
    expected_bootable_id: None,
};

// centos-bootc stream10, pinned by manifest digest so the test is
// reproducible even if the :stream10 tag moves forward.
// Mirrored from quay.io/centos-bootc/centos-bootc via ci/fixture-images.txt.
// This is the closest to the actual bootc sealed UKI production path.
const CENTOS_BOOTC: ContainerImage = ContainerImage {
    label: "centos-bootc",
    image_ref: "docker://ghcr.io/composefs/ci-fixture-centos-bootc:stream10-d1913e3d",
    upstream_ref: "docker://quay.io/centos-bootc/centos-bootc@sha256:d1913e3d616b9acb7fc2e3331be8baf844048bca2681a23d34e53e75eb18f3d0",
    expected_id: "ad575e0570dfb74cbc837f41715d3fba890dd983d992332eaeee93493ce112ee\
                  50d3dc5f6f2a3214cc92412fe3ae936e2e9c0eac24ea787e83ef13c0a718a193",
    expected_bootable_id: Some(
        "79c840369bf1ef414d71731166967a01f6616039bc0e1d4c5353bed02e0d2bd9\
         4459e22407bb885f1d6ce44a04add35adf0d00ca8a23f90544a99a76fdadb65b",
    ),
};

// Ubuntu 26.04 (resolute), pinned by manifest digest.
// Mirrored from docker.io/library/ubuntu via ci/fixture-images.txt.
// Ubuntu 26.04 uses umoci/PAX format tars produced by Rockcraft, which emit
// GNU-style record padding after the end-of-archive blocks.  This exercises
// the trailing-padding preservation fix in split_async() — without it the
// reconstructed tar is shorter than the original and the diff_id checksum
// fails in the @digest code path of create_filesystem().
const UBUNTU_RESOLUTE: ContainerImage = ContainerImage {
    label: "ubuntu-resolute",
    image_ref: "docker://ghcr.io/composefs/ci-fixture-ubuntu-resolute:26.04-d31acef2",
    upstream_ref: "docker://docker.io/library/ubuntu@sha256:d31acef2a964b6df1f2b7e20a1525c4f2378024e087a4f8a8a9a4247e6a79573",
    expected_id: "150caabb982d7005db1a1d0480d57a95e84b160aa2b1159f9aae66e92ba07b36\
                  11ea38e1836eff923dc3a1a617c18494757be0f5e3db16cc7a522981b3f42d40",
    expected_bootable_id: None,
};

/// All container images to test.
const CONTAINER_IMAGES: &[&ContainerImage] = &[&UBI10, &CENTOS_BOOTC, &UBUNTU_RESOLUTE];

/// Return `true` if network tests should be skipped.
fn skip_network() -> bool {
    std::env::var_os("COMPOSEFS_SKIP_NETWORK").is_some()
}

/// Pull an OCI image and return the config digest from the pull output.
///
/// Tries `image.image_ref` (the ghcr.io mirror) first.  If that fails —
/// which is expected for PRs that add a new mirror entry before it has been
/// pushed — falls back to `image.upstream_ref` with a warning.
fn pull_image(
    sh: &Shell,
    cfsctl: &std::path::Path,
    repo: &std::path::Path,
    image: &ContainerImage,
    name: &str,
) -> Result<String> {
    let candidates = [(image.image_ref, false), (image.upstream_ref, true)];
    let mut last_err = None;
    for (image_ref, is_fallback) in candidates {
        if is_fallback {
            eprintln!(
                "WARNING: mirror pull failed for {}; falling back to upstream {image_ref}",
                image.label,
            );
        }
        match try_pull_image(sh, cfsctl, repo, image_ref, name) {
            Ok(config) => return Ok(config),
            Err(e) => {
                eprintln!("Pull of {image_ref} failed: {e:#}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

fn try_pull_image(
    sh: &Shell,
    cfsctl: &std::path::Path,
    repo: &std::path::Path,
    image_ref: &str,
    name: &str,
) -> Result<String> {
    let output = cmd!(
        sh,
        "{cfsctl} --insecure --repo {repo} oci pull {image_ref} {name}"
    )
    .read()?;

    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("config") {
            return Ok(rest.trim().to_string());
        }
    }
    bail!("could not find config digest in pull output:\n{output}")
}

/// Compute the composefs image ID for a pulled OCI image.
///
/// The `config_digest` should be a bare OCI digest (e.g. `sha256:abc...`);
/// this function adds the `@` prefix required by the CLI.
fn compute_id(
    sh: &Shell,
    cfsctl: &std::path::Path,
    repo: &std::path::Path,
    config_digest: &str,
    bootable: bool,
) -> Result<String> {
    let at_digest = format!("@{config_digest}");
    let output = if bootable {
        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} oci compute-id --bootable {at_digest}"
        )
        .read()?
    } else {
        cmd!(
            sh,
            "{cfsctl} --insecure --repo {repo} oci compute-id {at_digest}"
        )
        .read()?
    };
    Ok(output.trim().to_string())
}

/// Table-driven OCI container digest stability test.
///
/// Pulls each pinned container image from a registry, computes the composefs
/// image ID for both plain and `--bootable` transforms, and asserts they
/// match the expected values.
///
/// Skipped when `COMPOSEFS_SKIP_NETWORK=1` is set.
fn test_oci_container_digest_stability() -> Result<()> {
    if skip_network() {
        eprintln!("Skipping (COMPOSEFS_SKIP_NETWORK is set)");
        return Ok(());
    }

    let sh = Shell::new()?;
    let cfsctl = cfsctl()?;

    for image in CONTAINER_IMAGES {
        eprintln!("--- {} ---", image.label);
        let repo_dir = tempfile::tempdir()?;
        let repo = repo_dir.path();
        cmd!(sh, "{cfsctl} --repo {repo} init --insecure").read()?;

        eprintln!("Pulling {} (this may take a while)...", image.label);
        let config = pull_image(&sh, &cfsctl, repo, image, image.label)?;

        // Plain (non-bootable) image ID
        let plain_id = compute_id(&sh, &cfsctl, repo, &config, false)?;
        eprintln!("{} composefs image ID: {plain_id}", image.label);
        assert_eq!(
            plain_id, image.expected_id,
            "{}: composefs image ID changed — the EROFS writer or OCI \
             pipeline produced different output for the same image",
            image.label,
        );

        // Bootable image ID (only for images that support it)
        if let Some(expected_bootable) = image.expected_bootable_id {
            let bootable_id = compute_id(&sh, &cfsctl, repo, &config, true)?;
            eprintln!(
                "{} composefs image ID (bootable): {bootable_id}",
                image.label
            );
            assert_eq!(
                bootable_id, expected_bootable,
                "{}: bootable composefs image ID changed — the EROFS writer or \
                 boot transform produced different output for the same image",
                image.label,
            );

            assert_ne!(
                plain_id, bootable_id,
                "{}: plain and --bootable image IDs should differ \
                 (bootable applies SELinux relabeling, empties /boot and /sysroot)",
                image.label,
            );
        }
    }

    Ok(())
}
integration_test!(test_oci_container_digest_stability);
