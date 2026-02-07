//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

use rustix::fs::CWD;

use composefs_boot::{write_boot, BootOps};

use composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    repository::Repository,
};

/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    #[clap(long, group = "repopath")]
    repo: Option<PathBuf>,
    #[clap(long, group = "repopath")]
    user: bool,
    #[clap(long, group = "repopath")]
    system: bool,

    /// What hash digest type to use for composefs repo
    #[clap(long, value_enum, default_value_t = HashType::Sha512)]
    hash: HashType,

    /// Sets the repository to insecure before running any operation and
    /// prepend '?' to the composefs kernel command line when writing
    /// boot entry.
    #[clap(long)]
    insecure: bool,

    /// Run in unprivileged mode (use FUSE mounting instead of kernel EROFS).
    /// Automatically enabled when running as non-root without CAP_SYS_ADMIN.
    #[clap(long)]
    unprivileged: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Default)]
enum HashType {
    Sha256,
    #[default]
    Sha512,
}

#[cfg(feature = "oci")]
#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar file as a splitstream in the repository.
    ImportLayer {
        digest: String,
        name: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream
        name: String,
    },
    Dump {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long)]
        bootable: bool,
    },
    /// Pull an OCI image from a registry
    Pull {
        /// Image reference (e.g., docker://registry.io/image:tag)
        image: String,
        /// Tag to assign to the image in the local repository
        name: Option<String>,
    },
    /// List all tagged OCI images in the repository
    #[clap(name = "images")]
    ListImages,
    /// Show information about an OCI image
    #[clap(name = "inspect")]
    Inspect {
        /// Image reference (tag name or manifest digest)
        image: String,
    },
    /// Tag an image with a new name
    Tag {
        /// Manifest digest (sha256:...)
        manifest_digest: String,
        /// Tag name to assign
        name: String,
    },
    /// Remove a tag from an image
    Untag {
        /// Tag name to remove
        name: String,
    },
    ComputeId {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long)]
        bootable: bool,
    },
    CreateImage {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long)]
        bootable: bool,
        #[clap(long)]
        image_name: Option<String>,
    },
    Seal {
        config_name: String,
        config_verity: Option<String>,
    },
    /// Create a composefs signature artifact for a sealed image
    #[cfg(feature = "signing")]
    Sign {
        /// Image reference (tag name)
        image: String,
        /// Path to PEM-encoded signing certificate
        #[clap(long)]
        cert: PathBuf,
        /// Path to PEM-encoded private key
        #[clap(long)]
        key: PathBuf,
    },
    /// Verify composefs signature artifacts for an image
    Verify {
        /// Image reference (tag name)
        image: String,
        /// Path to PEM-encoded trusted certificate for verification
        #[clap(long)]
        cert: Option<PathBuf>,
    },
    Mount {
        name: String,
        mountpoint: String,
    },
    PrepareBoot {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long, default_value = "/boot")]
        bootdir: PathBuf,
        #[clap(long)]
        entry_id: Option<String>,
        #[clap(long)]
        cmdline: Vec<String>,
    },
}

/// Common options for reading a filesystem from a path
#[derive(Debug, Parser)]
struct FsReadOptions {
    /// The path to the filesystem
    path: PathBuf,
    /// Transform the filesystem for boot (SELinux labels, empty /boot and /sysroot)
    #[clap(long)]
    bootable: bool,
    /// Don't copy /usr metadata to root directory (use if root already has well-defined metadata)
    #[clap(long)]
    no_propagate_usr_to_root: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either a content identifier or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC {
        /// Additional roots to keep (image or stream names)
        #[clap(long, short = 'r')]
        root: Vec<String>,
        /// Preview what would be deleted without actually deleting
        #[clap(long, short = 'n')]
        dry_run: bool,
    },
    /// Imports a composefs image (unsafe!)
    ImportImage { reference: String },
    /// Commands for dealing with OCI layers
    #[cfg(feature = "oci")]
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand,
    },
    /// Mounts a composefs, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either an fs-verity hash or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    /// Creates a composefs image from a filesystem
    CreateImage {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
        image_name: Option<String>,
    },
    /// Computes the composefs image ID for a filesystem
    ComputeId {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Outputs the composefs dumpfile format for a filesystem
    CreateDumpfile {
        #[clap(flatten)]
        fs_opts: FsReadOptions,
    },
    /// Lists all object IDs referenced by an image
    ImageObjects { name: String },
    #[cfg(feature = "http")]
    Fetch { url: String, name: String },
}

fn verity_opt<ObjectID>(opt: &Option<String>) -> Result<Option<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    Ok(match opt {
        Some(value) => Some(FsVerityHashValue::from_hex(value)?),
        None => None,
    })
}

fn open_repo<ObjectID>(args: &App) -> Result<Repository<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    let mut repo = (if let Some(path) = &args.repo {
        Repository::open_path(CWD, path)
    } else if args.system {
        Repository::open_system()
    } else if args.user {
        Repository::open_user()
    } else if rustix::process::getuid().is_root() {
        Repository::open_system()
    } else {
        Repository::open_user()
    })?;

    repo.set_insecure(args.insecure);

    // Auto-detect privilege level if not explicitly set
    if args.unprivileged {
        repo.set_privileged(false);
    } else {
        repo.set_privileged(rustix::process::getuid().is_root());
    }

    Ok(repo)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = App::parse();

    match args.hash {
        HashType::Sha256 => run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await,
        HashType::Sha512 => run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await,
    }
}

async fn run_cmd_with_repo<ObjectID>(repo: Repository<ObjectID>, args: App) -> Result<()>
where
    ObjectID: FsVerityHashValue,
{
    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        }
        Command::Cat { name } => {
            repo.merge_splitstream(&name, None, None, &mut std::io::stdout())?;
        }
        Command::ImportImage { reference } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", image_id.to_id());
        }
        #[cfg(feature = "oci")]
        Command::Oci { cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, digest } => {
                let object_id = composefs_oci::import_layer(
                    &Arc::new(repo),
                    &digest,
                    name.as_deref(),
                    &mut std::io::stdin(),
                )?;
                println!("{}", object_id.to_id());
            }
            OciCommand::LsLayer { name } => {
                composefs_oci::ls_layer(&repo, &name)?;
            }
            OciCommand::Dump {
                ref config_name,
                ref config_verity,
                bootable,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                fs.print_dumpfile()?;
            }
            OciCommand::ComputeId {
                ref config_name,
                ref config_verity,
                bootable,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let id = fs.compute_image_id();
                println!("{}", id.to_hex());
            }
            OciCommand::CreateImage {
                ref config_name,
                ref config_verity,
                bootable,
                ref image_name,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let image_id = fs.commit_image(&repo, image_name.as_deref())?;
                println!("{}", image_id.to_id());
            }
            OciCommand::Pull { ref image, name } => {
                // If no explicit name provided, use the image reference as the tag
                let tag_name = name.as_deref().unwrap_or(image);
                let result =
                    composefs_oci::pull_image(&Arc::new(repo), image, Some(tag_name), None).await?;

                println!("manifest {}", result.manifest_digest);
                println!("config   {}", result.config_digest);
                println!("verity   {}", result.manifest_verity.to_hex());
                println!("tagged   {tag_name}");
            }
            OciCommand::ListImages => {
                let images = composefs_oci::oci_image::list_images(&repo)?;

                if images.is_empty() {
                    println!("No images found");
                } else {
                    println!(
                        "{:<30} {:<12} {:<10} {:<8} {:<6}",
                        "NAME", "DIGEST", "ARCH", "SEALED", "LAYERS"
                    );
                    for img in images {
                        let digest_short = img
                            .manifest_digest
                            .strip_prefix("sha256:")
                            .unwrap_or(&img.manifest_digest);
                        let digest_display = if digest_short.len() > 12 {
                            &digest_short[..12]
                        } else {
                            digest_short
                        };
                        println!(
                            "{:<30} {:<12} {:<10} {:<8} {:<6}",
                            img.name,
                            digest_display,
                            if img.architecture.is_empty() {
                                "artifact"
                            } else {
                                &img.architecture
                            },
                            if img.sealed { "yes" } else { "no" },
                            img.layer_count
                        );
                    }
                }
            }
            OciCommand::Inspect { ref image } => {
                let img = if image.starts_with("sha256:") {
                    composefs_oci::oci_image::OciImage::open(&repo, image, None)?
                } else {
                    composefs_oci::oci_image::OciImage::open_ref(&repo, image)?
                };

                println!("Manifest:     {}", img.manifest_digest());
                println!("Config:       {}", img.config_digest());
                println!(
                    "Type:         {}",
                    if img.is_container_image() {
                        "container"
                    } else {
                        "artifact"
                    }
                );

                if img.is_container_image() {
                    println!("Architecture: {}", img.architecture());
                    println!("OS:           {}", img.os());
                }

                if let Some(created) = img.created() {
                    println!("Created:      {created}");
                }

                println!(
                    "Sealed:       {}",
                    if img.is_sealed() { "yes" } else { "no" }
                );
                if let Some(seal) = img.seal_digest() {
                    println!("Seal digest:  {seal}");
                }

                println!("Layers:       {}", img.layer_descriptors().len());
                for (i, layer) in img.layer_descriptors().iter().enumerate() {
                    println!("  [{i}] {} ({} bytes)", layer.digest(), layer.size());
                }

                if let Some(labels) = img.labels() {
                    if !labels.is_empty() {
                        println!("Labels:");
                        for (k, v) in labels {
                            println!("  {k}: {v}");
                        }
                    }
                }
            }
            OciCommand::Tag {
                ref manifest_digest,
                ref name,
            } => {
                composefs_oci::oci_image::tag_image(&repo, manifest_digest, name)?;
                println!("Tagged {manifest_digest} as {name}");
            }
            OciCommand::Untag { ref name } => {
                composefs_oci::oci_image::untag_image(&repo, name)?;
                println!("Removed tag {name}");
            }
            OciCommand::Seal {
                ref config_name,
                ref config_verity,
            } => {
                let verity = verity_opt(config_verity)?;
                let (digest, verity) =
                    composefs_oci::seal(&Arc::new(repo), config_name, verity.as_ref())?;
                println!("config {digest}");
                println!("verity {}", verity.to_id());
            }
            #[cfg(feature = "signing")]
            OciCommand::Sign {
                ref image,
                ref cert,
                ref key,
            } => {
                use anyhow::Context;
                use std::str::FromStr;

                let repo = Arc::new(repo);
                let img = composefs_oci::OciImage::open_ref(&repo, image)?;

                anyhow::ensure!(
                    img.is_sealed(),
                    "image {image} is not sealed; run 'cfsctl oci seal' first"
                );

                let seal_hex = img
                    .seal_digest()
                    .context("sealed image missing composefs.fsverity label")?;
                let merged_digest: ObjectID = FsVerityHashValue::from_hex(seal_hex)
                    .context("invalid seal digest in image label")?;

                let config_digest = img.config_digest().to_string();

                // Determine the composefs algorithm from ObjectID::ALGORITHM
                let algorithm = match ObjectID::ALGORITHM {
                    1 => composefs::fsverity::algorithm::SHA256_12,
                    2 => composefs::fsverity::algorithm::SHA512_12,
                    _ => anyhow::bail!("unsupported hash algorithm {}", ObjectID::ALGORITHM),
                };

                // Compute per-layer digests (verifies content hashes since we don't
                // have the config verity readily available from OciImage)
                let per_layer_digests =
                    composefs_oci::compute_per_layer_digests(&repo, &config_digest, None)?;

                // Load signing key
                let cert_pem = std::fs::read(cert).context("failed to read certificate file")?;
                let key_pem = std::fs::read(key).context("failed to read private key file")?;
                let signing_key =
                    composefs_oci::signing::FsVeritySigningKey::from_pem(&cert_pem, &key_pem)?;

                // Build subject descriptor from the source image's manifest
                let manifest_json = img.manifest().to_string()?;
                let subject = oci_spec::image::DescriptorBuilder::default()
                    .media_type(oci_spec::image::MediaType::ImageManifest)
                    .digest(
                        oci_spec::image::Digest::from_str(img.manifest_digest())
                            .context("parsing manifest digest")?,
                    )
                    .size(manifest_json.len() as u64)
                    .build()
                    .context("building subject descriptor")?;

                let mut builder =
                    composefs_oci::signature::SignatureArtifactBuilder::new(algorithm, subject);

                // Sign and add each per-layer digest
                for digest in &per_layer_digests {
                    let sig = signing_key.sign(digest)?;
                    builder.add_entry(composefs_oci::signature::SignatureEntry {
                        sig_type: composefs_oci::signature::SignatureType::Layer,
                        digest: digest.to_hex(),
                        signature: Some(sig),
                    })?;
                }

                // Sign and add the merged digest
                let merged_sig = signing_key.sign(&merged_digest)?;
                builder.add_entry(composefs_oci::signature::SignatureEntry {
                    sig_type: composefs_oci::signature::SignatureType::Merged,
                    digest: merged_digest.to_hex(),
                    signature: Some(merged_sig),
                })?;

                let artifact = builder.build()?;
                let (artifact_digest, _) =
                    composefs_oci::signature::store_signature_artifact(&repo, artifact)?;

                println!("{artifact_digest}");
            }
            OciCommand::Verify {
                ref image,
                ref cert,
            } => {
                let img = composefs_oci::OciImage::open_ref(&repo, image)?;

                let artifacts = composefs_oci::signature::find_signature_artifacts(
                    &repo,
                    img.manifest_digest(),
                )?;

                if artifacts.is_empty() {
                    anyhow::bail!("no signature artifacts found for {image}");
                }

                #[cfg(feature = "signing")]
                if cert.is_some() {
                    anyhow::bail!(
                        "PKCS#7 signature blob verification via --cert is not yet implemented; \
                         use digest-only verification (without --cert) for now"
                    );
                }
                #[cfg(not(feature = "signing"))]
                if cert.is_some() {
                    anyhow::bail!(
                        "PKCS#7 signature verification requires the 'signing' feature; \
                         rebuild with --features signing"
                    );
                }

                // Recompute expected digests
                let config_digest = img.config_digest().to_string();
                let per_layer_digests =
                    composefs_oci::compute_per_layer_digests(&repo, &config_digest, None)?;
                let merged_hex = img.seal_digest().map(|s| s.to_string());

                let mut all_ok = true;

                for artifact in &artifacts {
                    println!("Signature artifact (algorithm: {})", artifact.algorithm);

                    let mut layer_idx = 0usize;
                    for entry in &artifact.entries {
                        let (label, expected_hex) = match entry.sig_type {
                            composefs_oci::signature::SignatureType::Layer => {
                                let lbl = format!("  layer[{layer_idx}]:");
                                let expected = per_layer_digests.get(layer_idx).map(|d| d.to_hex());
                                layer_idx += 1;
                                (lbl, expected)
                            }
                            composefs_oci::signature::SignatureType::Merged => {
                                ("  merged:  ".to_string(), merged_hex.clone())
                            }
                            other => {
                                println!("  {other}: skipped (not verified by this tool)");
                                continue;
                            }
                        };

                        let digest_ok = match &expected_hex {
                            Some(expected) => *expected == entry.digest,
                            None => {
                                print!("{label} no expected digest to compare");
                                println!(" SKIP");
                                all_ok = false;
                                continue;
                            }
                        };

                        if !digest_ok {
                            println!("{label} digest MISMATCH");
                            all_ok = false;
                            continue;
                        }

                        println!("{label} digest matches ✓");
                    }
                }

                if !all_ok {
                    std::process::exit(1);
                }
            }
            OciCommand::Mount {
                ref name,
                ref mountpoint,
            } => {
                composefs_oci::mount(&repo, name, mountpoint, None)?;
            }
            OciCommand::PrepareBoot {
                ref config_name,
                ref config_verity,
                ref bootdir,
                ref entry_id,
                ref cmdline,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                let entries = fs.transform_for_boot(&repo)?;
                let id = fs.commit_image(&repo, None)?;

                let Some(entry) = entries.into_iter().next() else {
                    anyhow::bail!("No boot entries!");
                };

                let cmdline_refs: Vec<&str> = cmdline.iter().map(String::as_str).collect();
                write_boot::write_boot_simple(
                    &repo,
                    entry,
                    &id,
                    args.insecure,
                    bootdir,
                    None,
                    entry_id.as_deref(),
                    &cmdline_refs,
                )?;

                let state = args
                    .repo
                    .as_ref()
                    .map(|p: &PathBuf| p.parent().unwrap())
                    .unwrap_or(Path::new("/sysroot"))
                    .join("state/deploy")
                    .join(id.to_hex());

                create_dir_all(state.join("var"))?;
                create_dir_all(state.join("etc/upper"))?;
                create_dir_all(state.join("etc/work"))?;
            }
        },
        Command::ComputeId { fs_opts } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.compute_image_id();
            println!("{}", id.to_hex());
        }
        Command::CreateImage {
            fs_opts,
            ref image_name,
        } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.commit_image(&repo, image_name.as_deref())?;
            println!("{}", id.to_id());
        }
        Command::CreateDumpfile { fs_opts } => {
            let mut fs = if fs_opts.no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, &fs_opts.path, Some(&repo))?
            } else {
                composefs::fs::read_container_root(CWD, &fs_opts.path, Some(&repo))?
            };
            if fs_opts.bootable {
                fs.transform_for_boot(&repo)?;
            }
            fs.print_dumpfile()?;
        }
        Command::Mount { name, mountpoint } => {
            repo.mount_at(&name, &mountpoint)?;
        }
        Command::ImageObjects { name } => {
            let objects = repo.objects_for_image(&name)?;
            for object in objects {
                println!("{}", object.to_id());
            }
        }
        Command::GC { root, dry_run } => {
            let roots: Vec<&str> = root.iter().map(|s| s.as_str()).collect();
            let result = if dry_run {
                repo.gc_dry_run(&roots)?
            } else {
                repo.gc(&roots)?
            };
            if dry_run {
                println!("Dry run (no files deleted):");
            }
            println!(
                "Objects: {} removed ({} bytes)",
                result.objects_removed, result.objects_bytes
            );
            if result.images_pruned > 0 || result.streams_pruned > 0 {
                println!(
                    "Pruned symlinks: {} images, {} streams",
                    result.images_pruned, result.streams_pruned
                );
            }
        }
        #[cfg(feature = "http")]
        Command::Fetch { url, name } => {
            let (digest, verity) = composefs_http::download(&url, &name, Arc::new(repo)).await?;
            println!("content {digest}");
            println!("verity {}", verity.to_hex());
        }
    }
    Ok(())
}
