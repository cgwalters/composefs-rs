//! OCI runtime spec generation for `cfsctl oci run`.
//!
//! This module converts an OCI image configuration into an OCI runtime
//! `config.json` bundle that can be consumed by crun or runc.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use oci_spec::image::ImageConfiguration;
use oci_spec::runtime::{
    Linux, LinuxBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType, Mount,
    MountBuilder, Process, ProcessBuilder, Root, RootBuilder, Spec, SpecBuilder,
};

/// Network mode for the container.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum NetworkMode {
    /// Share the host network namespace.
    Host,
    /// Create a private network namespace (no external connectivity).
    None,
}

/// User-supplied overrides that take precedence over the OCI image config.
pub struct RunOverrides {
    /// Container name (used as hostname).
    pub name: String,
    /// Additional `KEY=VALUE` environment variables (appended after image env).
    pub extra_env: Vec<String>,
    /// Network mode.
    pub network: NetworkMode,
    /// Bind mount specs of the form `src:dst` or `src:dst:ro`.
    pub volumes: Vec<String>,
    /// If non-empty, replaces the image CMD (entrypoint is kept).
    pub cmd_override: Vec<String>,
}

/// Parse a volume spec (`src:dst` or `src:dst:ro`) into an OCI [`Mount`].
pub fn parse_volume(vol: &str) -> Result<Mount> {
    let parts: Vec<&str> = vol.splitn(3, ':').collect();
    anyhow::ensure!(
        parts.len() >= 2,
        "volume spec must be in the form src:dst[:ro], got: {vol}"
    );
    let source = parts[0];
    let dest = parts[1];
    let readonly = parts.get(2).map(|s| *s == "ro").unwrap_or(false);

    let mut options = vec![
        "rbind".to_string(),
        "rprivate".to_string(),
    ];
    if readonly {
        options.push("ro".to_string());
    }

    let mount = MountBuilder::default()
        .destination(PathBuf::from(dest))
        .typ("bind".to_string())
        .source(PathBuf::from(source))
        .options(options)
        .build()
        .context("building volume mount")?;
    Ok(mount)
}

/// Parse a `user` string from the OCI image config into `(uid, gid)`.
///
/// Understands `uid`, `uid:gid`, `username` (mapped to 0), etc.
/// For anything that isn't a numeric UID we fall back to 0:0 — proper
/// `/etc/passwd` lookup would require entering the container's rootfs,
/// which is the runtime's job.
fn parse_user(user_str: &str) -> (u32, u32) {
    let parts: Vec<&str> = user_str.splitn(2, ':').collect();
    let uid = parts[0].parse::<u32>().unwrap_or(0);
    let gid = parts
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (uid, gid)
}

/// Build the standard set of Linux mounts (proc, sysfs, devtmpfs, /tmp,
/// devpts).  Volume mounts are appended later.
fn standard_mounts() -> Vec<Mount> {
    vec![
        MountBuilder::default()
            .destination(PathBuf::from("/proc"))
            .typ("proc".to_string())
            .source(PathBuf::from("proc"))
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ])
            .build()
            .expect("proc mount"),
        MountBuilder::default()
            .destination(PathBuf::from("/sys"))
            .typ("sysfs".to_string())
            .source(PathBuf::from("sysfs"))
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "ro".to_string(),
            ])
            .build()
            .expect("sysfs mount"),
        MountBuilder::default()
            .destination(PathBuf::from("/dev"))
            .typ("tmpfs".to_string())
            .source(PathBuf::from("tmpfs"))
            .options(vec![
                "nosuid".to_string(),
                "strictatime".to_string(),
                "mode=755".to_string(),
                "size=65536k".to_string(),
            ])
            .build()
            .expect("devtmpfs mount"),
        MountBuilder::default()
            .destination(PathBuf::from("/dev/pts"))
            .typ("devpts".to_string())
            .source(PathBuf::from("devpts"))
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "newinstance".to_string(),
                "ptmxmode=0666".to_string(),
                "mode=0620".to_string(),
            ])
            .build()
            .expect("devpts mount"),
        MountBuilder::default()
            .destination(PathBuf::from("/dev/shm"))
            .typ("tmpfs".to_string())
            .source(PathBuf::from("shm"))
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                "size=65536k".to_string(),
            ])
            .build()
            .expect("dev/shm mount"),
        MountBuilder::default()
            .destination(PathBuf::from("/tmp"))
            .typ("tmpfs".to_string())
            .source(PathBuf::from("tmpfs"))
            .options(vec![
                "nosuid".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
            ])
            .build()
            .expect("tmp mount"),
    ]
}

/// Build the Linux namespaces list according to the requested network mode.
fn build_namespaces(network: &NetworkMode) -> Vec<LinuxNamespace> {
    let mut ns = vec![
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Pid)
            .build()
            .expect("pid ns"),
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Ipc)
            .build()
            .expect("ipc ns"),
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Uts)
            .build()
            .expect("uts ns"),
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Mount)
            .build()
            .expect("mount ns"),
        LinuxNamespaceBuilder::default()
            .typ(LinuxNamespaceType::Cgroup)
            .build()
            .expect("cgroup ns"),
    ];
    if matches!(network, NetworkMode::None) {
        ns.push(
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .build()
                .expect("network ns"),
        );
    }
    ns
}

/// Generate an OCI runtime [`Spec`] from an OCI image configuration and
/// user overrides.
///
/// The `rootfs` path is stored in `root.path` as an absolute path; the
/// caller is responsible for ensuring the directory exists.
pub fn generate_spec(
    rootfs: &Path,
    image_config: &ImageConfiguration,
    overrides: &RunOverrides,
) -> Result<Spec> {
    // --- Extract fields from the OCI image config ---
    let cfg = image_config.config();

    let image_env: Vec<String> = cfg
        .as_ref()
        .and_then(|c| c.env().as_ref())
        .cloned()
        .unwrap_or_default();

    let entrypoint: Vec<String> = cfg
        .as_ref()
        .and_then(|c| c.entrypoint().as_ref())
        .cloned()
        .unwrap_or_default();

    let image_cmd: Vec<String> = cfg
        .as_ref()
        .and_then(|c| c.cmd().as_ref())
        .cloned()
        .unwrap_or_default();

    let working_dir: String = cfg
        .as_ref()
        .and_then(|c| c.working_dir().as_ref())
        .cloned()
        .unwrap_or_else(|| "/".to_string());

    let user_str: String = cfg
        .as_ref()
        .and_then(|c| c.user().as_ref())
        .cloned()
        .unwrap_or_default();

    // --- Merge env: image env first, overrides second (overrides win) ---
    let mut env = image_env;
    env.extend(overrides.extra_env.iter().cloned());

    // --- Build args: entrypoint + cmd (override replaces image cmd) ---
    let effective_cmd = if overrides.cmd_override.is_empty() {
        image_cmd
    } else {
        overrides.cmd_override.clone()
    };

    let args: Vec<String> = if entrypoint.is_empty() {
        effective_cmd
    } else {
        entrypoint
            .iter()
            .cloned()
            .chain(effective_cmd)
            .collect()
    };

    // Fall back to `sh` if neither entrypoint nor cmd is set.
    let args = if args.is_empty() {
        vec!["sh".to_string()]
    } else {
        args
    };

    // --- Parse user ---
    let (uid, gid) = if user_str.is_empty() {
        (0u32, 0u32)
    } else {
        parse_user(&user_str)
    };

    // --- Build process ---
    let user = oci_spec::runtime::UserBuilder::default()
        .uid(uid)
        .gid(gid)
        .build()
        .context("building process user")?;

    let process: Process = ProcessBuilder::default()
        .terminal(false)
        .user(user)
        .args(args)
        .env(env)
        .cwd(PathBuf::from(&working_dir))
        .no_new_privileges(true)
        // Use the oci-spec default capability set (AuditWrite, Kill, NetBindService)
        .capabilities(oci_spec::runtime::LinuxCapabilities::default())
        .build()
        .context("building process spec")?;

    // --- Build root ---
    let root: Root = RootBuilder::default()
        .path(rootfs.to_path_buf())
        .readonly(true)
        .build()
        .context("building root spec")?;

    // --- Build mounts ---
    let mut mounts = standard_mounts();
    for vol in &overrides.volumes {
        mounts.push(parse_volume(vol)?);
    }

    // --- Build Linux section ---
    let namespaces = build_namespaces(&overrides.network);

    let linux: Linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .masked_paths(oci_spec::runtime::get_default_maskedpaths())
        .readonly_paths(oci_spec::runtime::get_default_readonly_paths())
        .build()
        .context("building linux spec")?;

    // --- Build final spec ---
    let spec: Spec = SpecBuilder::default()
        .version("1.0.2-dev".to_string())
        .root(root)
        .process(process)
        .hostname(overrides.name.clone())
        .mounts(mounts)
        .linux(linux)
        .build()
        .context("building OCI runtime spec")?;

    Ok(spec)
}

/// Write an OCI runtime bundle to `bundle_dir`.
///
/// Creates `bundle_dir` if it does not exist and writes `config.json`
/// inside it.  The `rootfs` subdirectory is expected to be created and
/// mounted separately by the caller before invoking the runtime.
pub fn write_bundle(bundle_dir: &Path, spec: &Spec) -> Result<()> {
    std::fs::create_dir_all(bundle_dir)
        .with_context(|| format!("creating bundle directory: {}", bundle_dir.display()))?;

    let config_path = bundle_dir.join("config.json");
    let file = std::fs::File::create(&config_path)
        .with_context(|| format!("creating config.json at {}", config_path.display()))?;

    serde_json::to_writer_pretty(file, spec)
        .with_context(|| format!("serializing config.json at {}", config_path.display()))?;

    Ok(())
}
