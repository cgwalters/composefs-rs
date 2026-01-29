//! Integration test utilities for composefs-rs
//!
//! This library provides utilities for running integration tests.
//! The main test runner is in main.rs.

use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result};

/// Test label for cleanup
pub const INTEGRATION_TEST_LABEL: &str = "composefs-rs.integration-test=1";

/// Get the path to cfsctl binary
pub fn get_cfsctl_path() -> Result<String> {
    // Check environment first
    if let Ok(path) = std::env::var("CFSCTL_PATH") {
        return Ok(path);
    }
    // Look in common locations
    for path in [
        "./target/release/cfsctl",
        "./target/debug/cfsctl",
        "/usr/bin/cfsctl",
    ] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    anyhow::bail!("cfsctl not found; set CFSCTL_PATH or build with `cargo build --release`")
}

/// Get the primary test image
pub fn get_primary_image() -> String {
    std::env::var("COMPOSEFS_RS_PRIMARY_IMAGE")
        .unwrap_or_else(|_| "quay.io/centos-bootc/centos-bootc:stream10".to_string())
}

/// Get all test images
pub fn get_all_images() -> Vec<String> {
    std::env::var("COMPOSEFS_RS_ALL_IMAGES")
        .unwrap_or_else(|_| get_primary_image())
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Captured command output
#[derive(Debug)]
pub struct CapturedOutput {
    /// Exit status
    pub status: ExitStatus,
    /// Captured stdout
    pub stdout: String,
    /// Captured stderr
    pub stderr: String,
}

impl CapturedOutput {
    /// Assert the command succeeded
    pub fn assert_success(&self) -> Result<()> {
        if !self.status.success() {
            anyhow::bail!(
                "Command failed with status {}\nstdout: {}\nstderr: {}",
                self.status,
                self.stdout,
                self.stderr
            );
        }
        Ok(())
    }
}

/// Run a command and capture output
pub fn run_command(cmd: &str, args: &[&str]) -> Result<CapturedOutput> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("Failed to execute: {} {:?}", cmd, args))?;

    Ok(CapturedOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Run cfsctl with arguments
pub fn run_cfsctl(args: &[&str]) -> Result<CapturedOutput> {
    let cfsctl = get_cfsctl_path()?;
    run_command(&cfsctl, args)
}

/// Run bcvk with arguments
pub fn run_bcvk(args: &[&str]) -> Result<CapturedOutput> {
    run_command("bcvk", args)
}
