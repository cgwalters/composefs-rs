//! Cleanup utility for integration tests
//!
//! Removes containers and VMs created during integration testing.

use std::process::Command;

use anyhow::{Context, Result};

const INTEGRATION_TEST_LABEL: &str = "composefs-rs.integration-test=1";

fn cleanup_podman_containers() -> Result<()> {
    println!(
        "Cleaning up podman containers with label: {}",
        INTEGRATION_TEST_LABEL
    );

    let output = Command::new("podman")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label={}", INTEGRATION_TEST_LABEL),
            "-q",
        ])
        .output()
        .context("Failed to list containers")?;

    let container_ids: Vec<&str> = std::str::from_utf8(&output.stdout)?
        .lines()
        .filter(|s| !s.is_empty())
        .collect();

    if container_ids.is_empty() {
        println!("No containers to clean up");
        return Ok(());
    }

    println!("Removing {} containers...", container_ids.len());

    for id in container_ids {
        let _ = Command::new("podman").args(["rm", "-f", id]).output();
    }

    Ok(())
}

fn cleanup_bcvk_vms() -> Result<()> {
    // Check if bcvk is available
    if Command::new("bcvk").arg("--version").output().is_err() {
        println!("bcvk not available; skipping VM cleanup");
        return Ok(());
    }

    println!("Checking for bcvk VMs to clean up...");

    let output = Command::new("bcvk")
        .args(["libvirt", "list"])
        .output()
        .context("Failed to list bcvk VMs")?;

    let stdout = std::str::from_utf8(&output.stdout)?;

    // Look for VMs that might be from our tests
    for line in stdout.lines() {
        if line.contains("composefs") {
            let vm_name = line.split_whitespace().next();
            if let Some(name) = vm_name {
                println!("Removing VM: {}", name);
                let _ = Command::new("bcvk").args(["libvirt", "rm", name]).output();
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("=== Integration Test Cleanup ===");

    if let Err(e) = cleanup_podman_containers() {
        eprintln!("Warning: Failed to clean up containers: {}", e);
    }

    if let Err(e) = cleanup_bcvk_vms() {
        eprintln!("Warning: Failed to clean up VMs: {}", e);
    }

    println!("Cleanup complete");
    Ok(())
}
