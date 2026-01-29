//! Integration test runner for composefs-rs
//!
//! This binary runs integration tests using libtest-mimic for nextest compatibility.

use anyhow::Result;
use integration_tests::{get_all_images, run_bcvk, run_cfsctl};
use libtest_mimic::{Arguments, Failed, Trial};

// ============================================================================
// Test implementations
// ============================================================================

fn test_cfsctl_version() -> Result<()> {
    let output = run_cfsctl(&["--version"])?;
    output.assert_success()?;
    assert!(
        output.stdout.contains("cfsctl") || output.stderr.contains("cfsctl"),
        "Version output should mention cfsctl"
    );
    Ok(())
}

fn test_cfsctl_help() -> Result<()> {
    let output = run_cfsctl(&["--help"])?;
    output.assert_success()?;
    assert!(
        output.stdout.contains("Usage") || output.stdout.contains("USAGE"),
        "Help should show usage"
    );
    Ok(())
}

fn test_bcvk_available() -> Result<()> {
    // This test checks if bcvk is available for VM-based tests
    match run_bcvk(&["--version"]) {
        Ok(output) => {
            output.assert_success()?;
            println!("bcvk version: {}", output.stdout.trim());
            Ok(())
        }
        Err(_) => {
            println!("bcvk not available; VM-based tests will be skipped");
            Ok(())
        }
    }
}

// Parameterized test - runs for each image
fn test_image_pull(image: &str) -> Result<()> {
    println!("Would test pulling image: {}", image);
    // In a real test, this would:
    // 1. Pull the image with podman
    // 2. Import it with cfsctl
    // 3. Verify the import
    Ok(())
}

/// All simple integration tests
fn get_simple_tests() -> Vec<(&'static str, fn() -> Result<()>)> {
    vec![
        ("test_cfsctl_version", test_cfsctl_version),
        ("test_cfsctl_help", test_cfsctl_help),
        ("test_bcvk_available", test_bcvk_available),
    ]
}

/// All parameterized tests (run for each image)
fn get_parameterized_tests() -> Vec<(&'static str, fn(&str) -> Result<()>)> {
    vec![("test_image_pull", test_image_pull)]
}

// ============================================================================
// Test harness main
// ============================================================================

fn main() {
    let args = Arguments::from_args();

    let mut trials = Vec::new();

    // Register simple tests
    for (name, test_fn) in get_simple_tests() {
        trials.push(Trial::test(name, move || {
            test_fn().map_err(|e| Failed::from(e.to_string()))
        }));
    }

    // Register parameterized tests
    let images = get_all_images();
    for (name, test_fn) in get_parameterized_tests() {
        for image in &images {
            let test_name = format!("{}::{}", name, image.rsplit('/').next().unwrap_or(image));
            let image = image.clone();
            trials.push(Trial::test(test_name, move || {
                test_fn(&image).map_err(|e| Failed::from(e.to_string()))
            }));
        }
    }

    libtest_mimic::run(&args, trials).exit();
}
