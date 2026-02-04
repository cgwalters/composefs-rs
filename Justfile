# Justfile for composefs-rs
# Run `just --list` to see available targets.
# --------------------------------------------------------------------

mod bootc

# Default tmpdir for tests that need fs-verity support
# In CI on GHA, this should be set to /run/host/var/tmp
export CFS_TEST_TMPDIR := env("CFS_TEST_TMPDIR", "")

# --------------------------------------------------------------------
# Build targets
# --------------------------------------------------------------------

# Build all crates
build:
    cargo build --workspace

# Build in release mode
build-release:
    cargo build --workspace --release

# --------------------------------------------------------------------
# Test targets
# --------------------------------------------------------------------

# Run unit tests (cargo test)
test:
    cargo test --workspace

# Run unit tests with verbose output
test-verbose:
    cargo test --workspace --verbose

# Run the integration test binary (crates/integration-tests)
test-integration:
    cargo run -p integration-tests --bin integration-tests

# Run the composefs-setup-root shell test (requires unshare -Umr)
# Usage: just test-setup-root /path/to/tmpdir
test-setup-root tmpdir:
    #!/bin/bash
    set -euo pipefail
    if [ ! -d "{{tmpdir}}" ]; then
        echo "Error: tmpdir '{{tmpdir}}' does not exist"
        exit 1
    fi
    echo "Running composefs-setup-root test in {{tmpdir}}"
    echo "Note: This requires root in a user namespace. Running via unshare..."
    cargo build -p composefs --bin composefs-setup-root
    unshare -Umr crates/composefs/tests/test.sh "{{tmpdir}}"

# Run VM-based example tests
# Usage: just test-example <example-dir> <os>
# Example: just test-example bls fedora
test-example example os:
    #!/bin/bash
    set -euo pipefail
    cd examples
    echo "Building example {{example}} for {{os}}..."
    "{{example}}/build" "{{os}}"
    echo "Running pytest tests..."
    TEST_IMAGE="{{example}}/{{os}}-{{example}}-efi.qcow2" pytest test

# Run all VM example tests (matrix from CI)
test-examples-all:
    #!/bin/bash
    set -euo pipefail
    # Subset of the GHA matrix that makes sense for local testing
    examples=(
        "bls:fedora"
        "bls:arch"
        "uki:fedora"
        "unified:fedora"
    )
    for pair in "${examples[@]}"; do
        IFS=':' read -r dir os <<< "$pair"
        echo "=== Testing $dir/$os ==="
        just test-example "$dir" "$os"
    done

# --------------------------------------------------------------------
# Lint and format targets
# --------------------------------------------------------------------

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings

# Run rustfmt check
fmt-check:
    cargo fmt --all -- --check

# Format code
fmt:
    cargo fmt --all

# Check workspace package validity (requires nightly)
package-check:
    cargo +nightly -Z package-workspace package --allow-dirty

# --------------------------------------------------------------------
# Combined targets
# --------------------------------------------------------------------

# Run all checks (clippy + fmt + test) - matches what CI runs
check: clippy fmt-check test

# Run the full CI suite locally (excluding VM tests which need special setup)
ci: build clippy fmt-check test-verbose

# Run the full CI suite including package check (requires nightly)
ci-full: ci package-check

# --------------------------------------------------------------------
# Utility targets
# --------------------------------------------------------------------

# Clean build artifacts
clean:
    cargo clean

# Show test configuration
test-config:
    #!/bin/bash
    echo "Test Configuration"
    echo "=================="
    echo "CFS_TEST_TMPDIR: ${CFS_TEST_TMPDIR:-<not set>}"
    echo ""
    echo "Available test targets:"
    echo "  just test            - Run cargo tests"
    echo "  just test-verbose    - Run cargo tests (verbose)"
    echo "  just test-integration - Run integration test binary"
    echo "  just test-setup-root <tmpdir> - Run setup-root test (needs unshare)"
    echo "  just test-example <dir> <os>  - Run single VM example test"
    echo "  just test-examples-all        - Run all VM example tests"
    echo ""
    echo "For CI:"
    echo "  just ci              - Run full CI suite (no VM tests)"
    echo "  just ci-full         - Run full CI suite + package check (needs nightly)"
