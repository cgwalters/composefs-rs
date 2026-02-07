#!/bin/bash
# Test the external openssl CLI workflow for creating fsverity PKCS#7 signatures.
#
# This verifies that the documented openssl signing workflow produces valid
# PKCS#7 signatures over the fsverity_formatted_digest structure, matching
# what the kernel and composefs-rs expect.
set -euo pipefail

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# --- Setup: generate a test keypair ---

openssl req -x509 -newkey rsa:2048 \
    -keyout "$TMPDIR/key.pem" -out "$TMPDIR/cert.pem" \
    -days 1 -nodes -subj '/CN=composefs-test' 2>/dev/null

# --- Test 1: Construct and sign a SHA-256 formatted_digest ---

# A known 32-byte digest (all zeros for simplicity)
DIGEST_SHA256="0000000000000000000000000000000000000000000000000000000000000000"

# Build the fsverity_formatted_digest by hand:
#   magic:  "FSVerity" = 46 53 56 65 72 69 74 79
#   alg:    0x0001 LE  = 01 00
#   size:   0x0020 LE  = 20 00
#   digest: 32 zero bytes
{
    printf '\x46\x53\x56\x65\x72\x69\x74\x79'  # FSVerity
    printf '\x01\x00'                            # algorithm 1 (SHA-256)
    printf '\x20\x00'                            # digest size 32
    echo -n "$DIGEST_SHA256" | xxd -r -p         # raw digest bytes
} > "$TMPDIR/formatted_digest_256.bin"

# Verify the structure is exactly 44 bytes (8 + 2 + 2 + 32)
SIZE=$(wc -c < "$TMPDIR/formatted_digest_256.bin")
if [ "$SIZE" -eq 44 ]; then
    pass "SHA-256 formatted_digest is 44 bytes"
else
    fail "SHA-256 formatted_digest is $SIZE bytes, expected 44"
fi

# Verify the magic bytes
MAGIC=$(head -c 8 "$TMPDIR/formatted_digest_256.bin")
if [ "$MAGIC" = "FSVerity" ]; then
    pass "SHA-256 formatted_digest has correct magic"
else
    fail "SHA-256 formatted_digest has wrong magic: $MAGIC"
fi

# Sign it
openssl smime -sign -binary \
    -in "$TMPDIR/formatted_digest_256.bin" \
    -signer "$TMPDIR/cert.pem" -inkey "$TMPDIR/key.pem" \
    -outform DER -noattr \
    -out "$TMPDIR/sig_256.der" 2>/dev/null

if [ -s "$TMPDIR/sig_256.der" ]; then
    pass "SHA-256 signature produced"
else
    fail "SHA-256 signature is empty or missing"
fi

# Verify it
if openssl smime -verify -binary \
    -in "$TMPDIR/sig_256.der" \
    -content "$TMPDIR/formatted_digest_256.bin" \
    -certfile "$TMPDIR/cert.pem" -CAfile "$TMPDIR/cert.pem" \
    -inform DER -noverify >/dev/null 2>&1; then
    pass "SHA-256 signature verifies"
else
    fail "SHA-256 signature verification failed"
fi

# --- Test 2: Construct and sign a SHA-512 formatted_digest ---

DIGEST_SHA512="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

{
    printf '\x46\x53\x56\x65\x72\x69\x74\x79'  # FSVerity
    printf '\x02\x00'                            # algorithm 2 (SHA-512)
    printf '\x40\x00'                            # digest size 64
    echo -n "$DIGEST_SHA512" | xxd -r -p         # raw digest bytes
} > "$TMPDIR/formatted_digest_512.bin"

SIZE=$(wc -c < "$TMPDIR/formatted_digest_512.bin")
if [ "$SIZE" -eq 76 ]; then
    pass "SHA-512 formatted_digest is 76 bytes"
else
    fail "SHA-512 formatted_digest is $SIZE bytes, expected 76"
fi

openssl smime -sign -binary \
    -in "$TMPDIR/formatted_digest_512.bin" \
    -signer "$TMPDIR/cert.pem" -inkey "$TMPDIR/key.pem" \
    -outform DER -noattr \
    -out "$TMPDIR/sig_512.der" 2>/dev/null

if openssl smime -verify -binary \
    -in "$TMPDIR/sig_512.der" \
    -content "$TMPDIR/formatted_digest_512.bin" \
    -certfile "$TMPDIR/cert.pem" -CAfile "$TMPDIR/cert.pem" \
    -inform DER -noverify >/dev/null 2>&1; then
    pass "SHA-512 signature verifies"
else
    fail "SHA-512 signature verification failed"
fi

# --- Test 3: Wrong digest must fail verification ---

# Flip a byte in the digest to create a different formatted_digest
{
    printf '\x46\x53\x56\x65\x72\x69\x74\x79'
    printf '\x01\x00'
    printf '\x20\x00'
    printf '\xff'  # differs from the all-zeros digest above
    # pad with 31 zero bytes
    printf '\x00%.0s' $(seq 1 31)
} > "$TMPDIR/formatted_digest_wrong.bin"

if openssl smime -verify -binary \
    -in "$TMPDIR/sig_256.der" \
    -content "$TMPDIR/formatted_digest_wrong.bin" \
    -certfile "$TMPDIR/cert.pem" -CAfile "$TMPDIR/cert.pem" \
    -inform DER -noverify >/dev/null 2>&1; then
    fail "Wrong-digest verification should have failed but passed"
else
    pass "Wrong-digest verification correctly rejected"
fi

# --- Test 4: Signature is valid DER-encoded PKCS#7 ---

if openssl pkcs7 -inform DER -in "$TMPDIR/sig_256.der" -noout 2>/dev/null; then
    pass "Signature is valid DER PKCS#7"
else
    fail "Signature is not valid DER PKCS#7"
fi

# --- Summary ---

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
