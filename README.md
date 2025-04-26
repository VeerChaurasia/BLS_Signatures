# BLS Signatures Implementation in Rust

This is my implementation of **BLS Signatures** in Rust, used in Ethereum for cryptographic operations such as key generation, signing, signature aggregation, and verification.

## Features

- **Key Generation**: Generates secret and public key pairs.
- **Signing**: Signs a message using the secret key.
- **Signature Aggregation**: Aggregates multiple signatures into one.
- **Signature Verification**: Verifies the aggregated signature with the public keys.

## Usage

```rust
fn key_generation() -> (SecretKey, PublicKey)
fn signing(sk: &SecretKey, message: &[u8]) -> Signature
fn agg_signatures(signatures: &[Signature]) -> Signature
fn verify_agg_signatures(agg_signatures: &Signature, ps: &[PublicKey], message: &[u8]) -> bool
