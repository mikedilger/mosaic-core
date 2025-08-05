#!/bin/bash

rm -rf ./target/doc/
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features --no-deps
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps -p secp256k1
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps -p ed25519-dalek
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps -p mainline
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps -p rand

echo "<meta http-equiv=\"refresh\" content=\"0; url=mosaic_core/index.html\">" > target/doc/index.html
rm -rf ./docs
mv target/doc ./docs
