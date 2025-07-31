# vfio-bindings

## Design

The vfio-bindings crate is designed as rust FFI bindings to vfio
generated using [bindgen](https://crates.io/crates/bindgen).

Currently the bindings are generated from Linux kernel version v6.6.0.

## Usage

First, add the following to your Cargo.toml:
```toml
vfio-bindings = "0.5"
```

Next, to use this bindings, you can do:
```rust
use vfio_bindings::bindings::vfio::*;
```

## License

This code is licensed under Apache-2.0 or BSD-3-Clause.
