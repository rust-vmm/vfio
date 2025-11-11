## Upcoming Release

## Changed

## Fixed

## Added

# [v0.6.1]

## Changed

- [[114]](https://github.com/rust-vmm/vfio/pull/114) Cargo.toml: Update deps to latest version

# [v0.6.0]

## Changed

- [[101]](https://github.com/rust-vmm/vfio/pull/101) Disable multi-version support
- [[104]](https://github.com/rust-vmm/vfio/pull/104) Regenerate vfio-bindings with the Linux kernel v6.6.0

# [v0.5.0]

## Fixed

- [[85]](https://github.com/rust-vmm/vfio/pull/85) Fix file permissions

## Changed

- [[86]](https://github.com/rust-vmm/vfio/pull/86) Upgrade vmm sys utils to v0.14.0
- [[91]](https://github.com/rust-vmm/vfio/pull/91) vfio-bindings: Regenerate bindings using new bindgen-cli

# [v0.4.0]

## Added

- Update vmm-sys-util to ">=0.12.1"

# [v0.3.1]

- Update repository to https://github.com/rust-vmm/vfio

# [v0.3.0]

## Added

- Update vmm-sys-util version to ">=0.8.0"

# [v0.2.0]

## Added

- Add FAM wrappers for vfio\_irq\_set
- Update vmm-sys-util version to ">=0.2.0"

# [v0.1.0]

This is the first `vfio-bindings` crate release.

This crate provides Rust FFI bindings to the
[Virtual Function I/O (VFIO)](https://www.kernel.org/doc/Documentation/vfio.txt)
Linux kernel API. With this first release, the bindings are for the Linux kernel
version 5.0.

The bindings are generated using [bindgen](https://crates.io/crates/bindgen).
