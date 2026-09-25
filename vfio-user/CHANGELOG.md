## Upcoming release

## Changed

- [[175]](https://github.com/rust-vmm/vfio/pull/175) Server replies EINVAL to region accesses outside the region or above max_data_xfer_size

## Added

## Fixed

- [[175]](https://github.com/rust-vmm/vfio/pull/175) Client hang on an error reply and panics on malformed VERSION or region info

# [v0.1.6]

## Changed

- Bump `vfio-bindings` to 0.6.3.

# [v0.1.5]

## Added

- [[160]](https://github.com/rust-vmm/vfio/pull/160) construct vfio-user server from owned fd

# [v0.1.4]

## Changed

- [[163]](https://github.com/rust-vmm/vfio/pull/163) Support vm-memory 0.18

# [v0.1.3]

## Changed

- [[128]](https://github.com/rust-vmm/vfio/pull/128) Support vm-memory 0.17

## Added

- [[132]](https://github.com/rust-vmm/vfio/pull/132) Implement sparse mmap capability for Server

## Fixed

- [[134]](https://github.com/rust-vmm/vfio/pull/134) Fix incorrect spec implementation for sparse mmap areas

# [v0.1.2]

### Changed
- [[114]](https://github.com/rust-vmm/vfio/pull/114) Cargo.toml: Update deps to latest version

# [v0.1.1]

## Changed
- Bumped vfio-bindings to 0.6.0

# [v0.1.0]

This is the first `vfio-user` crate release.

This crate provides the client and server support for implementing vfio-user devices.

`vfio-user` is now merged into a single monorepo `vfio`.
