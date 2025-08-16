## Upcoming release

### Changed

- [[111]](https://github.com/rust-vmm/vfio/pull/111) vfio-ioctls: upgrade mshv-bindings and mshv-ioctls

# [v0.5.0]

## Changed

- [[86]](https://github.com/rust-vmm/vfio/pull/86) Upgrade vmm sys utils to v0.14.0
- [[87]](https://github.com/rust-vmm/vfio/pull/87) vfio-ioctls: Upgrade kvm-ioctl & kvm-bindings crates
- [[88]](https://github.com/rust-vmm/vfio/pull/88) Bump thiserror to latest version

# [v0.4.0]

## Added

- Enable support for Microsoft Hyper-V.
- `VfioError` now propagates the underlying error for more error
  types.
- Many structs now derive `Eq` where it makes sense.
- Added `VfioDevice::set_irq_resample_fd` to unmask level-triggered
  IRQs via an eventfd.

## Changed

- We skipped to version 0.4.0 to harmonize versions with
  `vfio-bindings`.
- The device handle in `VfioContainer::new` has become optional.
- Device file descriptors have their own type (`VfioDeviceFd`) to hide
  the underlying hypervisor-specific types.
- Fixed file descriptor handling on big endian architectures.
- Avoid logging errors for querying VGA regions for devices that don't
  have them.

# [v0.1.0]

This is the first `vfio-ioctl` crate release.

This crate provides higher-level abstractions for the
[Virtual Function I/O (VFIO)](https://www.kernel.org/doc/Documentation/vfio.txt)
Linux kernel API.
