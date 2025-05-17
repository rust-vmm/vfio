# vfio_user

## Design

This crate provides the client and server support for implementing vfio-user devices. More details of vfio-user can be found in the [protocol specification](https://github.com/nutanix/libvfio-user/blob/master/docs/vfio-user.rst).

## Usage

There are two structs:

* `Client` provides a vfio-user client (the part that sits in the VMM)
* `Server` provides a vfio-user server (the part that implements the device)

## Examples

The examples directory contains a sample PCI device implementing a GPIO controller. It can be compiled with `cargo build --examples`

## Licence

This crate is licensed under the Apache 2.0 licence. The full text can be found
in the LICENSE-APACHE file.
