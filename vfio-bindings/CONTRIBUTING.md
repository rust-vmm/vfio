# Contributing to vfio-bindings

## Dependencies

### Bindgen
The bindings are currently generated using
[bindgen](https://crates.io/crates/bindgen) version 0.71.1:

```bash
cargo install bindgen-cli --vers 0.71.1
```

### Linux Kernel
Generating bindings depends on the Linux kernel, so you need to have the
repository on your machine:

```bash
git clone https://github.com/torvalds/linux.git
```

## Example for adding a new version

For this example we assume that you have both linux and vfio-bindings
repositories in your root and we will use linux version v5.2 as example.

```bash
# linux is the repository that you cloned previously.
cd linux

# Step 1: Checkout the version you want to generate the bindings for.
git checkout v5.2

# Step 2: Generate the bindings from the kernel headers.
make headers_install INSTALL_HDR_PATH=vfio_headers
cd vfio_headers
bindgen include/linux/vfio.h -o vfio.rs \
    --impl-debug --with-derive-default  \
    --with-derive-partialeq  --impl-partialeq \
    -- -Iinclude

cd ~

# Step 3: Copy the generated files to the new version module.
cp linux/vfio_headers/vfio.rs vfio-bindings/src/vfio_bindings
```
