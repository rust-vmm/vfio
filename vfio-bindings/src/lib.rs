// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: (BSD-3-Clause OR Apache-2.0)

#[cfg(feature = "fam-wrappers")]
#[macro_use]
extern crate vmm_sys_util;

#[cfg(feature = "fam-wrappers")]
mod fam_wrappers;

#[cfg(feature = "vfio-v5_0_0")]
mod vfio_bindings;

// Default to latest version if no version is specified by using the features.
#[cfg(not(feature = "vfio-v5_0_0"))]
mod vfio_bindings;

pub mod bindings {
    #[cfg(feature = "vfio-v5_0_0")]
    pub use super::vfio_bindings::*;

    #[cfg(not(feature = "vfio-v5_0_0"))]
    pub use super::vfio_bindings::*;

    #[cfg(feature = "fam-wrappers")]
    pub use super::fam_wrappers::*;
}
