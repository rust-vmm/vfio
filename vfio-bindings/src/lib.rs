// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: (BSD-3-Clause OR Apache-2.0)

#[cfg(feature = "fam-wrappers")]
#[macro_use]
extern crate vmm_sys_util;

#[cfg(feature = "fam-wrappers")]
mod fam_wrappers;

mod vfio_bindings;

pub mod bindings {
    pub use super::vfio_bindings::*;

    #[cfg(feature = "fam-wrappers")]
    pub use super::fam_wrappers::*;
}
