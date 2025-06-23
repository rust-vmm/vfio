// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: (BSD-3-Clause OR Apache-2.0)

#[cfg(all(feature = "vfio-v5_0_0", feature = "vfio-v6_6_0"))]
compile_error!(
    "Features 'vfio-v5_0_0' and 'vfio-v6_6_0' are mutually exclusive. Please enable only one."
);
#[cfg(all(not(feature = "vfio-v5_0_0"), not(feature = "vfio-v6_6_0")))]
compile_error!(
    "Features 'vfio-v5_0_0' and 'vfio-v6_6_0' are not enabled. Please enable one (and only one)."
);

#[cfg(feature = "fam-wrappers")]
#[macro_use]
extern crate vmm_sys_util;

#[cfg(feature = "fam-wrappers")]
mod fam_wrappers;

#[cfg(feature = "vfio-v5_0_0")]
mod bindings_v5_0_0;

#[cfg(feature = "vfio-v6_6_0")]
mod bindings_v6_6_0;

pub mod bindings {
    #[cfg(feature = "vfio-v5_0_0")]
    pub use super::bindings_v5_0_0::*;

    #[cfg(feature = "vfio-v6_6_0")]
    pub use super::bindings_v6_6_0::*;

    #[cfg(feature = "fam-wrappers")]
    pub use super::fam_wrappers::*;
}
