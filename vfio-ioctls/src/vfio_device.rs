// Copyright © 2019 Intel Corporation
// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::any::Any;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::mem::{self, ManuallyDrop};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use byteorder::{ByteOrder, NativeEndian};
#[cfg(feature = "vfio_cdev")]
use iommufd_bindings::*;
#[cfg(feature = "vfio_cdev")]
use iommufd_ioctls::{IommuFd, IommufdHwptData, IommufdVDevice, IommufdVIommu};
use log::{debug, error, warn};
use vfio_bindings::bindings::vfio::*;
use vm_memory::{Address, GuestMemory, GuestMemoryRegion, MemoryRegionAddress};
use vmm_sys_util::eventfd::EventFd;

use crate::fam::vec_with_array_field;
use crate::vfio_ioctls::*;
use crate::{Result, VfioError};
#[cfg(all(feature = "kvm", not(test)))]
use kvm_bindings::{
    kvm_device_attr, KVM_DEV_VFIO_FILE, KVM_DEV_VFIO_FILE_ADD, KVM_DEV_VFIO_FILE_DEL,
};
#[cfg(all(feature = "kvm", not(test)))]
use kvm_ioctls::DeviceFd as KvmDeviceFd;
#[cfg(all(feature = "mshv", not(test)))]
use mshv_bindings::{
    mshv_device_attr, MSHV_DEV_VFIO_FILE, MSHV_DEV_VFIO_FILE_ADD, MSHV_DEV_VFIO_FILE_DEL,
};
#[cfg(all(feature = "mshv", not(test)))]
use mshv_ioctls::DeviceFd as MshvDeviceFd;
#[cfg(all(any(feature = "kvm", feature = "mshv"), not(test)))]
use std::os::unix::io::FromRawFd;
#[cfg(all(any(feature = "kvm", feature = "mshv"), not(test)))]
use vmm_sys_util::errno::Error;

#[derive(Debug)]
enum DeviceFdInner {
    #[cfg(all(feature = "kvm", not(test)))]
    Kvm(KvmDeviceFd),
    #[cfg(all(feature = "mshv", not(test)))]
    Mshv(MshvDeviceFd),
}

#[derive(Debug)]
/// A wrapper for a device fd from either KVM or MSHV.
pub struct VfioDeviceFd(DeviceFdInner);

impl VfioDeviceFd {
    /// Create an VfioDeviceFd from a KVM DeviceFd
    #[cfg(all(feature = "kvm", not(test)))]
    pub fn new_from_kvm(fd: KvmDeviceFd) -> Self {
        VfioDeviceFd(DeviceFdInner::Kvm(fd))
    }
    /// Extract the KVM DeviceFd from an VfioDeviceFd
    #[cfg(all(feature = "kvm", not(test)))]
    pub fn to_kvm(self) -> Result<KvmDeviceFd> {
        match self {
            VfioDeviceFd(DeviceFdInner::Kvm(fd)) => Ok(fd),
            #[allow(unreachable_patterns)]
            _ => Err(VfioError::VfioDeviceFdWrongType),
        }
    }
    /// Create an VfioDeviceFd from an MSHV DeviceFd
    #[cfg(all(feature = "mshv", not(test)))]
    pub fn new_from_mshv(fd: MshvDeviceFd) -> Self {
        VfioDeviceFd(DeviceFdInner::Mshv(fd))
    }
    /// Extract the MSHV DeviceFd from an VfioDeviceFd
    #[cfg(all(feature = "mshv", not(test)))]
    pub fn to_mshv(self) -> Result<MshvDeviceFd> {
        match self {
            VfioDeviceFd(DeviceFdInner::Mshv(fd)) => Ok(fd),
            #[allow(unreachable_patterns)]
            _ => Err(VfioError::VfioDeviceFdWrongType),
        }
    }
    /// Try to duplicate an VfioDeviceFd
    #[cfg(all(any(feature = "kvm", feature = "mshv"), not(test)))]
    pub fn try_clone(&self) -> Result<Self> {
        match &self.0 {
            #[cfg(feature = "kvm")]
            DeviceFdInner::Kvm(fd) => {
                // SAFETY: FFI call to libc
                let dup_fd = unsafe { libc::dup(fd.as_raw_fd()) };
                if dup_fd == -1 {
                    Err(VfioError::VfioDeviceDupFd)
                } else {
                    // SAFETY: dup_fd is a valid device fd for KVM
                    let kvm_fd = unsafe { KvmDeviceFd::from_raw_fd(dup_fd) };
                    Ok(VfioDeviceFd(DeviceFdInner::Kvm(kvm_fd)))
                }
            }
            #[cfg(feature = "mshv")]
            DeviceFdInner::Mshv(fd) => {
                // SAFETY: FFI call to libc
                let dup_fd = unsafe { libc::dup(fd.as_raw_fd()) };
                if dup_fd == -1 {
                    Err(VfioError::VfioDeviceDupFd)
                } else {
                    // SAFETY: dup_fd is a valid device fd for MSHV
                    let mshv_fd = unsafe { MshvDeviceFd::from_raw_fd(dup_fd) };
                    Ok(VfioDeviceFd(DeviceFdInner::Mshv(mshv_fd)))
                }
            }
        }
    }
}

pub type VfioContainerDeviceHandle = Arc<VfioDeviceFd>;

#[repr(C)]
#[derive(Debug, Default)]
// A VFIO region structure with an incomplete array for region
// capabilities information.
//
// When the VFIO_DEVICE_GET_REGION_INFO ioctl returns with
// VFIO_REGION_INFO_FLAG_CAPS flag set, it also provides the size of the region
// capabilities information. This is a kernel hint for us to fetch this
// information by calling the same ioctl, but with the argument size set to
// the region plus the capabilities information array length. The kernel will
// then fill our vfio_region_info_with_cap structure with both the region info
// and its capabilities.
pub struct vfio_region_info_with_cap {
    pub region_info: vfio_region_info,
    cap_info: __IncompleteArrayField<u8>,
}

impl vfio_region_info_with_cap {
    fn from_region_info(region_info: &vfio_region_info) -> Vec<Self> {
        let region_info_size: u32 = mem::size_of::<vfio_region_info>() as u32;
        let cap_len: usize = (region_info.argsz - region_info_size) as usize;

        let mut region_with_cap = vec_with_array_field::<Self, u8>(cap_len);
        region_with_cap[0].region_info.argsz = region_info.argsz;
        region_with_cap[0].region_info.flags = 0;
        region_with_cap[0].region_info.index = region_info.index;
        region_with_cap[0].region_info.cap_offset = 0;
        region_with_cap[0].region_info.size = 0;
        region_with_cap[0].region_info.offset = 0;

        region_with_cap
    }
}
/// Trait to define common operations exposed to user-space drivers for
/// VFIO device wrappers that are either backed by a legacy VfioContainer or
/// a VFIO cdev device using iommufd.
pub trait VfioOps: Any + Send + Sync {
    /// Map a region of user space memory (e.g. guest memory) into an IO
    /// address space managed by IOMMU hardware to enable DMA for
    /// associated VFIO devices
    ///
    /// # Parameters
    /// * iova: IO virtual address to map the memory.
    /// * size: size of the memory region.
    /// * user_addr: user space address (e.g. host virtual address) for
    ///   the guest memory region to map.
    fn vfio_dma_map(&self, _iova: u64, _size: u64, _user_addr: u64) -> Result<()> {
        unimplemented!()
    }

    /// Unmap a region of user space memory (e.g. guest memory) from an IO
    /// address space managed by IOMMU hardware to disable DMA for
    /// associated VFIO devices
    ///
    /// # Parameters
    /// * iova: IO virtual address to unmap the memory.
    /// * size: size of the memory region.
    fn vfio_dma_unmap(&self, _iova: u64, _size: u64) -> Result<()> {
        unimplemented!()
    }

    /// Downcast to the underlying vfio wrapper type
    fn as_any(&self) -> &dyn Any {
        unimplemented!()
    }
}

struct VfioCommon {
    #[allow(dead_code)]
    device_fd: Option<VfioContainerDeviceHandle>,
}

impl VfioCommon {
    #[cfg(all(any(feature = "kvm", feature = "mshv"), not(test)))]
    fn device_set_fd(&self, dev_fd: RawFd, add: bool) -> Result<()> {
        let dev_fd_ptr = &dev_fd as *const i32;

        if let Some(device_fd) = self.device_fd.as_ref() {
            match &device_fd.0 {
                #[cfg(feature = "kvm")]
                DeviceFdInner::Kvm(fd) => {
                    let flag = if add {
                        KVM_DEV_VFIO_FILE_ADD
                    } else {
                        KVM_DEV_VFIO_FILE_DEL
                    };
                    let dev_attr = kvm_device_attr {
                        flags: 0,
                        group: KVM_DEV_VFIO_FILE,
                        attr: u64::from(flag),
                        addr: dev_fd_ptr as u64,
                    };
                    fd.set_device_attr(&dev_attr)
                        .map_err(|e| VfioError::SetDeviceAttr(Error::new(e.errno())))
                }
                #[cfg(feature = "mshv")]
                DeviceFdInner::Mshv(fd) => {
                    let flag = if add {
                        MSHV_DEV_VFIO_FILE_ADD
                    } else {
                        MSHV_DEV_VFIO_FILE_DEL
                    };
                    let dev_attr = mshv_device_attr {
                        flags: 0,
                        group: MSHV_DEV_VFIO_FILE,
                        attr: u64::from(flag),
                        addr: dev_fd_ptr as u64,
                    };
                    fd.set_device_attr(&dev_attr)
                        .map_err(|e| VfioError::SetDeviceAttr(Error::new(e.errno())))
                }
            }
        } else {
            Ok(())
        }
    }

    #[cfg(all(feature = "vfio_cdev", test))]
    fn device_set_fd(&self, _dev_fd: RawFd, _add: bool) -> Result<()> {
        Ok(())
    }
}

/// A safe wrapper over a VFIO container object.
///
/// A VFIO container represents an IOMMU domain, or a set of IO virtual address translation tables.
/// On its own, the container provides little functionality, with all but a couple version and
/// extension query interfaces locked away. The user needs to add a group into the container for
/// the next level of functionality. After some groups are associated with a container, the user
/// can query and set the IOMMU backend, and then build IOVA mapping to access memory.
///
/// Multiple VFIO groups may be associated with the same VFIO container to share the underline
/// address translation mapping tables.
pub struct VfioContainer {
    pub(crate) container: File,
    pub(crate) groups: Mutex<HashMap<u32, Arc<VfioGroup>>>,
    #[allow(dead_code)]
    common: VfioCommon,
}

impl VfioContainer {
    /// Create a container wrapper object.
    ///
    /// # Arguments
    /// * `device_fd`: An optional file handle of the hypervisor VFIO device.
    pub fn new(device_fd: Option<VfioContainerDeviceHandle>) -> Result<Self> {
        let container = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")
            .map_err(VfioError::OpenContainer)?;

        let container = VfioContainer {
            container,
            common: VfioCommon { device_fd },
            groups: Mutex::new(HashMap::new()),
        };
        container.check_api_version()?;
        container.check_extension(VFIO_TYPE1v2_IOMMU)?;

        Ok(container)
    }

    fn check_api_version(&self) -> Result<()> {
        let version = vfio_syscall::check_api_version(self);
        if version as u32 != VFIO_API_VERSION {
            return Err(VfioError::VfioApiVersion);
        }
        Ok(())
    }

    fn check_extension(&self, val: u32) -> Result<()> {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            return Err(VfioError::VfioInvalidType);
        }

        let ret = vfio_syscall::check_extension(self, val)?;
        if ret != 1 {
            return Err(VfioError::VfioExtension);
        }

        Ok(())
    }

    fn set_iommu(&self, val: u32) -> Result<()> {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            return Err(VfioError::VfioInvalidType);
        }

        vfio_syscall::set_iommu(self, val)
    }

    fn get_group(&self, group_id: u32) -> Result<Arc<VfioGroup>> {
        // Safe because there's no legal way to break the lock.
        let mut hash = self.groups.lock().unwrap();
        if let Some(entry) = hash.get(&group_id) {
            return Ok(entry.clone());
        }

        let group = Arc::new(VfioGroup::new(group_id)?);

        // Bind the new group object to the container.
        vfio_syscall::set_group_container(&group, self)?;

        // Initialize the IOMMU backend driver after binding the first group object.
        if hash.is_empty() {
            if let Err(e) = self.set_iommu(VFIO_TYPE1v2_IOMMU) {
                let _ = vfio_syscall::unset_group_container(&group, self);
                return Err(e);
            }
        }

        // Add the new group object to the hypervisor driver.
        #[cfg(any(feature = "kvm", feature = "mshv"))]
        if let Err(e) = self.device_add_group(&group) {
            let _ = vfio_syscall::unset_group_container(&group, self);
            return Err(e);
        }

        hash.insert(group_id, group.clone());

        Ok(group)
    }

    fn put_group(&self, group: Arc<VfioGroup>) {
        // Safe because there's no legal way to break the lock.
        let mut hash = self.groups.lock().unwrap();

        // Clean up the group when the last user releases reference to the group, three reference
        // count for:
        // - one reference cloned in VfioDevice.drop() and passed into here
        // - one reference held by the groups hashmap
        if Arc::strong_count(&group) == 2 {
            #[cfg(any(feature = "kvm", feature = "mshv"))]
            match self.device_del_group(&group) {
                Ok(_) => {}
                Err(e) => {
                    error!("Could not delete VFIO group: {e:?}");
                    return;
                }
            }
            if vfio_syscall::unset_group_container(&group, self).is_err() {
                error!("Could not unbind VFIO group: {:?}", group.id());
                return;
            }
            hash.remove(&group.id());
        }
    }

    /// Map a region of user space memory (e.g. guest memory) into an IO
    /// address space managed by IOMMU hardware to enable DMA for
    /// associated VFIO devices
    ///
    /// # Parameters
    /// * iova: IO virtual address to mapping the memory.
    /// * size: size of the memory region.
    /// * user_addr: host virtual address for the guest memory region to map.
    pub fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        let dma_map = vfio_iommu_type1_dma_map {
            argsz: mem::size_of::<vfio_iommu_type1_dma_map>() as u32,
            flags: VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: user_addr,
            iova,
            size,
        };

        vfio_syscall::map_dma(self, &dma_map)
    }

    /// Unmap a region of user space memory (e.g. guest memory) from an IO
    /// address space managed by IOMMU hardware to disable DMA for
    /// associated VFIO devices
    ///
    /// # Parameters
    /// * iova: IO virtual address to unmap the memory.
    /// * size: size of the memory region.
    pub fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        let mut dma_unmap = vfio_iommu_type1_dma_unmap {
            argsz: mem::size_of::<vfio_iommu_type1_dma_unmap>() as u32,
            flags: 0,
            iova,
            size,
            ..Default::default()
        };

        vfio_syscall::unmap_dma(self, &mut dma_unmap)?;
        if dma_unmap.size != size {
            return Err(VfioError::InvalidDmaUnmapSize);
        }

        Ok(())
    }

    /// Add all guest memory regions into the vfio container's iommu table.
    ///
    /// # Parameters
    /// * mem: pinned guest memory which could be accessed by devices binding to the container.
    pub fn vfio_map_guest_memory<M: GuestMemory>(&self, mem: &M) -> Result<()> {
        mem.iter().try_for_each(|region| {
            let host_addr = region
                .get_host_address(MemoryRegionAddress(0))
                .map_err(|_| VfioError::GetHostAddress)?;
            self.vfio_dma_map(
                region.start_addr().raw_value(),
                region.len(),
                host_addr as u64,
            )
        })
    }

    /// Remove all guest memory regions from the vfio container's iommu table.
    ///
    /// The vfio kernel driver and device hardware couldn't access this guest memory after
    /// returning from the function.
    ///
    /// # Parameters
    /// * mem: pinned guest memory which could be accessed by devices binding to the container.
    pub fn vfio_unmap_guest_memory<M: GuestMemory>(&self, mem: &M) -> Result<()> {
        mem.iter().try_for_each(|region| {
            self.vfio_dma_unmap(region.start_addr().raw_value(), region.len())
        })
    }

    /// Add a device to a VFIO group
    ///
    /// The VFIO device fd should have been set.
    ///
    /// # Parameters
    /// * group: target VFIO group
    #[cfg(all(any(feature = "kvm", feature = "mshv"), not(test)))]
    fn device_add_group(&self, group: &VfioGroup) -> Result<()> {
        self.common.device_set_fd(group.as_raw_fd(), true)
    }

    /// Delete a device from a VFIO group
    ///
    /// The VFIO device fd should have been set.
    ///
    /// # Parameters
    /// * group: target VFIO group
    #[cfg(all(any(feature = "kvm", feature = "mshv"), not(test)))]
    fn device_del_group(&self, group: &VfioGroup) -> Result<()> {
        self.common.device_set_fd(group.as_raw_fd(), false)
    }

    #[cfg(test)]
    fn device_add_group(&self, _group: &VfioGroup) -> Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn device_del_group(&self, _group: &VfioGroup) -> Result<()> {
        Ok(())
    }
}

impl AsRawFd for VfioContainer {
    fn as_raw_fd(&self) -> RawFd {
        self.container.as_raw_fd()
    }
}

impl VfioOps for VfioContainer {
    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        self.vfio_dma_map(iova, size, user_addr)
    }

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        self.vfio_dma_unmap(iova, size)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A safe wrapper over a VFIO group object.
///
/// The Linux VFIO frameworks supports multiple devices per group, and multiple groups per
/// container. But current implementation assumes there's only one device per group to simplify
/// implementation. With such an assumption, the `VfioGroup` becomes an internal implementation
/// details.
pub struct VfioGroup {
    pub(crate) id: u32,
    pub(crate) group: File,
}

impl VfioGroup {
    #[cfg(not(test))]
    fn open_group_file(id: u32) -> Result<File> {
        let group_path = Path::new("/dev/vfio").join(id.to_string());
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(group_path)
            .map_err(|e| VfioError::OpenGroup(e, id.to_string()))
    }

    /// Create a new VfioGroup object.
    ///
    /// # Parameters
    /// * `id`: ID(index) of the VFIO group file.
    fn new(id: u32) -> Result<Self> {
        let group = Self::open_group_file(id)?;
        let mut group_status = vfio_group_status {
            argsz: mem::size_of::<vfio_group_status>() as u32,
            flags: 0,
        };
        vfio_syscall::get_group_status(&group, &mut group_status)?;
        if group_status.flags != VFIO_GROUP_FLAGS_VIABLE {
            return Err(VfioError::GroupViable);
        }

        Ok(VfioGroup { id, group })
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn get_device(&self, name: &Path) -> Result<VfioDeviceInfo> {
        let uuid_osstr = name.file_name().ok_or(VfioError::InvalidPath)?;
        let uuid_str = uuid_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let path: CString = CString::new(uuid_str.as_bytes()).expect("CString::new() failed");
        let device = vfio_syscall::get_group_device_fd(self, &path)?;
        let dev_info = VfioDeviceInfo::get_device_info(&device)?;

        Ok(VfioDeviceInfo::new(device, &dev_info))
    }
}

impl AsRawFd for VfioGroup {
    fn as_raw_fd(&self) -> RawFd {
        self.group.as_raw_fd()
    }
}

/// A safe wrapper over vfio devices backed by vfio cdev using iommufd
#[cfg(feature = "vfio_cdev")]
pub struct VfioIommufd {
    pub(crate) iommufd: Arc<IommuFd>,
    pub(crate) ioas_id: u32,
    common: VfioCommon,
    s1_hwpt_data_type: Option<iommu_hwpt_data_type>,
}

#[cfg(feature = "vfio_cdev")]
impl VfioIommufd {
    /// Create a wrapper object for vfio devices backed by vfio cdev
    /// using iommufd.
    ///
    /// # Arguments
    /// * `iommufd`: the iommufd to be bound with the VFIO device
    /// * `ioas_id`: the IOAS id to be bound with the VFIO device
    /// * `device_fd`: An optional file handle of the hypervisor VFIO device.
    /// * `s1_hwpt_data_type`: An optional IOMMU hardware page table data type.
    ///   - If `None`, nested HWPT is disabled.
    ///   - If `Some`, nested HWPT is enabled with the provided data type.
    pub fn new(
        iommufd: Arc<IommuFd>,
        ioas_id: Option<u32>,
        device_fd: Option<VfioContainerDeviceHandle>,
        s1_hwpt_data_type: Option<iommu_hwpt_data_type>,
    ) -> Result<Self> {
        let ioas_id = match ioas_id {
            Some(ioas_id) => ioas_id,
            None => {
                let mut alloc_data = iommu_ioas_alloc {
                    size: mem::size_of::<iommu_ioas_alloc>() as u32,
                    flags: 0,
                    out_ioas_id: 0,
                };

                iommufd
                    .as_ref()
                    .alloc_iommu_ioas(&mut alloc_data)
                    .map_err(VfioError::NewVfioIommufd)?;

                alloc_data.out_ioas_id
            }
        };

        let vfio_iommufd = VfioIommufd {
            iommufd,
            ioas_id,
            common: VfioCommon { device_fd },
            s1_hwpt_data_type,
        };

        Ok(vfio_iommufd)
    }

    /// Map a region of user space memory (e.g. guest memory) into an IO
    /// address space managed by IOMMU hardware to enable DMA for
    /// associated VFIO devices
    ///
    /// # Parameters
    /// * iova: IO virtual address to map the memory.
    /// * size: size of the memory region.
    /// * user_addr: user space address (e.g. host virtual address) for
    ///   the guest memory region to map.
    pub fn vfio_dma_map(&self, iova: u64, length: u64, user_addr: u64) -> Result<()> {
        let dma_map = iommu_ioas_map {
            size: mem::size_of::<iommu_ioas_map>() as u32,
            flags: iommufd_ioas_map_flags_IOMMU_IOAS_MAP_READABLE
                | iommufd_ioas_map_flags_IOMMU_IOAS_MAP_WRITEABLE
                | iommufd_ioas_map_flags_IOMMU_IOAS_MAP_FIXED_IOVA,
            ioas_id: self.ioas_id,
            __reserved: 0,
            user_va: user_addr,
            length,
            iova,
        };

        self.iommufd
            .map_iommu_ioas(&dma_map)
            .map_err(VfioError::IommufdIoctlError)
    }

    /// Unmap a region of user space memory (e.g. guest memory) from an IO
    /// address space managed by IOMMU hardware to disable DMA for
    /// associated VFIO devices
    ///
    /// # Parameters
    /// * iova: IO virtual address to unmap the memory.
    /// * size: size of the memory region.
    pub fn vfio_dma_unmap(&self, iova: u64, length: u64) -> Result<()> {
        let mut dma_unmap = iommu_ioas_unmap {
            size: mem::size_of::<iommu_ioas_unmap>() as u32,
            ioas_id: self.ioas_id,
            iova,
            length,
        };

        self.iommufd
            .unmap_iommu_ioas(&mut dma_unmap)
            .map_err(VfioError::IommufdIoctlError)?;

        if dma_unmap.length != length {
            return Err(VfioError::InvalidDmaUnmapSize);
        }

        Ok(())
    }
}

#[cfg(feature = "vfio_cdev")]
impl VfioOps for VfioIommufd {
    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        self.vfio_dma_map(iova, size, user_addr)
    }

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        self.vfio_dma_unmap(iova, size)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Represent one area of the sparse mmap
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfioRegionSparseMmapArea {
    /// Offset of mmap'able area within region
    pub offset: u64,
    /// Size of mmap'able area
    pub size: u64,
}

/// List of sparse mmap areas
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VfioRegionInfoCapSparseMmap {
    /// List of areas
    pub areas: Vec<VfioRegionSparseMmapArea>,
}

/// Represent a specific device by providing type and subtype
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfioRegionInfoCapType {
    /// Device type
    pub type_: u32,
    /// Device subtype
    pub subtype: u32,
}

/// Carry NVLink SSA TGT information
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfioRegionInfoCapNvlink2Ssatgt {
    /// TGT value
    pub tgt: u64,
}

/// Carry NVLink link speed information
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfioRegionInfoCapNvlink2Lnkspd {
    /// Link speed value
    pub link_speed: u32,
}

/// List of capabilities that can be related to a region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VfioRegionInfoCap {
    /// Sparse memory mapping type
    SparseMmap(VfioRegionInfoCapSparseMmap),
    /// Capability holding type and subtype
    Type(VfioRegionInfoCapType),
    /// Indicate if the region is mmap'able with the presence of MSI-X region
    MsixMappable,
    /// NVLink SSA TGT
    Nvlink2Ssatgt(VfioRegionInfoCapNvlink2Ssatgt),
    /// NVLink Link Speed
    Nvlink2Lnkspd(VfioRegionInfoCapNvlink2Lnkspd),
}

/// Information about VFIO MMIO region.
#[derive(Clone, Debug)]
pub struct VfioRegion {
    pub(crate) flags: u32,
    pub(crate) size: u64,
    pub(crate) offset: u64,
    pub(crate) caps: Vec<VfioRegionInfoCap>,
}

/// Information about VFIO interrupts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfioIrq {
    /// Flags for irq.
    pub flags: u32,
    /// Staring index.
    pub index: u32,
    /// Number interrupts.
    pub count: u32,
}

pub(crate) struct VfioDeviceInfo {
    device: File,
    flags: u32,
    num_regions: u32,
    num_irqs: u32,
}

impl VfioDeviceInfo {
    #[inline]
    /// Get device type from device_info flags.
    ///
    /// # Parameters
    /// * `flags`: flags field in device_info structure.
    fn get_device_type(flags: &u32) -> u32 {
        // There may be more types of device here later according to vfio_bindings.
        let device_type: u32 = VFIO_DEVICE_FLAGS_PCI
            | VFIO_DEVICE_FLAGS_PLATFORM
            | VFIO_DEVICE_FLAGS_AMBA
            | VFIO_DEVICE_FLAGS_CCW
            | VFIO_DEVICE_FLAGS_AP;

        flags & device_type
    }

    fn get_device_info(device: &File) -> Result<vfio_device_info> {
        let mut dev_info = vfio_device_info {
            argsz: mem::size_of::<vfio_device_info>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
            cap_offset: 0,
            pad: 0,
        };
        vfio_syscall::get_device_info(device, &mut dev_info)?;
        match VfioDeviceInfo::get_device_type(&dev_info.flags) {
            VFIO_DEVICE_FLAGS_PLATFORM => {}
            VFIO_DEVICE_FLAGS_PCI => {
                if dev_info.num_regions < VFIO_PCI_CONFIG_REGION_INDEX + 1
                    || dev_info.num_irqs < VFIO_PCI_MSIX_IRQ_INDEX + 1
                {
                    return Err(VfioError::VfioDeviceGetInfoPCI);
                }
            }
            _ => {
                return Err(VfioError::VfioDeviceGetInfoOther);
            }
        }

        Ok(dev_info)
    }

    fn new(device: File, dev_info: &vfio_device_info) -> Self {
        VfioDeviceInfo {
            device,
            flags: dev_info.flags,
            num_regions: dev_info.num_regions,
            num_irqs: dev_info.num_irqs,
        }
    }

    fn get_irqs(&self) -> Result<HashMap<u32, VfioIrq>> {
        let mut irqs: HashMap<u32, VfioIrq> = HashMap::new();

        for index in 0..self.num_irqs {
            let mut irq_info = vfio_irq_info {
                argsz: mem::size_of::<vfio_irq_info>() as u32,
                flags: 0,
                index,
                count: 0,
            };

            if vfio_syscall::get_device_irq_info(self, &mut irq_info).is_err() {
                warn!("Could not get VFIO IRQ info for index {index:}");
                continue;
            }

            let irq = VfioIrq {
                flags: irq_info.flags,
                index,
                count: irq_info.count,
            };

            debug!("IRQ #{index}");
            debug!("\tflag 0x{:x}", irq.flags);
            debug!("\tindex {}", irq.index);
            debug!("\tcount {}", irq.count);
            irqs.insert(index, irq);
        }

        Ok(irqs)
    }

    fn get_region_map(
        &self,
        region: &mut VfioRegion,
        region_info: &vfio_region_info,
    ) -> Result<()> {
        let region_info_size: u32 = mem::size_of::<vfio_region_info>() as u32;

        if region_info.flags & VFIO_REGION_INFO_FLAG_CAPS == 0
            || region_info.argsz <= region_info_size
        {
            // There is not capabilities information for that region, we can just return.
            return Ok(());
        }

        // There is a capability information for that region, we have to call
        // VFIO_DEVICE_GET_REGION_INFO with a vfio_region_with_cap structure and the hinted size.
        let mut region_with_cap = vfio_region_info_with_cap::from_region_info(region_info);
        vfio_syscall::get_device_region_info_cap(self, &mut region_with_cap)?;

        // region_with_cap[0] may contain different types of structure depending on the capability
        // type, but all of them begin with vfio_info_cap_header in order to identify the capability
        // type, version and if there's another capability after this one.
        // It is safe to convert region_with_cap[0] with an offset of cap_offset into
        // vfio_info_cap_header pointer and access its elements, as long as cap_offset is greater
        // than region_info_size.
        //
        // Safety: following code is safe because we trust data returned by the kernel.
        if region_with_cap[0].region_info.cap_offset >= region_info_size {
            let mut next_cap_offset = region_with_cap[0].region_info.cap_offset;
            let info_ptr = &region_with_cap[0] as *const vfio_region_info_with_cap as *const u8;

            while next_cap_offset >= region_info_size {
                // SAFETY: data structure returned by kernel is trusted.
                let cap_header = unsafe {
                    *(info_ptr.offset(next_cap_offset as isize) as *const vfio_info_cap_header)
                };

                match u32::from(cap_header.id) {
                    VFIO_REGION_INFO_CAP_SPARSE_MMAP => {
                        // SAFETY: data structure returned by kernel is trusted.
                        let sparse_mmap = unsafe {
                            info_ptr.offset(next_cap_offset as isize)
                                as *const vfio_region_info_cap_sparse_mmap
                        };
                        // SAFETY: data structure returned by kernel is trusted.
                        let nr_areas = unsafe { (*sparse_mmap).nr_areas };
                        // SAFETY: data structure returned by kernel is trusted.
                        let areas = unsafe { (*sparse_mmap).areas.as_slice(nr_areas as usize) };

                        let cap = VfioRegionInfoCapSparseMmap {
                            areas: areas
                                .iter()
                                .map(|a| VfioRegionSparseMmapArea {
                                    offset: a.offset,
                                    size: a.size,
                                })
                                .collect(),
                        };
                        region.caps.push(VfioRegionInfoCap::SparseMmap(cap));
                    }
                    VFIO_REGION_INFO_CAP_TYPE => {
                        // SAFETY: data structure returned by kernel is trusted.
                        let type_ = unsafe {
                            *(info_ptr.offset(next_cap_offset as isize)
                                as *const vfio_region_info_cap_type)
                        };
                        let cap = VfioRegionInfoCapType {
                            type_: type_.type_,
                            subtype: type_.subtype,
                        };
                        region.caps.push(VfioRegionInfoCap::Type(cap));
                    }
                    VFIO_REGION_INFO_CAP_MSIX_MAPPABLE => {
                        region.caps.push(VfioRegionInfoCap::MsixMappable);
                    }
                    VFIO_REGION_INFO_CAP_NVLINK2_SSATGT => {
                        // SAFETY: data structure returned by kernel is trusted.
                        let nvlink2_ssatgt = unsafe {
                            *(info_ptr.offset(next_cap_offset as isize)
                                as *const vfio_region_info_cap_nvlink2_ssatgt)
                        };
                        let cap = VfioRegionInfoCapNvlink2Ssatgt {
                            tgt: nvlink2_ssatgt.tgt,
                        };
                        region.caps.push(VfioRegionInfoCap::Nvlink2Ssatgt(cap));
                    }
                    VFIO_REGION_INFO_CAP_NVLINK2_LNKSPD => {
                        // SAFETY: data structure returned by kernel is trusted.
                        let nvlink2_lnkspd = unsafe {
                            *(info_ptr.offset(next_cap_offset as isize)
                                as *const vfio_region_info_cap_nvlink2_lnkspd)
                        };
                        let cap = VfioRegionInfoCapNvlink2Lnkspd {
                            link_speed: nvlink2_lnkspd.link_speed,
                        };
                        region.caps.push(VfioRegionInfoCap::Nvlink2Lnkspd(cap));
                    }
                    _ => {}
                }

                next_cap_offset = cap_header.next;
            }
        }

        Ok(())
    }

    fn get_regions(&self) -> Result<Vec<VfioRegion>> {
        let mut regions: Vec<VfioRegion> = Vec::new();

        for i in VFIO_PCI_BAR0_REGION_INDEX..self.num_regions {
            let argsz: u32 = mem::size_of::<vfio_region_info>() as u32;
            let mut reg_info = vfio_region_info {
                argsz,
                flags: 0,
                index: i,
                cap_offset: 0,
                size: 0,
                offset: 0,
            };

            if let Err(e) = vfio_syscall::get_device_region_info(self, &mut reg_info) {
                match e {
                    // Non-VGA devices do not have the VGA region,
                    // the kernel indicates this by returning -EINVAL,
                    // and it's not an error.
                    VfioError::VfioDeviceGetRegionInfo(e)
                        if e.errno() == libc::EINVAL && i == VFIO_PCI_VGA_REGION_INDEX =>
                    {
                        continue;
                    }
                    _ => {
                        error!("Could not get region #{i} info {e}");
                        continue;
                    }
                }
            }

            let mut region = VfioRegion {
                flags: reg_info.flags,
                size: reg_info.size,
                offset: reg_info.offset,
                caps: Vec::new(),
            };
            if let Err(e) = self.get_region_map(&mut region, &reg_info) {
                error!("Could not get region #{i} map {e}");
                continue;
            }

            debug!("Region #{i}");
            debug!("\tflag 0x{:x}", region.flags);
            debug!("\tsize 0x{:x}", region.size);
            debug!("\toffset 0x{:x}", region.offset);
            regions.push(region);
        }

        Ok(regions)
    }
}

impl AsRawFd for VfioDeviceInfo {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}

/// A safe wrapper over a Vfio device to access underlying hardware device.
///
/// The VFIO device API includes ioctls for describing the device, the I/O regions and their
/// read/write/mmap offsets on the device descriptor, as well as mechanisms for describing and
/// registering interrupt notifications.
pub struct VfioDevice {
    pub(crate) device: ManuallyDrop<File>,
    pub(crate) flags: u32,
    pub(crate) regions: Vec<VfioRegion>,
    pub(crate) irqs: HashMap<u32, VfioIrq>,
    pub(crate) sysfspath: PathBuf,
    pub(crate) vfio_ops: Arc<dyn VfioOps>,
}

impl VfioDevice {
    #[cfg(not(test))]
    fn get_group_id_from_path(sysfspath: &Path) -> Result<u32> {
        let uuid_path: PathBuf = [sysfspath, Path::new("iommu_group")].iter().collect();
        let group_path = uuid_path.read_link().map_err(|_| VfioError::InvalidPath)?;
        let group_osstr = group_path.file_name().ok_or(VfioError::InvalidPath)?;
        let group_str = group_osstr.to_str().ok_or(VfioError::InvalidPath)?;

        group_str.parse::<u32>().map_err(|_| VfioError::InvalidPath)
    }

    #[cfg(feature = "vfio_cdev")]
    fn get_device_cdev_from_path(sysfspath: &Path) -> Result<File> {
        // For the folder structure of vfio cdev, refer:
        // https://docs.kernel.org/driver-api/vfio.html#device-cdev-example
        let vfio_dev_path = sysfspath.join("vfio-dev");

        let file_list: Vec<PathBuf> = vfio_dev_path
            .read_dir()
            .map_err(|_| VfioError::InvalidVfioDev)?
            .filter_map(|entry| Some(entry.ok()?.path()))
            .collect();

        if file_list.len() == 1 && file_list[0].is_dir() {
            let cdev_name = file_list[0].file_name().ok_or(VfioError::InvalidVfioDev)?;
            let device_cdev_path: PathBuf = Path::new("/dev/vfio/devices/").join(cdev_name);

            OpenOptions::new()
                .read(true)
                .write(true)
                .open(device_cdev_path)
                .map_err(VfioError::OpenDeviceCdev)
        } else {
            Err(VfioError::InvalidVfioDev)
        }
    }

    fn get_device_info(sysfspath: &Path, vfio_ops: Arc<dyn VfioOps>) -> Result<VfioDeviceInfo> {
        if let Some(vfio_container) = vfio_ops.as_any().downcast_ref::<VfioContainer>() {
            let group_id = Self::get_group_id_from_path(sysfspath)?;
            let group = vfio_container.get_group(group_id)?;

            return group.get_device(sysfspath);
        }

        #[cfg(feature = "vfio_cdev")]
        if let Some(vfio_iommufd) = vfio_ops.as_any().downcast_ref::<VfioIommufd>() {
            // Open the vfio cdev file
            let device = Self::get_device_cdev_from_path(sysfspath)?;

            // Add the vfio cdev file to VFIO-KVM device tracking
            vfio_iommufd
                .common
                .device_set_fd(device.as_raw_fd(), true)?;

            // Bind the VFIO device to the iommufd file
            let mut bind = vfio_device_bind_iommufd {
                argsz: mem::size_of::<vfio_device_bind_iommufd>() as u32,
                flags: 0,
                iommufd: vfio_iommufd.iommufd.as_raw_fd(),
                out_devid: 0,
            };
            vfio_syscall::bind_device_iommufd(&device, &mut bind)?;

            // Associate the vfio device to the IOAS within the bound iommufd
            let mut attach_data = vfio_device_attach_iommufd_pt {
                argsz: mem::size_of::<vfio_device_attach_iommufd_pt>() as u32,
                flags: 0,
                pt_id: vfio_iommufd.ioas_id,
            };
            vfio_syscall::attach_device_iommufd_pt(&device, &mut attach_data)?;

            let dev_info = VfioDeviceInfo::get_device_info(&device)?;
            let dev_info = VfioDeviceInfo::new(device, &dev_info);

            return Ok(dev_info);
        }

        Err(VfioError::DowncastVfioOps)
    }

    /// Create a new vfio device, then guest read/write on this device could be transferred into kernel vfio.
    ///
    /// # Parameters
    /// * `sysfspath`: specify the vfio device path in sys file system.
    /// * `vfio_ops`: the vfio device wrapper object that the new VFIO device object will bind to.
    pub fn new(sysfspath: &Path, vfio_ops: Arc<dyn VfioOps>) -> Result<Self> {
        let device_info = Self::get_device_info(sysfspath, vfio_ops.clone())?;
        let regions = device_info.get_regions()?;
        let irqs = device_info.get_irqs()?;

        Ok(VfioDevice {
            device: ManuallyDrop::new(device_info.device),
            flags: device_info.flags,
            regions,
            irqs,
            sysfspath: sysfspath.to_path_buf(),
            vfio_ops,
        })
    }

    #[cfg(feature = "vfio_cdev")]
    /// Creates a new VFIO device backed by IOMMUFD.
    ///
    /// This initializes a VFIO device with support for vIOMMU and vDevice abstractions
    /// when nested hardware page tables (HWPT) are configured via the `VfioIommufd` instance.
    ///
    /// # Arguments
    ///
    /// * `sysfspath` - Path to the VFIO device in sysfs.
    ///   * Note: Future versions may support file descriptor interfaces to be more versatile. *
    /// * `vfio_ops` - The VFIO operations wrapper (must be a `VfioIommufd` instance).
    /// * `viommu` - An optional vIOMMU instance.
    ///   - If `None` and nested HWPT is enabled, a new vIOMMU instance is created and returned.
    ///   - If `Some`, the provided instance is reused.
    ///   * Note: The reused vIOMMU must be associated with the same physical IOMMU as this device;
    ///     otherwise, vDevice creation will fail and error will be returned.*
    /// * `virt_sid` - The Virtual Stream ID. This is required if `s1_hwpt_data_type` is
    ///   configured in the `VfioIommufd` instance (i.e., nested HWPT is active).
    ///
    /// # Returns
    ///
    /// A tuple containing the initialized `VfioDevice` and an optional `IommufdVDevice`
    /// (present only when nested HWPT is configured).
    pub fn new_with_iommufd(
        sysfspath: &Path,
        vfio_ops: Arc<dyn VfioOps>,
        viommu: &mut Option<Arc<IommufdVIommu>>,
        virt_sid: Option<u64>,
    ) -> Result<(Self, Option<IommufdVDevice>)> {
        let vfio_iommufd =
            if let Some(vfio_iommufd) = vfio_ops.as_any().downcast_ref::<VfioIommufd>() {
                vfio_iommufd
            } else {
                return Err(VfioError::DowncastVfioOps);
            };

        let (device_info, iommufd_vdevice) = {
            // Open the vfio cdev file
            let device = Self::get_device_cdev_from_path(sysfspath)?;

            // Add the vfio cdev file to VFIO-KVM device tracking
            vfio_iommufd
                .common
                .device_set_fd(device.as_raw_fd(), true)?;

            // Bind the VFIO device to the iommufd file
            let mut bind = vfio_device_bind_iommufd {
                argsz: mem::size_of::<vfio_device_bind_iommufd>() as u32,
                flags: 0,
                iommufd: vfio_iommufd.iommufd.as_raw_fd(),
                out_devid: 0,
            };
            vfio_syscall::bind_device_iommufd(&device, &mut bind)?;

            let iommufd_vdevice = match vfio_iommufd.s1_hwpt_data_type {
                // When no s1 hwpt is used, associate the vfio device to the IOAS within the bound iommufd
                None => {
                    let mut attach_data = vfio_device_attach_iommufd_pt {
                        argsz: mem::size_of::<vfio_device_attach_iommufd_pt>() as u32,
                        flags: 0,
                        pt_id: vfio_iommufd.ioas_id,
                    };
                    vfio_syscall::attach_device_iommufd_pt(&device, &mut attach_data)?;

                    None
                }
                // When s1 hwpt is used, create and attach vIOMMU and vDevice for nested (s1+s2) hwpt setup
                Some(s1_hwpt_data_type) => {
                    let virt_id = if let Some(virt_sid) = virt_sid {
                        virt_sid
                    } else {
                        return Err(VfioError::MissingVirtSid);
                    };

                    let viommu = if let Some(viommu) = viommu {
                        // Reuse the passed in vIOMMU instance if available
                        viommu.clone()
                    } else {
                        // Allocate an instance of vIOMMU for the vfio device if no instance is passed in
                        let new_viommu = IommufdVIommu::new(
                            vfio_iommufd.iommufd.clone(),
                            vfio_iommufd.ioas_id,
                            bind.out_devid,
                            s1_hwpt_data_type,
                        )
                        .map_err(VfioError::NewIommufdVIommu)?;

                        let viommu_arc = Arc::new(new_viommu);
                        *viommu = Some(viommu_arc.clone());

                        viommu_arc
                    };

                    // Allocate an instance of vDevice
                    let vdevice = IommufdVDevice::new(viommu.clone(), bind.out_devid, virt_id)
                        .map_err(VfioError::NewIommufdVDevice)?;

                    // Attach the vfio cdev device to the s1_bypass_hwpt
                    let mut attach_data = vfio_device_attach_iommufd_pt {
                        argsz: mem::size_of::<vfio_device_attach_iommufd_pt>() as u32,
                        flags: 0,
                        pt_id: viommu.bypass_hwpt_id,
                    };
                    vfio_syscall::attach_device_iommufd_pt(&device, &mut attach_data)?;

                    Some(vdevice)
                }
            };

            let dev_info = VfioDeviceInfo::get_device_info(&device)?;
            let dev_info = VfioDeviceInfo::new(device, &dev_info);

            (dev_info, iommufd_vdevice)
        };

        let regions = device_info.get_regions()?;
        let irqs = device_info.get_irqs()?;

        Ok((
            VfioDevice {
                device: ManuallyDrop::new(device_info.device),
                flags: device_info.flags,
                regions,
                irqs,
                sysfspath: sysfspath.to_path_buf(),
                vfio_ops,
            },
            iommufd_vdevice,
        ))
    }

    #[cfg(feature = "vfio_cdev")]
    /// Uninstall s1 hwpt for the vfio device.
    ///// # Parameters
    /// * `vdevice`: the `IommufdVDevice` instance associated with the vfio device.
    /// * `abort`: if true, use s1 abort_hwpt; if false, use s1 bypass_hwpt.
    pub fn uninstall_s1_hwpt(&self, vdevice: &mut IommufdVDevice, abort: bool) -> Result<()> {
        // Attach to bypass hwpt or abort hwpt based on the 'abort' flag
        let hwpt_id = if abort {
            vdevice.viommu.abort_hwpt_id
        } else {
            vdevice.viommu.bypass_hwpt_id
        };
        let mut attach_data = vfio_device_attach_iommufd_pt {
            argsz: mem::size_of::<vfio_device_attach_iommufd_pt>() as u32,
            flags: 0,
            pt_id: hwpt_id,
        };
        vfio_syscall::attach_device_iommufd_pt(&self.device, &mut attach_data)?;

        // Destroy s1 hwpt
        vdevice
            .destroy_s1_hwpt()
            .map_err(VfioError::IommufdS1HwptDestroy)?;

        Ok(())
    }

    #[cfg(feature = "vfio_cdev")]
    /// Install s1 hwpt for the vfio device based on the input hwpt data.
    ////
    /// # Parameters
    /// * `vdevice`: the `IommufdVDevice` instance associated with the vfio device.
    /// * `hwpt_data`: the hwpt data to create s1 hwpt.
    pub fn install_s1_hwpt(
        &self,
        vdevice: &mut IommufdVDevice,
        hwpt_data: &IommufdHwptData,
    ) -> Result<()> {
        // Uninstall existing s1 hwpt if exists
        self.uninstall_s1_hwpt(vdevice, true)?;

        // Create s1 hwpt based on the input data
        let s1_hwpt_id = vdevice
            .allocate_s1_hwpt(hwpt_data)
            .map_err(VfioError::IommufdS1HwptAlloc)?;

        // Attach the vfio device to the newly created s1 hwpt
        let mut attach_data = vfio_device_attach_iommufd_pt {
            argsz: mem::size_of::<vfio_device_attach_iommufd_pt>() as u32,
            flags: 0,
            pt_id: s1_hwpt_id,
        };
        vfio_syscall::attach_device_iommufd_pt(&self.device, &mut attach_data)?;

        Ok(())
    }

    /// VFIO device reset only if the device supports being reset.
    pub fn reset(&self) {
        if self.flags & VFIO_DEVICE_FLAGS_RESET != 0 {
            vfio_syscall::reset(self);
        }
    }

    /// Get information about VFIO IRQs.
    ///
    /// # Arguments
    /// * `irq_index` - The type (INTX, MSI or MSI-X) of interrupts to enable.
    pub fn get_irq_info(&self, irq_index: u32) -> Option<&VfioIrq> {
        self.irqs.get(&irq_index)
    }

    /// Trigger a VFIO device IRQ from userspace.
    ///
    /// Once a signaling mechanism is set, DATA_BOOL or DATA_NONE can be used with ACTION_TRIGGER
    /// to perform kernel level interrupt loopback testing from userspace (ie. simulate hardware
    /// triggering).
    ///
    /// # Arguments
    /// * `irq_index` - The type (INTX, MSI or MSI-X) of interrupts to enable.
    /// * `vector` - The sub-index into the interrupt group of `irq_index`.
    pub fn trigger_irq(&self, irq_index: u32, vector: u32) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceTriggerIrq)?;
        if irq.count <= vector {
            return Err(VfioError::VfioDeviceTriggerIrq);
        }

        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = irq_index;
        irq_set[0].start = vector;
        irq_set[0].count = 1;

        vfio_syscall::set_device_irqs(self, irq_set.as_slice())
            .map_err(|_| VfioError::VfioDeviceTriggerIrq)
    }

    /// Enables a VFIO device IRQs.
    /// This maps a vector of EventFds to all VFIO managed interrupts. In other words, this
    /// tells VFIO which EventFd to write into whenever one of the device interrupt vector
    /// is triggered.
    ///
    /// # Arguments
    /// * `irq_index` - The type (INTX, MSI or MSI-X) of interrupts to enable.
    /// * `event_fds` - The EventFds vector that matches all the supported VFIO interrupts.
    pub fn enable_irq(&self, irq_index: u32, event_fds: Vec<&EventFd>) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceEnableIrq)?;
        if irq.count == 0 || (irq.count as usize) < event_fds.len() {
            return Err(VfioError::VfioDeviceEnableIrq);
        }

        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(event_fds.len());
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32
            + (event_fds.len() * mem::size_of::<u32>()) as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = irq_index;
        irq_set[0].start = 0;
        irq_set[0].count = event_fds.len() as u32;

        {
            // irq_set.data could be none, bool or fd according to flags, so irq_set.data
            // is u8 default, here irq_set.data is a vector of fds as u32, so 4 default u8
            // are combined together as u32 for each fd.
            // SAFETY: It is safe as enough space is reserved through
            // vec_with_array_field(u32)<event_fds.len()>.
            let fds = unsafe {
                irq_set[0]
                    .data
                    .as_mut_slice(event_fds.len() * mem::size_of::<u32>())
            };
            for (index, event_fd) in event_fds.iter().enumerate() {
                let fds_offset = index * mem::size_of::<u32>();
                let fd = &mut fds[fds_offset..fds_offset + mem::size_of::<u32>()];
                NativeEndian::write_u32(fd, event_fd.as_raw_fd() as u32);
            }
        }

        vfio_syscall::set_device_irqs(self, irq_set.as_slice())
            .map_err(|_| VfioError::VfioDeviceEnableIrq)
    }

    /// Sets a VFIO irq's resample fd.
    /// This allows to set the signaling for an ACTION_UNMASK action. Once the resample fd
    /// is set, vfio can auto-unmask the INTX interrupt when the resamplefd is triggered.
    ///
    /// # Arguments
    /// * `irq_index` - INTX (the only type support to set resample fd)
    /// * `event_rfds` - The resample EventFds will be set to vfio.
    pub fn set_irq_resample_fd(&self, irq_index: u32, event_rfds: Vec<&EventFd>) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceSetIrqResampleFd)?;
        // Currently the VFIO driver only support MASK/UNMASK INTX, so count is hard-coded to 1.
        if irq.count != 1
            || (irq.count as usize) < event_rfds.len()
            || irq.index != VFIO_PCI_INTX_IRQ_INDEX
        {
            return Err(VfioError::VfioDeviceSetIrqResampleFd);
        }

        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(event_rfds.len());
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32
            + (event_rfds.len() * mem::size_of::<u32>()) as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_UNMASK;
        irq_set[0].index = irq_index;
        irq_set[0].start = 0;
        irq_set[0].count = event_rfds.len() as u32;

        {
            // irq_set.data could be none, bool or fd according to flags, so irq_set.data
            // is u8 default, here irq_set.data is a vector of fds as u32, so 4 default u8
            // are combined together as u32 for each fd.
            // SAFETY: It is safe as enough space is reserved through
            // vec_with_array_field(u32)<event_fds.len()>.
            let fds = unsafe {
                irq_set[0]
                    .data
                    .as_mut_slice(event_rfds.len() * mem::size_of::<u32>())
            };
            for (index, event_fd) in event_rfds.iter().enumerate() {
                let fds_offset = index * mem::size_of::<u32>();
                let fd = &mut fds[fds_offset..fds_offset + mem::size_of::<u32>()];
                NativeEndian::write_u32(fd, event_fd.as_raw_fd() as u32);
            }
        }

        vfio_syscall::set_device_irqs(self, irq_set.as_slice())
            .map_err(|_| VfioError::VfioDeviceSetIrqResampleFd)
    }

    /// Disables a VFIO device IRQs
    ///
    /// # Arguments
    /// * `irq_index` - The type (INTX, MSI or MSI-X) of interrupts to disable.
    pub fn disable_irq(&self, irq_index: u32) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceDisableIrq)?;
        // Currently the VFIO driver only support MASK/UNMASK INTX, so count is hard-coded to 1.
        if irq.count == 0 {
            return Err(VfioError::VfioDeviceDisableIrq);
        }

        // Individual subindex interrupts can be disabled using the -1 value for DATA_EVENTFD or
        // the index can be disabled as a whole with: flags = (DATA_NONE|ACTION_TRIGGER), count = 0.
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = irq_index;
        irq_set[0].start = 0;
        irq_set[0].count = 0;

        vfio_syscall::set_device_irqs(self, irq_set.as_slice())
            .map_err(|_| VfioError::VfioDeviceDisableIrq)
    }

    /// Unmask IRQ
    ///
    /// # Arguments
    /// * `irq_index` - The type (INTX, MSI or MSI-X) of interrupts to unmask.
    pub fn unmask_irq(&self, irq_index: u32) -> Result<()> {
        let irq = self
            .irqs
            .get(&irq_index)
            .ok_or(VfioError::VfioDeviceUnmaskIrq)?;
        // Currently the VFIO driver only support MASK/UNMASK INTX, so count is hard-coded to 1.
        if irq.count == 0 || irq.count != 1 || irq.index != VFIO_PCI_INTX_IRQ_INDEX {
            return Err(VfioError::VfioDeviceUnmaskIrq);
        }

        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK;
        irq_set[0].index = irq_index;
        irq_set[0].start = 0;
        irq_set[0].count = 1;

        vfio_syscall::set_device_irqs(self, irq_set.as_slice())
            .map_err(|_| VfioError::VfioDeviceUnmaskIrq)
    }

    /// Wrapper to enable MSI IRQs.
    pub fn enable_msi(&self, fds: Vec<&EventFd>) -> Result<()> {
        self.enable_irq(VFIO_PCI_MSI_IRQ_INDEX, fds)
    }

    /// Wrapper to disable MSI IRQs.
    pub fn disable_msi(&self) -> Result<()> {
        self.disable_irq(VFIO_PCI_MSI_IRQ_INDEX)
    }

    /// Wrapper to enable MSI-X IRQs.
    pub fn enable_msix(&self, fds: Vec<&EventFd>) -> Result<()> {
        self.enable_irq(VFIO_PCI_MSIX_IRQ_INDEX, fds)
    }

    /// Wrapper to disable MSI-X IRQs.
    pub fn disable_msix(&self) -> Result<()> {
        self.disable_irq(VFIO_PCI_MSIX_IRQ_INDEX)
    }

    /// Get a region's flag.
    ///
    /// # Arguments
    /// * `index` - The index of memory region.
    pub fn get_region_flags(&self, index: u32) -> u32 {
        match self.regions.get(index as usize) {
            Some(v) => v.flags,
            None => 0,
        }
    }

    /// Get a region's offset.
    ///
    /// # Arguments
    /// * `index` - The index of memory region.
    pub fn get_region_offset(&self, index: u32) -> u64 {
        match self.regions.get(index as usize) {
            Some(v) => v.offset,
            None => 0,
        }
    }

    /// Get a region's size.
    ///
    /// # Arguments
    /// * `index` - The index of memory region.
    pub fn get_region_size(&self, index: u32) -> u64 {
        match self.regions.get(index as usize) {
            Some(v) => v.size,
            None => {
                warn!("get_region_size with invalid index: {index}");
                0
            }
        }
    }

    /// Get region's list of capabilities
    ///
    /// # Arguments
    /// * `index` - The index of memory region.
    pub fn get_region_caps(&self, index: u32) -> Vec<VfioRegionInfoCap> {
        match self.regions.get(index as usize) {
            Some(v) => v.caps.clone(),
            None => {
                warn!("get_region_caps with invalid index: {index}");
                Vec::new()
            }
        }
    }

    /// Read region's data from VFIO device into buf
    ///
    /// # Arguments
    /// * `index`: region num
    /// * `buf`: data destination and buf length is read size
    /// * `addr`: offset in the region
    pub fn region_read(&self, index: u32, buf: &mut [u8], addr: u64) {
        let region: &VfioRegion = match self.regions.get(index as usize) {
            Some(v) => v,
            None => {
                warn!("region read with invalid index: {index}");
                return;
            }
        };

        let size = buf.len() as u64;
        if size > region.size || addr + size > region.size {
            warn!("region read with invalid parameter, add: {addr}, size: {size}");
            return;
        }

        if let Err(e) = self.device.read_exact_at(buf, region.offset + addr) {
            warn!("Failed to read region in index: {index}, addr: {addr}, error: {e}");
        }
    }

    /// Write the data from buf into a vfio device region
    ///
    /// # Arguments
    /// * `index`: region num
    /// * `buf`: data src and buf length is write size
    /// * `addr`: offset in the region
    pub fn region_write(&self, index: u32, buf: &[u8], addr: u64) {
        let stub: &VfioRegion = match self.regions.get(index as usize) {
            Some(v) => v,
            None => {
                warn!("region write with invalid index: {index}");
                return;
            }
        };

        let size = buf.len() as u64;
        if size > stub.size
            || addr + size > stub.size
            || (stub.flags & VFIO_REGION_INFO_FLAG_WRITE) == 0
        {
            warn!("region write with invalid parameter, add: {addr}, size: {size}");
            return;
        }

        if let Err(e) = self.device.write_all_at(buf, stub.offset + addr) {
            warn!("Failed to write region in index: {index}, addr: {addr}, error: {e}");
        }
    }

    /// Return the maximum numner of interrupts a VFIO device can request.
    pub fn max_interrupts(&self) -> u32 {
        let mut max_interrupts = 0;
        let irq_indexes = vec![
            VFIO_PCI_INTX_IRQ_INDEX,
            VFIO_PCI_MSI_IRQ_INDEX,
            VFIO_PCI_MSIX_IRQ_INDEX,
        ];

        for index in irq_indexes {
            if let Some(irq_info) = self.irqs.get(&index) {
                if irq_info.count > max_interrupts {
                    max_interrupts = irq_info.count;
                }
            }
        }

        max_interrupts
    }
}

impl AsRawFd for VfioDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}

impl Drop for VfioDevice {
    fn drop(&mut self) {
        // ManuallyDrop is needed here because we need to ensure that VfioDevice::device is closed
        // before dropping VfioDevice::group, otherwise it will cause EBUSY when putting the
        // group object.
        if let Some(container) = self.vfio_ops.as_any().downcast_ref::<VfioContainer>() {
            // SAFETY: we own the File object.
            unsafe {
                ManuallyDrop::drop(&mut self.device);
            }

            let group_id = Self::get_group_id_from_path(&self.sysfspath).unwrap();
            let group = container.get_group(group_id).unwrap();
            container.put_group(group);
        }

        #[cfg(feature = "vfio_cdev")]
        if let Some(vfio_iommufd) = self.vfio_ops.as_any().downcast_ref::<VfioIommufd>() {
            // Remove the association of the vfio device and its current associated IOAS
            let detach_data = vfio_device_detach_iommufd_pt {
                argsz: mem::size_of::<vfio_device_detach_iommufd_pt>() as u32,
                flags: 0,
            };
            vfio_syscall::detach_device_iommufd_pt(&self.device, &detach_data).unwrap();

            // Remove the vfio cdev file from VFIO-KVM device tracking
            vfio_iommufd
                .common
                .device_set_fd(self.device.as_raw_fd(), false)
                .unwrap();

            // SAFETY: we own the File object.
            unsafe {
                ManuallyDrop::drop(&mut self.device);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    use vmm_sys_util::tempfile::TempFile;

    impl VfioGroup {
        pub(crate) fn open_group_file(id: u32) -> Result<File> {
            let tmp_file = TempFile::new().unwrap();
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(tmp_file.as_path())
                .map_err(|e| VfioError::OpenGroup(e, id.to_string()))
        }
    }

    impl VfioDevice {
        pub(crate) fn get_group_id_from_path(_sysfspath: &Path) -> Result<u32> {
            Ok(3)
        }
    }

    #[test]
    fn test_vfio_region_info_with_cap() {
        let reg = vfio_region_info {
            argsz: 129,
            flags: 0,
            index: 5,
            cap_offset: 0,
            size: 0,
            offset: 0,
        };
        let cap = vfio_region_info_with_cap::from_region_info(&reg);

        assert_eq!(size_of::<vfio_region_info>(), 32);
        assert_eq!(cap.len(), 5);
        assert_eq!(cap[0].region_info.argsz, 129);
        assert_eq!(cap[0].region_info.index, 5);

        let reg = vfio_region_info_with_cap::default();
        assert_eq!(reg.region_info.index, 0);
        assert_eq!(reg.region_info.argsz, 0);
    }

    #[test]
    fn test_vfio_device_info() {
        let tmp_file = TempFile::new().unwrap();
        let device = File::open(tmp_file.as_path()).unwrap();
        let dev_info = vfio_syscall::create_dev_info_for_test();
        let device_info = VfioDeviceInfo::new(device, &dev_info);

        let irqs = device_info.get_irqs().unwrap();
        assert_eq!(irqs.len(), 3);
        let irq = irqs.get(&0).unwrap();
        assert_eq!(irq.flags, VFIO_IRQ_INFO_MASKABLE);
        assert_eq!(irq.count, 1);
        assert_eq!(irq.index, 0);
        let irq = irqs.get(&1).unwrap();
        assert_eq!(irq.flags, VFIO_IRQ_INFO_EVENTFD);
        assert_eq!(irq.count, 32);
        assert_eq!(irq.index, 1);
        let irq = irqs.get(&2).unwrap();
        assert_eq!(irq.flags, VFIO_IRQ_INFO_EVENTFD);
        assert_eq!(irq.count, 2048);
        assert_eq!(irq.index, 2);

        let regions = device_info.get_regions().unwrap();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].flags, 0);
        assert_eq!(regions[0].offset, 0x10000);
        assert_eq!(regions[0].size, 0x1000);
        assert_eq!(regions[0].caps.len(), 0);

        assert_eq!(regions[1].flags, VFIO_REGION_INFO_FLAG_CAPS);
        assert_eq!(regions[1].offset, 0x20000);
        assert_eq!(regions[1].size, 0x2000);
        assert_eq!(regions[1].caps.len(), 3);
        assert_eq!(regions[1].caps[0], VfioRegionInfoCap::MsixMappable);

        let ty = &regions[1].caps[1];
        if let VfioRegionInfoCap::Type(t) = ty {
            assert_eq!(t.type_, 0x5);
            assert_eq!(t.subtype, 0x6);
        } else {
            panic!("expect VfioRegionInfoCapType");
        }

        let mmap = &regions[1].caps[2];
        if let VfioRegionInfoCap::SparseMmap(m) = mmap {
            assert_eq!(m.areas.len(), 1);
            assert_eq!(m.areas[0].size, 0x3);
            assert_eq!(m.areas[0].offset, 0x4);
        } else {
            panic!("expect VfioRegionInfoCapType");
        }
    }

    fn create_vfio_container() -> VfioContainer {
        let tmp_file = TempFile::new().unwrap();
        let container = File::open(tmp_file.as_path()).unwrap();

        VfioContainer {
            container,
            common: VfioCommon { device_fd: None },
            groups: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn test_vfio_container() {
        let container = create_vfio_container();

        assert!(container.as_raw_fd() > 0);
        container.check_api_version().unwrap();
        container.check_extension(VFIO_TYPE1v2_IOMMU).unwrap();

        let group = VfioGroup::new(1).unwrap();
        container.device_add_group(&group).unwrap();
        container.device_del_group(&group).unwrap();

        let group = container.get_group(3).unwrap();
        assert_eq!(Arc::strong_count(&group), 2);
        assert_eq!(container.groups.lock().unwrap().len(), 1);
        let group2 = container.get_group(4).unwrap();
        assert_eq!(Arc::strong_count(&group2), 2);
        assert_eq!(container.groups.lock().unwrap().len(), 2);

        let group3 = container.get_group(3).unwrap();
        assert_eq!(Arc::strong_count(&group), 3);
        let group4 = container.get_group(3).unwrap();
        assert_eq!(Arc::strong_count(&group), 4);
        container.put_group(group4);
        assert_eq!(Arc::strong_count(&group), 3);
        container.put_group(group3);
        assert_eq!(Arc::strong_count(&group), 2);
        container.put_group(group);

        container.vfio_dma_map(0x1000, 0x1000, 0x8000).unwrap();
        container.vfio_dma_map(0x2000, 0x2000, 0x8000).unwrap_err();
        container.vfio_dma_unmap(0x1000, 0x1000).unwrap();
        container.vfio_dma_unmap(0x2000, 0x2000).unwrap_err();
    }

    #[test]
    fn test_vfio_group() {
        let group = VfioGroup::new(1).unwrap();
        let tmp_file = TempFile::new().unwrap();

        assert_eq!(group.id, 1);
        assert!(group.as_raw_fd() >= 0);
        let device = group.get_device(tmp_file.as_path()).unwrap();
        assert_eq!(device.num_irqs, 3);
        assert_eq!(device.num_regions, 9);

        let regions = device.get_regions().unwrap();
        // test code skips VFIO_PCI_VGA_REGION_INDEX
        assert_eq!(regions.len(), 8)
    }

    #[test]
    fn test_vfio_device() {
        let tmp_file = TempFile::new().unwrap();
        let container = Arc::new(create_vfio_container());
        let device = VfioDevice::new(tmp_file.as_path(), container.clone()).unwrap();

        assert!(device.as_raw_fd() > 0);
        assert_eq!(device.max_interrupts(), 2048);

        device.reset();
        assert_eq!(device.regions.len(), 8);
        assert_eq!(device.irqs.len(), 3);

        assert!(device.get_irq_info(3).is_none());
        let irq = device.get_irq_info(2).unwrap();
        assert_eq!(irq.count, 2048);

        device.trigger_irq(3, 0).unwrap_err();
        device.trigger_irq(2, 2048).unwrap_err();
        device.trigger_irq(2, 2047).unwrap();
        device.trigger_irq(2, 0).unwrap();

        device.enable_irq(3, Vec::new()).unwrap_err();
        device.enable_irq(0, Vec::new()).unwrap_err();
        device.enable_irq(1, Vec::new()).unwrap();

        device.set_irq_resample_fd(1, Vec::new()).unwrap_err();
        device.set_irq_resample_fd(0, Vec::new()).unwrap();

        device.disable_irq(3).unwrap_err();
        device.disable_irq(0).unwrap_err();
        device.disable_irq(1).unwrap();

        device.unmask_irq(3).unwrap_err();
        device.unmask_irq(1).unwrap_err();
        device.unmask_irq(0).unwrap();

        device.enable_msi(Vec::new()).unwrap();
        device.disable_msi().unwrap();
        device.enable_msix(Vec::new()).unwrap();
        device.disable_msix().unwrap();

        assert_eq!(device.get_region_flags(1), VFIO_REGION_INFO_FLAG_CAPS);
        assert_eq!(device.get_region_flags(7), 0);
        assert_eq!(device.get_region_flags(8), 0);
        assert_eq!(device.get_region_offset(1), 0x20000);
        assert_eq!(device.get_region_offset(7), 0x80000);
        assert_eq!(device.get_region_offset(8), 0);
        assert_eq!(device.get_region_size(1), 0x2000);
        assert_eq!(device.get_region_size(7), 0x8000);
        assert_eq!(device.get_region_size(8), 0);
        assert_eq!(device.get_region_caps(1).len(), 3);
        assert_eq!(device.get_region_caps(7).len(), 0);
        assert_eq!(device.get_region_caps(8).len(), 0);

        let mut buf = [0u8; 16];
        device.region_read(8, &mut buf, 0x30000);
        device.region_read(7, &mut buf, 0x30000);
        device.region_read(1, &mut buf, 0x30000);
        device.region_write(8, &buf, 0x30000);
        device.region_write(7, &buf, 0x30000);
        device.region_write(1, &buf, 0x30000);

        device.reset();

        drop(device);
        assert_eq!(container.groups.lock().unwrap().len(), 0);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_vfio_region_info_cap() {
        let v1 = VfioRegionInfoCap::Type(VfioRegionInfoCapType {
            type_: 1,
            subtype: 1,
        });
        let v2 = VfioRegionInfoCap::Type(VfioRegionInfoCapType {
            type_: 1,
            subtype: 2,
        });

        assert_eq!(v1, v1.clone());
        assert_ne!(v1, v2);

        let v3 = VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
            areas: vec![VfioRegionSparseMmapArea { offset: 3, size: 4 }],
        });
        let v4 = VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
            areas: vec![VfioRegionSparseMmapArea { offset: 5, size: 6 }],
        });
        assert_eq!(v3, v3.clone());
        assert_ne!(v3, v4);
        assert_ne!(v1, v4);
        assert_ne!(v1.clone(), v4);

        let v5 = VfioRegionInfoCap::MsixMappable;
        assert_eq!(v5, v5.clone());
        assert_ne!(v5, v1);
        assert_ne!(v5, v3);
        assert_ne!(v5, v2.clone());
        assert_ne!(v5, v4.clone());

        let v6 = VfioRegionInfoCap::Nvlink2Lnkspd(VfioRegionInfoCapNvlink2Lnkspd { link_speed: 7 });
        let v7 = VfioRegionInfoCap::Nvlink2Lnkspd(VfioRegionInfoCapNvlink2Lnkspd { link_speed: 8 });
        assert_eq!(v6, v6.clone());
        assert_ne!(v6, v7);
        assert_ne!(v6, v1);
        assert_ne!(v6, v2.clone());
        assert_ne!(v6, v4.clone());

        let v8 = VfioRegionInfoCap::Nvlink2Ssatgt(VfioRegionInfoCapNvlink2Ssatgt { tgt: 9 });
        let v9 = VfioRegionInfoCap::Nvlink2Ssatgt(VfioRegionInfoCapNvlink2Ssatgt { tgt: 10 });
        assert_eq!(v8, v8.clone());
        assert_ne!(v8, v9);
        assert_ne!(v8, v1);
        assert_ne!(v8, v2.clone());
        assert_ne!(v8, v4.clone());
        assert_ne!(v8, v6.clone());
    }

    #[test]
    fn test_vfio_map_guest_memory() {
        let addr1 = GuestAddress(0x1000);
        let mem1 = GuestMemoryMmap::<()>::from_ranges(&[(addr1, 0x1000)]).unwrap();
        let container = create_vfio_container();

        container.vfio_map_guest_memory(&mem1).unwrap();

        let addr2 = GuestAddress(0x3000);
        let mem2 = GuestMemoryMmap::<()>::from_ranges(&[(addr2, 0x1000)]).unwrap();

        container.vfio_unmap_guest_memory(&mem2).unwrap_err();

        let addr3 = GuestAddress(0x1000);
        let mem3 = GuestMemoryMmap::<()>::from_ranges(&[(addr3, 0x2000)]).unwrap();

        container.vfio_unmap_guest_memory(&mem3).unwrap_err();

        container.vfio_unmap_guest_memory(&mem1).unwrap();
    }

    #[test]
    fn test_get_device_type() {
        let flags: u32 = VFIO_DEVICE_FLAGS_PCI;
        assert_eq!(flags, VfioDeviceInfo::get_device_type(&flags));

        let flags: u32 = VFIO_DEVICE_FLAGS_PLATFORM;
        assert_eq!(flags, VfioDeviceInfo::get_device_type(&flags));

        let flags: u32 = VFIO_DEVICE_FLAGS_AMBA;
        assert_eq!(flags, VfioDeviceInfo::get_device_type(&flags));

        let flags: u32 = VFIO_DEVICE_FLAGS_CCW;
        assert_eq!(flags, VfioDeviceInfo::get_device_type(&flags));

        let flags: u32 = VFIO_DEVICE_FLAGS_AP;
        assert_eq!(flags, VfioDeviceInfo::get_device_type(&flags));
    }
}
