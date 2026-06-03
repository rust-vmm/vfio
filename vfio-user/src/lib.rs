// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use bitflags::bitflags;
use libc::{c_void, iovec, EINVAL};
use libc::{sysconf, _SC_PAGESIZE};
use std::ffi::CString;
use std::fs::File;
use std::io::{IoSlice, Read, Write};
use std::mem::size_of;
use std::num::Wrapping;
use std::os::unix::{
    io::{FromRawFd, RawFd},
    net::{UnixListener, UnixStream},
};
use std::path::{Path, PathBuf};
use thiserror::Error;
use vfio_bindings::bindings::vfio::*;
use vm_memory::{ByteValued, FileOffset};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

#[allow(dead_code)]
#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, enumn::N)]
pub enum Command {
    #[default]
    Unknown = 0,
    Version = 1,
    DmaMap = 2,
    DmaUnmap = 3,
    DeviceGetInfo = 4,
    DeviceGetRegionInfo = 5,
    GetRegionIoFds = 6,
    GetIrqInfo = 7,
    SetIrqs = 8,
    RegionRead = 9,
    RegionWrite = 10,
    DmaRead = 11,
    DmaWrite = 12,
    DeviceReset = 13,
    UserDirtyPages = 14, // legacy v1 dirty pages (unsupported; superseded by DeviceFeature DMA logging)
    // Migration v2 (the kernel VFIO device-feature uAPI mirrored over the vfio-user wire).
    DeviceFeature = 16, // MIG_DEVICE_STATE get/set + DMA_LOGGING_START/STOP/REPORT
    MigDataRead = 17,   // read serialized device state (STOP_COPY / PRE_COPY)
    MigDataWrite = 18,  // write serialized device state (RESUMING)
}

// vfio-user migration-v2 wire constants. The eight device-state values are absent from vfio-bindings
// (kernel ioctl bindings), so they are defined here; the capability flags are u64 to match the
// `vfio_user_device_feature_migration.flags` wire field. Values match libvfio-user include/vfio-user.h.
/// Device migration states (the v2 FSM), shared by backends and clients.
pub const VFIO_DEVICE_STATE_ERROR: u32 = 0;
pub const VFIO_DEVICE_STATE_STOP: u32 = 1;
pub const VFIO_DEVICE_STATE_RUNNING: u32 = 2;
pub const VFIO_DEVICE_STATE_STOP_COPY: u32 = 3;
pub const VFIO_DEVICE_STATE_RESUMING: u32 = 4;
pub const VFIO_DEVICE_STATE_RUNNING_P2P: u32 = 5;
pub const VFIO_DEVICE_STATE_PRE_COPY: u32 = 6;
pub const VFIO_DEVICE_STATE_PRE_COPY_P2P: u32 = 7;
/// DeviceFeature flag bits.
pub const VFIO_DEVICE_FEATURE_GET: u32 = 1 << 16;
pub const VFIO_DEVICE_FEATURE_SET: u32 = 1 << 17;
pub const VFIO_DEVICE_FEATURE_PROBE: u32 = 1 << 18;
pub const VFIO_DEVICE_FEATURE_MASK: u32 = 0xffff;
/// DeviceFeature feature indices.
pub const VFIO_DEVICE_FEATURE_MIGRATION: u32 = 1;
pub const VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE: u32 = 2;
pub const VFIO_DEVICE_FEATURE_DMA_LOGGING_START: u32 = 6;
pub const VFIO_DEVICE_FEATURE_DMA_LOGGING_STOP: u32 = 7;
pub const VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT: u32 = 8;
/// VFIO_DEVICE_FEATURE_MIGRATION capability flags (which states a device supports).
pub const VFIO_MIGRATION_STOP_COPY: u64 = 1 << 0;
pub const VFIO_MIGRATION_P2P: u64 = 1 << 1;
pub const VFIO_MIGRATION_PRE_COPY: u64 = 1 << 2;

// Upper bounds on wire-controlled allocations in the migration dispatch (a client controls these
// sizes). The server rejects anything larger with InvalidInput rather than allocating it.
const MAX_MIG_DATA_SIZE: usize = 8 << 20; // bytes per MIG_DATA chunk
const MAX_DMA_LOG_BITMAP: usize = 64 << 20; // dirty-bitmap bytes per report (~8 TiB at 4 KiB pages)

#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum HeaderFlags {
    #[default]
    Command = 0,
    Reply = 1,
    NoReply = 1 << 4,
    Error = 1 << 5,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Header {
    message_id: u16,
    command: u16,
    message_size: u32,
    flags: u32,
    error: u32,
}

impl Header {
    fn no_reply(&self) -> bool {
        self.flags & HeaderFlags::NoReply as u32 != 0
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Version {
    header: Header,
    major: u16,
    minor: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct MigrationCapabilities {
    pgsize: u32,
}

const fn default_max_msg_fds() -> u32 {
    1
}

const fn default_max_data_xfer_size() -> u32 {
    1048576
}

#[inline(always)]
fn pagesize() -> u32 {
    // SAFETY: sysconf
    unsafe { sysconf(_SC_PAGESIZE) as u32 }
}

fn default_migration_capabilities() -> MigrationCapabilities {
    MigrationCapabilities { pgsize: pagesize() }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DmaMapFlags: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();

        // There might be unknown bits and we don't want bitflags to clear them.
        const _ = !0;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DmaUnmapFlags: u32 {
        const GET_DIRTY_PAGE_INFO = 1 << 1;
        const UNMAP_ALL = 1 << 2;

        // See above.
        const _ = !0;
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaMap {
    header: Header,
    argsz: u32,
    flags: u32,
    offset: u64,
    address: u64,
    size: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaUnmap {
    header: Header,
    argsz: u32,
    flags: u32,
    address: u64,
    size: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceGetInfo {
    header: Header,
    argsz: u32,
    flags: u32,
    num_regions: u32,
    num_irqs: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceGetRegionInfo {
    header: Header,
    region_info: vfio_region_info,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct RegionAccess {
    header: Header,
    offset: u64,
    region: u32,
    count: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct GetIrqInfo {
    header: Header,
    argsz: u32,
    flags: u32,
    index: u32,
    count: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct SetIrqs {
    header: Header,
    argsz: u32,
    flags: u32,
    index: u32,
    start: u32,
    count: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceReset {
    header: Header,
}

// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for Header {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for Version {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DmaMap {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DmaUnmap {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DeviceGetInfo {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DeviceGetRegionInfo {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for RegionAccess {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for GetIrqInfo {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for SetIrqs {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DeviceReset {}

// Migration v2 wire payloads (after the 16-byte Header). Layouts match libvfio-user
// include/vfio-user.h byte-for-byte.
/// `struct vfio_user_device_feature { u32 argsz; u32 flags; u8 data[] }` (data follows on the wire).
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DeviceFeatureHdr {
    header: Header,
    argsz: u32, // size of (this feature struct without `header`) + trailing data
    flags: u32, // feature index (low 16) | GET/SET/PROBE
}
/// `struct vfio_user_device_feature_migration { u64 flags }`.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct FeatureMigration {
    flags: u64,
}
/// `struct vfio_user_device_feature_mig_state { u32 device_state; u32 data_fd }` (data_fd unused on vfio-user).
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct FeatureMigState {
    device_state: u32,
    data_fd: u32,
}
/// `struct vfio_user_device_feature_dma_logging_control { u64 page_size; u32 num_ranges; u32 reserved }`.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaLoggingControl {
    page_size: u64,
    num_ranges: u32,
    reserved: u32,
}
/// `struct vfio_user_device_feature_dma_logging_range { u64 iova; u64 length }`.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaLoggingRange {
    iova: u64,
    length: u64,
}
/// `struct vfio_user_device_feature_dma_logging_report { u64 iova; u64 length; u64 page_size; u8 bitmap[] }`.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DmaLoggingReport {
    iova: u64,
    length: u64,
    page_size: u64,
}
/// `struct vfio_user_mig_data { u32 argsz; u32 size; u8 data[] }`.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct MigData {
    header: Header,
    argsz: u32,
    size: u32,
}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DeviceFeatureHdr {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for FeatureMigration {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for FeatureMigState {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DmaLoggingControl {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DmaLoggingRange {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for DmaLoggingReport {}
// SAFETY: data structure only contain a series of integers
unsafe impl ByteValued for MigData {}

#[derive(Serialize, Deserialize, Debug)]
struct Capabilities {
    #[serde(default = "default_max_msg_fds")]
    max_msg_fds: u32,
    #[serde(default = "default_max_data_xfer_size")]
    max_data_xfer_size: u32,
    #[serde(default = "default_migration_capabilities")]
    migration: MigrationCapabilities,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct CapabilitiesData {
    capabilities: Capabilities,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            max_msg_fds: default_max_msg_fds(),
            max_data_xfer_size: default_max_data_xfer_size(),
            migration: default_migration_capabilities(),
        }
    }
}

pub struct Client {
    stream: UnixStream,
    next_message_id: Wrapping<u16>,
    num_irqs: u32,
    resettable: bool,
    regions: Vec<Region>,
}

#[derive(Debug)]
pub struct Region {
    pub flags: u32,
    pub index: u32,
    pub size: u64,
    pub file_offset: Option<FileOffset>,
    pub sparse_areas: Vec<vfio_region_sparse_mmap_area>,
}

#[derive(Clone, Copy, Debug)]
pub struct IrqInfo {
    pub index: u32,
    pub flags: u32,
    pub count: u32,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error connecting: {0}")]
    Connect(#[source] std::io::Error),
    #[error("Error serializing capabilities: {0}")]
    SerializeCapabilites(#[source] serde_json::Error),
    #[error("Error deserializing capabilities: {0}")]
    DeserializeCapabilites(#[source] serde_json::Error),
    #[error("Error writing to stream: {0}")]
    StreamWrite(#[source] std::io::Error),
    #[error("Error reading from stream: {0}")]
    StreamRead(#[source] std::io::Error),
    #[error("Error shutting down stream: {0}")]
    StreamShutdown(#[source] std::io::Error),
    #[error("Error writing with file descriptors: {0}")]
    SendWithFd(#[source] vmm_sys_util::errno::Error),
    #[error("Error reading with file descriptors: {0}")]
    ReceiveWithFd(#[source] vmm_sys_util::errno::Error),
    #[error("Not a PCI device")]
    NotPciDevice,
    #[error("Socket path already exists")]
    SocketPathExists,
    #[error("Error binding to socket: {0}")]
    SocketBind(#[source] std::io::Error),
    #[error("Error accepting connection: {0}")]
    SocketAccept(#[source] std::io::Error),
    #[error("Unknown command: {0}")]
    UnknownCommand(u16),
    #[error("Unsupported command: {0:?}")]
    UnsupportedCommand(Command),
    #[error("Unsupported feature")]
    UnsupportedFeature,
    #[error("Error from backend: {0:?}")]
    Backend(#[source] std::io::Error),
    #[error("Remote returned error {0}")]
    RemoteError(u32),
    #[error("Invalid input")]
    InvalidInput,
    #[error("No_reply bit unexpectedly set for command: {0:?}")]
    UnexpectedNoReply(Command),
}

impl Client {
    pub fn new(path: &Path) -> Result<Client, Error> {
        let stream = UnixStream::connect(path).map_err(Error::Connect)?;

        let mut client = Client {
            next_message_id: Wrapping(0),
            stream,
            num_irqs: 0,
            resettable: false,
            regions: Vec::new(),
        };

        client.negotiate_version()?;

        client.regions = client.get_regions()?;

        Ok(client)
    }

    fn negotiate_version(&mut self) -> Result<(), Error> {
        let caps = CapabilitiesData::default();

        let version_data = serde_json::to_string(&caps).map_err(Error::SerializeCapabilites)?;

        let version = Version {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::Version as u16,
                flags: HeaderFlags::Command as u32,
                message_size: (size_of::<Version>() + version_data.len() + 1) as u32,
                ..Default::default()
            },
            major: 0,
            minor: 1,
        };
        debug!("Command: {version:?}");

        let version_data = CString::new(version_data.as_bytes()).unwrap();
        let bufs = vec![
            IoSlice::new(version.as_slice()),
            IoSlice::new(version_data.as_bytes_with_nul()),
        ];

        // TODO: Use write_all_vectored() when ready
        let _ = self
            .stream
            .write_vectored(&bufs)
            .map_err(Error::StreamWrite)?;

        debug!(
            "Sent client version information: major = {} minor = {} capabilities = {:?}",
            version.major, version.minor, &caps.capabilities
        );

        self.next_message_id += Wrapping(1);

        let mut server_version: Version = Version::default();
        self.stream
            .read_exact(server_version.as_mut_slice())
            .map_err(Error::StreamRead)?;

        debug!("Reply: {server_version:?}");

        let mut server_version_data =
            vec![0; server_version.header.message_size as usize - size_of::<Version>()];
        self.stream
            .read_exact(server_version_data.as_mut_slice())
            .map_err(Error::StreamRead)?;

        let server_caps: CapabilitiesData =
            serde_json::from_slice(&server_version_data[0..server_version_data.len() - 1])
                .map_err(Error::DeserializeCapabilites)?;

        debug!(
            "Received server version information: major = {} minor = {} capabilities = {:?}",
            server_version.major, server_version.minor, &server_caps.capabilities
        );

        Ok(())
    }

    pub fn dma_map(
        &mut self,
        offset: u64,
        address: u64,
        size: u64,
        fd: RawFd,
    ) -> Result<(), Error> {
        let dma_map = DmaMap {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DmaMap as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DmaMap>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<DmaMap>() - size_of::<Header>()) as u32,
            flags: DmaMapFlags::READ_WRITE.bits(),
            offset,
            address,
            size,
        };
        debug!("Command: {dma_map:?}");
        self.next_message_id += Wrapping(1);
        self.stream
            .send_with_fd(dma_map.as_slice(), fd)
            .map_err(Error::SendWithFd)?;

        let mut reply = Header::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");

        Ok(())
    }

    pub fn dma_unmap(&mut self, address: u64, size: u64) -> Result<(), Error> {
        let dma_unmap = DmaUnmap {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DmaUnmap as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DmaUnmap>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<DmaUnmap>() - size_of::<Header>()) as u32,
            flags: 0,
            address,
            size,
        };
        debug!("Command: {dma_unmap:?}");
        self.next_message_id += Wrapping(1);
        self.stream
            .write_all(dma_unmap.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = DmaUnmap::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");

        Ok(())
    }

    // Migration v2 client API (drives the device-state FSM + DMA logging over the socket).
    /// Send a VFIO_USER_DEVICE_FEATURE command and return the reply's feature payload. `out_len` is
    /// the expected reply payload size (for a GET): `argsz` is sized to cover it, since a conforming
    /// peer rejects the request if `argsz` is smaller than the reply it would send.
    fn device_feature(
        &mut self,
        flags: u32,
        data: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let body = size_of::<DeviceFeatureHdr>() - size_of::<Header>();
        let cmd = DeviceFeatureHdr {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DeviceFeature as u16,
                flags: HeaderFlags::Command as u32,
                message_size: (size_of::<DeviceFeatureHdr>() + data.len()) as u32,
                ..Default::default()
            },
            argsz: (body + data.len().max(out_len)) as u32,
            flags,
        };
        self.next_message_id += Wrapping(1);
        // Send header and payload as one write: libvfio-user's server reads a request body with a
        // single recv() and rejects a partial read, so it must arrive as one contiguous chunk.
        let mut req = cmd.as_slice().to_vec();
        req.extend_from_slice(data);
        self.stream.write_all(&req).map_err(Error::StreamWrite)?;
        // Read the header first: an error reply is header-only, so it must not be parsed as a body.
        let mut hdr = Header::default();
        self.stream
            .read_exact(hdr.as_mut_slice())
            .map_err(Error::StreamRead)?;
        let rest = (hdr.message_size as usize).saturating_sub(size_of::<Header>());
        let mut rest_buf = vec![0u8; rest];
        self.stream
            .read_exact(&mut rest_buf)
            .map_err(Error::StreamRead)?;
        if hdr.flags & HeaderFlags::Error as u32 != 0 || hdr.error != 0 {
            return Err(Error::RemoteError(hdr.error));
        }
        // rest_buf = [argsz u32][flags u32][payload]; strip the device-feature header.
        Ok(rest_buf.get(body..).unwrap_or(&[]).to_vec())
    }

    /// Query supported migration flags (VFIO_MIGRATION_*); a backend that isn't migratable errors.
    pub fn query_migration(&mut self) -> Result<u64, Error> {
        let p = self.device_feature(
            VFIO_DEVICE_FEATURE_MIGRATION | VFIO_DEVICE_FEATURE_GET,
            &[],
            size_of::<FeatureMigration>(),
        )?;
        Ok(FeatureMigration::from_slice(
            p.get(..size_of::<FeatureMigration>())
                .ok_or(Error::InvalidInput)?,
        )
        .ok_or(Error::InvalidInput)?
        .flags)
    }
    /// Transition the device to a VFIO_DEVICE_STATE_* value.
    pub fn set_device_state(&mut self, state: u32) -> Result<(), Error> {
        let st = FeatureMigState {
            device_state: state,
            data_fd: 0,
        };
        self.device_feature(
            VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE | VFIO_DEVICE_FEATURE_SET,
            st.as_slice(),
            0,
        )?;
        Ok(())
    }
    /// Read the current device migration state.
    pub fn get_device_state(&mut self) -> Result<u32, Error> {
        let p = self.device_feature(
            VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE | VFIO_DEVICE_FEATURE_GET,
            &[],
            size_of::<FeatureMigState>(),
        )?;
        Ok(FeatureMigState::from_slice(
            p.get(..size_of::<FeatureMigState>())
                .ok_or(Error::InvalidInput)?,
        )
        .ok_or(Error::InvalidInput)?
        .device_state)
    }
    /// Start DMA dirty logging over the given IOVA ranges at `page_size`.
    pub fn dma_logging_start(
        &mut self,
        page_size: u64,
        ranges: &[(u64, u64)],
    ) -> Result<(), Error> {
        let mut data = Vec::new();
        data.extend_from_slice(
            DmaLoggingControl {
                page_size,
                num_ranges: ranges.len() as u32,
                reserved: 0,
            }
            .as_slice(),
        );
        for (iova, length) in ranges {
            data.extend_from_slice(
                DmaLoggingRange {
                    iova: *iova,
                    length: *length,
                }
                .as_slice(),
            );
        }
        self.device_feature(
            VFIO_DEVICE_FEATURE_DMA_LOGGING_START | VFIO_DEVICE_FEATURE_SET,
            &data,
            0,
        )?;
        Ok(())
    }
    /// Stop DMA dirty logging.
    pub fn dma_logging_stop(&mut self) -> Result<(), Error> {
        self.device_feature(
            VFIO_DEVICE_FEATURE_DMA_LOGGING_STOP | VFIO_DEVICE_FEATURE_SET,
            &[],
            0,
        )?;
        Ok(())
    }
    /// Report-and-clear the dirty bitmap for [iova, iova+length) (1 bit per page_size, LSB-first).
    pub fn dma_logging_report(
        &mut self,
        iova: u64,
        length: u64,
        page_size: u64,
    ) -> Result<Vec<u8>, Error> {
        let req = DmaLoggingReport {
            iova,
            length,
            page_size,
        };
        let bitmap_bytes = (length.div_ceil(page_size.max(1)) as usize).div_ceil(8);
        let p = self.device_feature(
            VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT | VFIO_DEVICE_FEATURE_GET,
            req.as_slice(),
            size_of::<DmaLoggingReport>() + bitmap_bytes,
        )?;
        Ok(p.get(size_of::<DmaLoggingReport>()..)
            .unwrap_or(&[])
            .to_vec())
    }
    /// Read one chunk of serialized device state into `buf`. Returns bytes read; a short fill
    /// (return value < `buf.len()`, including 0) marks end-of-stream per the vfio-user MIG_DATA
    /// contract — callers must stop once they see one.
    pub fn read_migration_data(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let cmd = MigData {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::MigDataRead as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<MigData>() as u32,
                ..Default::default()
            },
            // argsz must cover the reply (body + up to `size` bytes), or a peer rejects the request.
            argsz: (size_of::<MigData>() - size_of::<Header>() + buf.len()) as u32,
            size: buf.len() as u32,
        };
        self.next_message_id += Wrapping(1);
        self.stream
            .write_all(cmd.as_slice())
            .map_err(Error::StreamWrite)?;
        // Header first so an error reply (header-only) is not parsed as MIG_DATA.
        let mut hdr = Header::default();
        self.stream
            .read_exact(hdr.as_mut_slice())
            .map_err(Error::StreamRead)?;
        let rest = (hdr.message_size as usize).saturating_sub(size_of::<Header>());
        let mut rest_buf = vec![0u8; rest];
        self.stream
            .read_exact(&mut rest_buf)
            .map_err(Error::StreamRead)?;
        if hdr.flags & HeaderFlags::Error as u32 != 0 || hdr.error != 0 {
            return Err(Error::RemoteError(hdr.error));
        }
        // rest_buf = [argsz u32][size u32][data...]; the byte count is at offset 4.
        let size = u32::from_le_bytes(
            rest_buf
                .get(4..8)
                .ok_or(Error::InvalidInput)?
                .try_into()
                .unwrap(),
        ) as usize;
        let n = size.min(buf.len());
        buf[..n].copy_from_slice(rest_buf.get(8..8 + n).ok_or(Error::InvalidInput)?);
        Ok(n)
    }
    /// Write one chunk of serialized device state.
    pub fn write_migration_data(&mut self, buf: &[u8]) -> Result<(), Error> {
        let cmd = MigData {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::MigDataWrite as u16,
                flags: HeaderFlags::Command as u32,
                message_size: (size_of::<MigData>() + buf.len()) as u32,
                ..Default::default()
            },
            argsz: (size_of::<MigData>() - size_of::<Header>() + buf.len()) as u32,
            size: buf.len() as u32,
        };
        self.next_message_id += Wrapping(1);
        // One write (header + data): the server reads the body with a single recv() that rejects a
        // partial read, so the message must arrive contiguously.
        let mut req = cmd.as_slice().to_vec();
        req.extend_from_slice(buf);
        self.stream.write_all(&req).map_err(Error::StreamWrite)?;
        let mut reply = Header::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        let rest = (reply.message_size as usize).saturating_sub(size_of::<Header>());
        if rest > 0 {
            let mut drain = vec![0u8; rest];
            self.stream
                .read_exact(&mut drain)
                .map_err(Error::StreamRead)?;
        }
        if reply.flags & HeaderFlags::Error as u32 != 0 || reply.error != 0 {
            return Err(Error::RemoteError(reply.error));
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), Error> {
        let reset = DeviceReset {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DeviceReset as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DeviceReset>() as u32,
                ..Default::default()
            },
        };
        debug!("Command: {reset:?}");
        self.next_message_id += Wrapping(1);
        self.stream
            .write_all(reset.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = Header::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");

        Ok(())
    }

    fn get_regions(&mut self) -> Result<Vec<Region>, Error> {
        let get_info = DeviceGetInfo {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DeviceGetInfo as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<DeviceGetInfo>() as u32,
                ..Default::default()
            },
            argsz: size_of::<DeviceGetInfo>() as u32,
            ..Default::default()
        };
        debug!("Command: {get_info:?}");
        self.next_message_id += Wrapping(1);

        self.stream
            .write_all(get_info.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = DeviceGetInfo::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");
        self.num_irqs = reply.num_irqs;

        if reply.flags & VFIO_DEVICE_FLAGS_PCI != VFIO_DEVICE_FLAGS_PCI {
            return Err(Error::NotPciDevice);
        }

        self.resettable = reply.flags & VFIO_DEVICE_FLAGS_RESET != VFIO_DEVICE_FLAGS_RESET;

        let num_regions = reply.num_regions;
        let mut regions = Vec::new();
        for index in 0..num_regions {
            let (region_info, fd, sparse_areas) = self.get_region_info(index)?;
            regions.push(Region {
                flags: region_info.flags,
                index: region_info.index,
                size: region_info.size,
                file_offset: fd.map(|fd| FileOffset::new(fd, region_info.offset)),
                sparse_areas,
            });
        }

        Ok(regions)
    }

    fn get_region_info(
        &mut self,
        index: u32,
    ) -> Result<
        (
            vfio_region_info,
            Option<File>,
            Vec<vfio_region_sparse_mmap_area>,
        ),
        Error,
    > {
        // Retrieve the region info without capability
        let mut get_region_info = DeviceGetRegionInfo {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::DeviceGetRegionInfo as u16,
                flags: HeaderFlags::Command as u32,
                message_size: std::mem::size_of::<DeviceGetRegionInfo>() as u32,
                ..Default::default()
            },
            region_info: vfio_region_info {
                argsz: size_of::<vfio_region_info>() as u32,
                index,
                ..Default::default()
            },
        };
        debug!("Command: {get_region_info:?}");
        self.next_message_id += Wrapping(1);

        self.stream
            .write_all(get_region_info.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = DeviceGetRegionInfo::default();
        let (_, fd) = self
            .stream
            .recv_with_fd(reply.as_mut_slice())
            .map_err(Error::ReceiveWithFd)?;
        debug!("Reply: {reply:?}");

        // Retrieve the region info again with capabilities if needed
        if reply.region_info.argsz > std::mem::size_of::<vfio_region_info>() as u32 {
            get_region_info.region_info.argsz = reply.region_info.argsz;
            debug!("Command: {get_region_info:?}");
            self.next_message_id += Wrapping(1);

            self.stream
                .write_all(get_region_info.as_slice())
                .map_err(Error::StreamWrite)?;

            let mut reply = DeviceGetRegionInfo::default();
            let (_, fd) = self
                .stream
                .recv_with_fd(reply.as_mut_slice())
                .map_err(Error::ReceiveWithFd)?;
            debug!("Reply: {reply:?}");

            let cap_size = reply.region_info.argsz - std::mem::size_of::<vfio_region_info>() as u32;
            assert_eq!(
                cap_size,
                reply.header.message_size - size_of::<DeviceGetRegionInfo>() as u32
            );
            let mut cap_data = vec![0; cap_size as usize];
            self.stream
                .read_exact(cap_data.as_mut_slice())
                .map_err(Error::StreamRead)?;

            let sparse_areas = Self::parse_region_caps(&cap_data, &reply.region_info)?;

            Ok((reply.region_info, fd, sparse_areas))
        } else {
            Ok((reply.region_info, fd, Vec::new()))
        }
    }

    fn parse_region_caps(
        cap_data: &[u8],
        region_info: &vfio_region_info,
    ) -> Result<Vec<vfio_region_sparse_mmap_area>, Error> {
        let mut sparse_areas: Vec<vfio_region_sparse_mmap_area> = Vec::new();

        let cap_size = cap_data.len() as u32;
        let cap_header_size = size_of::<vfio_info_cap_header>() as u32;
        let mmap_cap_size = size_of::<vfio_region_info_cap_sparse_mmap>() as u32;
        let mmap_area_size = size_of::<vfio_region_sparse_mmap_area>() as u32;

        let cap_data_ptr = cap_data.as_ptr();
        let mut region_info_offset = region_info.cap_offset;
        while region_info_offset != 0 {
            // calculate the offset from the begining of the cap_data based on the offset
            // that is relative to the begining of the VFIO region info structure
            let cap_offset = region_info_offset - size_of::<vfio_region_info>() as u32;
            if cap_offset + cap_header_size > cap_size {
                warn!(
                    "Unexpected end of cap data: 'cap_offset + cap_header_size > cap_size' \
                cap_offset = {cap_offset}, cap_header_size = {cap_header_size}, cap_size = {cap_size}"
                );
                break;
            }

            // SAFETY: `cap_data_ptr` is valid and the `cap_offset` is checked above
            let cap_ptr = unsafe { cap_data_ptr.offset(cap_offset as isize) };
            // SAFETY: `cap_ptr` is valid
            let cap_header = unsafe { &*(cap_ptr as *const vfio_info_cap_header) };
            match cap_header.id as u32 {
                VFIO_REGION_INFO_CAP_SPARSE_MMAP => {
                    if cap_offset + mmap_cap_size > cap_size {
                        warn!(
                            "Unexpected end of cap data: 'cap_offset + mmap_cap_size > cap_size' \
                        cap_offset = {cap_offset}, mmap_cap_size = {mmap_cap_size}, cap_size = {cap_size}"
                        );
                        break;
                    }
                    // SAFETY: `cap_ptr` is valid and its size is also checked above
                    let sparse_mmap = unsafe {
                        &*(cap_ptr as *mut u8 as *const vfio_region_info_cap_sparse_mmap)
                    };

                    let area_num = sparse_mmap.nr_areas;
                    if cap_offset + mmap_cap_size + area_num * mmap_area_size > cap_size {
                        warn!("Unexpected end of cap data: 'cap_offset + mmap_cap_size + area_num * mmap_area_size > cap_size' \
                        cap_offset = {cap_offset}, mmap_cap_size = {mmap_area_size}, area_num = {area_num}, mmap_area_size = {mmap_area_size}, cap_size = {cap_size}");
                        break;
                    }
                    let areas =
                        // SAFETY: `sparse_mmap` is valid and its size is also checked above
                        unsafe { sparse_mmap.areas.as_slice(sparse_mmap.nr_areas as usize) };
                    for area in areas.iter() {
                        sparse_areas.push(*area);
                    }
                }
                _ => {
                    warn!(
                        "Ignoring unsupported vfio region capability (id = '{}')",
                        cap_header.id
                    );
                }
            }
            region_info_offset = cap_header.next;
        }

        Ok(sparse_areas)
    }

    pub fn region_read(&mut self, region: u32, offset: u64, data: &mut [u8]) -> Result<(), Error> {
        let region_read = RegionAccess {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::RegionRead as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<RegionAccess>() as u32,
                ..Default::default()
            },
            offset,
            count: data.len() as u32,
            region,
        };
        debug!("Command: {region_read:?}");
        self.next_message_id += Wrapping(1);
        self.stream
            .write_all(region_read.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = RegionAccess::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");
        self.stream.read_exact(data).map_err(Error::StreamRead)?;
        Ok(())
    }

    pub fn region_write(&mut self, region: u32, offset: u64, data: &[u8]) -> Result<(), Error> {
        let region_write = RegionAccess {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::RegionWrite as u16,
                flags: HeaderFlags::Command as u32,
                message_size: (size_of::<RegionAccess>() + data.len()) as u32,
                ..Default::default()
            },
            offset,
            count: data.len() as u32,
            region,
        };
        debug!("Command: {region_write:?}");
        self.next_message_id += Wrapping(1);

        let bufs = vec![IoSlice::new(region_write.as_slice()), IoSlice::new(data)];

        // TODO: Use write_all_vectored() when ready
        let _ = self
            .stream
            .write_vectored(&bufs)
            .map_err(Error::StreamWrite)?;

        let mut reply = RegionAccess::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");
        Ok(())
    }

    pub fn get_irq_info(&mut self, index: u32) -> Result<IrqInfo, Error> {
        let get_irq_info = GetIrqInfo {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::GetIrqInfo as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<GetIrqInfo>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<GetIrqInfo>() - size_of::<Header>()) as u32,
            flags: 0,
            index,
            count: 0,
        };
        debug!("Command: {get_irq_info:?}");
        self.next_message_id += Wrapping(1);

        self.stream
            .write_all(get_irq_info.as_slice())
            .map_err(Error::StreamWrite)?;

        let mut reply = GetIrqInfo::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");

        Ok(IrqInfo {
            index: reply.index,
            flags: reply.flags,
            count: reply.count,
        })
    }

    pub fn set_irqs(
        &mut self,
        index: u32,
        flags: u32,
        start: u32,
        count: u32,
        fds: &[RawFd],
    ) -> Result<(), Error> {
        let set_irqs = SetIrqs {
            header: Header {
                message_id: self.next_message_id.0,
                command: Command::SetIrqs as u16,
                flags: HeaderFlags::Command as u32,
                message_size: size_of::<SetIrqs>() as u32,
                ..Default::default()
            },
            argsz: (size_of::<SetIrqs>() - size_of::<Header>()) as u32,
            flags,
            start,
            index,
            count,
        };
        debug!("Command: {set_irqs:?}");
        self.next_message_id += Wrapping(1);

        self.stream
            .send_with_fds(&[set_irqs.as_slice()], fds)
            .map_err(Error::SendWithFd)?;

        let mut reply = Header::default();
        self.stream
            .read_exact(reply.as_mut_slice())
            .map_err(Error::StreamRead)?;
        debug!("Reply: {reply:?}");

        Ok(())
    }

    pub fn region(&self, region_index: u32) -> Option<&Region> {
        self.regions
            .iter()
            .find(|&region| region.index == region_index)
    }

    pub fn resettable(&self) -> bool {
        self.resettable
    }

    pub fn shutdown(&self) -> Result<(), Error> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(Error::StreamShutdown)
    }
}

pub trait ServerBackend {
    fn region_read(
        &mut self,
        _region: u32,
        _offset: u64,
        _data: &mut [u8],
    ) -> Result<(), std::io::Error>;
    fn region_write(
        &mut self,
        _region: u32,
        _offset: u64,
        _data: &[u8],
    ) -> Result<(), std::io::Error>;
    fn dma_map(
        &mut self,
        _flags: DmaMapFlags,
        _offset: u64,
        _address: u64,
        _size: u64,
        _fd: Option<File>,
    ) -> Result<(), std::io::Error>;
    fn dma_unmap(
        &mut self,
        _flags: DmaUnmapFlags,
        _address: u64,
        _size: u64,
    ) -> Result<(), std::io::Error>;
    fn reset(&mut self) -> Result<(), std::io::Error>;
    fn set_irqs(
        &mut self,
        _index: u32,
        _flags: u32,
        _start: u32,
        _count: u32,
        _fds: Vec<File>,
    ) -> Result<(), std::io::Error>;

    // Migration v2 (default: not supported; a migratable backend overrides these).
    /// Supported-migration flags (VFIO_MIGRATION_*), or None if not migratable. Some(..) makes the
    /// server advertise migration via VFIO_DEVICE_FEATURE_MIGRATION.
    fn migration_flags(&mut self) -> Option<u64> {
        None
    }
    /// Transition the device migration state to a VFIO_DEVICE_STATE_* value (the v2 FSM). The
    /// backend quiesces / serializes / rehydrates accordingly.
    fn migration_set_state(&mut self, _state: u32) -> Result<(), std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    /// Current device migration state (VFIO_DEVICE_STATE_*).
    fn migration_get_state(&mut self) -> Result<u32, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    /// Read the NEXT chunk of serialized device state into `buf` (sequential; valid in
    /// STOP_COPY/PRE_COPY). Fill as much of `buf` as remains and return the count; a return
    /// < `buf.len()` (including 0) signals end-of-stream to the client. The backend tracks its own
    /// read position and resets it when entering STOP_COPY/PRE_COPY via migration_set_state.
    fn migration_read_data(&mut self, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    /// Write the NEXT chunk of serialized device state (sequential; valid in RESUMING). The backend
    /// tracks its own write position and resets it when entering RESUMING via migration_set_state.
    fn migration_write_data(&mut self, _buf: &[u8]) -> Result<(), std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    /// Start DMA dirty logging for the given guest IOVA `ranges` (iova,len) at `page_size`.
    fn dma_logging_start(
        &mut self,
        _page_size: u64,
        _ranges: &[(u64, u64)],
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    /// Stop DMA dirty logging and free the bitmaps.
    fn dma_logging_stop(&mut self) -> Result<(), std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    /// Report-and-CLEAR the dirty bitmap for [iova, iova+len) into `bitmap` (1 bit per `page_size`,
    /// LSB-first). On ANY error the caller must treat the whole range as dirty.
    fn dma_logging_report(
        &mut self,
        _iova: u64,
        _len: u64,
        _page_size: u64,
        _bitmap: &mut [u8],
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[derive(Clone, Copy)]
pub struct SparseArea {
    pub area: vfio_region_sparse_mmap_area,
}

#[derive(Clone)]
pub struct ServerRegion {
    pub region_info: vfio_region_info,
    pub sparse_areas: Vec<SparseArea>,
    pub mmap_fd: Option<RawFd>,
}

pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    resettable: bool,
    irqs: Vec<IrqInfo>,
    regions: Vec<ServerRegion>,
}

impl Server {
    pub fn new(
        path: &Path,
        resettable: bool,
        irqs: Vec<IrqInfo>,
        regions: Vec<ServerRegion>,
    ) -> Result<Server, Error> {
        if path.exists() {
            return Err(Error::SocketPathExists);
        }

        let listener = UnixListener::bind(path).map_err(Error::SocketBind)?;

        Ok(Server {
            listener,
            path: path.to_path_buf(),
            resettable,
            irqs,
            regions,
        })
    }

    fn handle_command(
        &self,
        backend: &mut dyn ServerBackend,
        stream: &mut UnixStream,
        header: Header,
        fds: Vec<File>,
    ) -> Result<(), Error> {
        let command = Command::n(header.command).ok_or(Error::UnknownCommand(header.command))?;
        match command {
            Command::Unknown
            | Command::GetRegionIoFds
            | Command::DmaRead
            | Command::DmaWrite
            | Command::UserDirtyPages => {
                return Err(Error::UnsupportedCommand(command));
            }
            // Migration v2 (device-feature + mig-data over the wire).
            Command::DeviceFeature => {
                let mut df = DeviceFeatureHdr {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut df.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;
                let feature = df.flags & VFIO_DEVICE_FEATURE_MASK;
                let is_get = df.flags & VFIO_DEVICE_FEATURE_GET != 0;
                let dlen =
                    (df.header.message_size as usize).saturating_sub(size_of::<DeviceFeatureHdr>());
                let mut data = vec![0u8; dlen];
                stream.read_exact(&mut data).map_err(Error::StreamRead)?;

                // Build the reply payload that follows the echoed DeviceFeatureHdr.
                let mut out: Vec<u8> = Vec::new();
                match feature {
                    VFIO_DEVICE_FEATURE_MIGRATION => {
                        let flags = backend
                            .migration_flags()
                            .ok_or(Error::UnsupportedCommand(command))?;
                        if is_get {
                            out.extend_from_slice(FeatureMigration { flags }.as_slice());
                        }
                    }
                    VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE => {
                        if is_get {
                            let st = backend.migration_get_state().map_err(Error::Backend)?;
                            out.extend_from_slice(
                                FeatureMigState {
                                    device_state: st,
                                    data_fd: 0,
                                }
                                .as_slice(),
                            );
                        } else {
                            let st = FeatureMigState::from_slice(
                                data.get(..size_of::<FeatureMigState>())
                                    .ok_or(Error::InvalidInput)?,
                            )
                            .ok_or(Error::InvalidInput)?;
                            backend
                                .migration_set_state(st.device_state)
                                .map_err(Error::Backend)?;
                        }
                    }
                    VFIO_DEVICE_FEATURE_DMA_LOGGING_START => {
                        let ctrl = *DmaLoggingControl::from_slice(
                            data.get(..size_of::<DmaLoggingControl>())
                                .ok_or(Error::InvalidInput)?,
                        )
                        .ok_or(Error::InvalidInput)?;
                        let base = size_of::<DmaLoggingControl>();
                        let n = ctrl.num_ranges as usize;
                        // num_ranges is wire-controlled: require the message to actually carry that many
                        // ranges before allocating, so a bogus count can't force a huge allocation.
                        let need = base
                            .checked_add(
                                n.checked_mul(size_of::<DmaLoggingRange>())
                                    .ok_or(Error::InvalidInput)?,
                            )
                            .ok_or(Error::InvalidInput)?;
                        if data.len() < need {
                            return Err(Error::InvalidInput);
                        }
                        let mut ranges = Vec::with_capacity(n);
                        for i in 0..n {
                            let off = base + i * size_of::<DmaLoggingRange>();
                            let r = DmaLoggingRange::from_slice(
                                &data[off..off + size_of::<DmaLoggingRange>()],
                            )
                            .ok_or(Error::InvalidInput)?;
                            ranges.push((r.iova, r.length));
                        }
                        backend
                            .dma_logging_start(ctrl.page_size, &ranges)
                            .map_err(Error::Backend)?;
                    }
                    VFIO_DEVICE_FEATURE_DMA_LOGGING_STOP => {
                        backend.dma_logging_stop().map_err(Error::Backend)?;
                    }
                    VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT => {
                        let rep = *DmaLoggingReport::from_slice(
                            data.get(..size_of::<DmaLoggingReport>())
                                .ok_or(Error::InvalidInput)?,
                        )
                        .ok_or(Error::InvalidInput)?;
                        if rep.page_size == 0 {
                            return Err(Error::InvalidInput);
                        }
                        let nbytes = (rep.length.div_ceil(rep.page_size) as usize).div_ceil(8);
                        if nbytes > MAX_DMA_LOG_BITMAP {
                            return Err(Error::InvalidInput);
                        }
                        let mut bitmap = vec![0u8; nbytes];
                        backend
                            .dma_logging_report(rep.iova, rep.length, rep.page_size, &mut bitmap)
                            .map_err(Error::Backend)?;
                        out.extend_from_slice(rep.as_slice());
                        out.extend_from_slice(&bitmap);
                    }
                    _ => return Err(Error::UnsupportedCommand(command)),
                }
                if df.header.no_reply() {
                    return Ok(());
                }
                // A SET reply echoes the request verbatim (client's argsz and payload unchanged);
                // a GET reply carries the queried payload with argsz set to the reply length. This
                // matches libvfio-user, so a libvfio-user client accepts the reply.
                let (argsz, body): (u32, &[u8]) = if is_get {
                    (
                        (size_of::<DeviceFeatureHdr>() - size_of::<Header>() + out.len()) as u32,
                        &out,
                    )
                } else {
                    (df.argsz, &data)
                };
                let reply = DeviceFeatureHdr {
                    header: Header {
                        message_id: df.header.message_id,
                        command: Command::DeviceFeature as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: (size_of::<DeviceFeatureHdr>() + body.len()) as u32,
                        ..Default::default()
                    },
                    argsz,
                    flags: df.flags,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
                if !body.is_empty() {
                    stream.write_all(body).map_err(Error::StreamWrite)?;
                }
            }
            Command::MigDataRead => {
                let mut md = MigData {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut md.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;
                if md.size as usize > MAX_MIG_DATA_SIZE {
                    return Err(Error::InvalidInput);
                }
                let mut buf = vec![0u8; md.size as usize];
                let n = backend
                    .migration_read_data(&mut buf)
                    .map_err(Error::Backend)?;
                // The reply data is always the full requested size (zero-padded past the n valid
                // bytes); `size` carries the actual count, and size < requested signals end-of-stream.
                // libvfio-user requires this fixed length, so a short read mustn't truncate the wire.
                let reply = MigData {
                    header: Header {
                        message_id: md.header.message_id,
                        command: Command::MigDataRead as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: (size_of::<MigData>() + buf.len()) as u32,
                        ..Default::default()
                    },
                    argsz: (size_of::<MigData>() - size_of::<Header>() + n) as u32,
                    size: n as u32,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
                if !buf.is_empty() {
                    stream.write_all(&buf).map_err(Error::StreamWrite)?;
                }
            }
            Command::MigDataWrite => {
                let mut md = MigData {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut md.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;
                if md.size as usize > MAX_MIG_DATA_SIZE {
                    return Err(Error::InvalidInput);
                }
                let mut buf = vec![0u8; md.size as usize];
                stream.read_exact(&mut buf).map_err(Error::StreamRead)?;
                backend.migration_write_data(&buf).map_err(Error::Backend)?;
                if md.header.no_reply() {
                    return Ok(());
                }
                let reply = Header {
                    message_id: md.header.message_id,
                    command: Command::MigDataWrite as u16,
                    flags: HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    ..Default::default()
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::Version => {
                if header.no_reply() {
                    return Err(Error::UnexpectedNoReply(Command::Version));
                }

                // TODO: Make version/capabilities configurable
                let mut client_version = Version {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut client_version.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let mut raw_version_data =
                    vec![0; header.message_size as usize - size_of::<Version>()];
                stream
                    .read_exact(&mut raw_version_data)
                    .map_err(Error::StreamRead)?;
                let client_version_data = CString::from_vec_with_nul(raw_version_data)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let client_capabilities: CapabilitiesData =
                    serde_json::from_str(&client_version_data)
                        .map_err(Error::DeserializeCapabilites)?;

                info!(
                    "Received client version: major = {} minor = {} capabilities = {:?}",
                    client_version.major, client_version.minor, client_capabilities.capabilities,
                );

                let server_capabilities = CapabilitiesData::default();
                let server_version_data = serde_json::to_string(&server_capabilities)
                    .map_err(Error::SerializeCapabilites)?;
                let server_version = Version {
                    header: Header {
                        message_id: client_version.header.message_id,
                        command: Command::Version as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: (size_of::<Version>() + server_version_data.len() + 1) as u32,
                        ..Default::default()
                    },
                    major: 0,
                    minor: 0,
                };

                let server_version_data = CString::new(server_version_data.as_bytes()).unwrap();

                let bufs = vec![
                    IoSlice::new(server_version.as_slice()),
                    IoSlice::new(server_version_data.as_bytes_with_nul()),
                ];

                // TODO: Use write_all_vectored() when ready
                let _ = stream.write_vectored(&bufs).map_err(Error::StreamWrite)?;

                info!(
                    "Sent server version: major = {} minor = {} capabilities = {:?}",
                    server_version.major, server_version.minor, server_capabilities.capabilities
                );
            }
            Command::DmaMap => {
                let mut cmd = DmaMap {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let mut fds = fds;

                // The specification demands that the caller passes 0
                // or 1 file descriptor.
                if fds.len() > 1 {
                    return Err(Error::InvalidInput);
                }

                backend
                    .dma_map(
                        DmaMapFlags::from_bits_truncate(cmd.flags),
                        cmd.offset,
                        cmd.address,
                        cmd.size,
                        fds.pop(),
                    )
                    .map_err(Error::Backend)?;

                if header.no_reply() {
                    return Ok(());
                }

                let reply = Header {
                    message_id: cmd.header.message_id,
                    command: Command::DmaMap as u16,
                    flags: HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    ..Default::default()
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DmaUnmap => {
                let mut cmd = DmaUnmap {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                backend
                    .dma_unmap(
                        DmaUnmapFlags::from_bits_truncate(cmd.flags),
                        cmd.address,
                        cmd.size,
                    )
                    .map_err(Error::Backend)?;

                if header.no_reply() {
                    return Ok(());
                }

                let reply = DmaUnmap {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::DmaUnmap as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<DmaUnmap>() as u32,
                        ..Default::default()
                    },
                    argsz: cmd.argsz,
                    flags: cmd.flags,
                    address: cmd.address,
                    size: cmd.size,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DeviceGetInfo => {
                if header.no_reply() {
                    return Err(Error::UnexpectedNoReply(Command::DeviceGetInfo));
                }

                let mut cmd = DeviceGetInfo {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let reply = DeviceGetInfo {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::DeviceGetInfo as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<DeviceGetInfo>() as u32,
                        ..Default::default()
                    },
                    argsz: size_of::<DeviceGetInfo>() as u32 - size_of::<Header>() as u32,
                    // TODO: Consider non-PCI devices
                    flags: VFIO_DEVICE_FLAGS_PCI
                        | if self.resettable {
                            VFIO_DEVICE_FLAGS_RESET
                        } else {
                            0
                        },
                    num_regions: self.regions.len() as u32,
                    num_irqs: self.irqs.len() as u32,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DeviceGetRegionInfo => {
                if header.no_reply() {
                    return Err(Error::UnexpectedNoReply(Command::DeviceGetRegionInfo));
                }

                let mut cmd = DeviceGetRegionInfo {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                if cmd.region_info.index as usize >= self.regions.len() {
                    return Err(Error::InvalidInput);
                }

                let server_region = &self.regions[cmd.region_info.index as usize];
                let mut region_info = server_region.region_info;
                let sparse_areas = &server_region.sparse_areas;

                let mut cap_data: Vec<u8> = Vec::new();
                if !sparse_areas.is_empty() {
                    let cap_header = vfio_info_cap_header {
                        id: VFIO_REGION_INFO_CAP_SPARSE_MMAP as u16,
                        version: 1,
                        next: 0,
                    };
                    // SAFETY: vfio_info_cap_header is repr(C) and cap_header
                    // is correctly initialized.
                    cap_data.extend_from_slice(unsafe {
                        std::slice::from_raw_parts(
                            &cap_header as *const vfio_info_cap_header as *const u8,
                            size_of::<vfio_info_cap_header>(),
                        )
                    });
                    cap_data.extend_from_slice(&(sparse_areas.len() as u32).to_le_bytes());
                    cap_data.extend_from_slice(&0u32.to_le_bytes());
                    for sparse_area in sparse_areas {
                        // SAFETY: vfio_region_sparse_mmap_area is repr(C) and
                        // sparse_area.area is correctly initialized.
                        cap_data.extend_from_slice(unsafe {
                            std::slice::from_raw_parts(
                                &sparse_area.area as *const vfio_region_sparse_mmap_area
                                    as *const u8,
                                size_of::<vfio_region_sparse_mmap_area>(),
                            )
                        });
                    }
                }

                let send_cap_data = if !cap_data.is_empty() {
                    let full_argsz = (size_of::<vfio_region_info>() + cap_data.len()) as u32;
                    region_info.flags |= VFIO_REGION_INFO_FLAG_CAPS;
                    region_info.argsz = full_argsz;
                    region_info.cap_offset = size_of::<vfio_region_info>() as u32;
                    cmd.region_info.argsz >= full_argsz
                } else {
                    false
                };

                let message_size = if send_cap_data {
                    (size_of::<DeviceGetRegionInfo>() + cap_data.len()) as u32
                } else {
                    size_of::<DeviceGetRegionInfo>() as u32
                };

                let reply = DeviceGetRegionInfo {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::DeviceGetRegionInfo as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size,
                        ..Default::default()
                    },
                    region_info,
                };

                if send_cap_data {
                    let reply_bytes = reply.as_slice();
                    let mut buf = Vec::with_capacity(reply_bytes.len() + cap_data.len());
                    buf.extend_from_slice(reply_bytes);
                    buf.extend_from_slice(&cap_data);

                    if let Some(fd) = server_region.mmap_fd {
                        stream
                            .send_with_fds(&[&buf[..]], &[fd])
                            .map_err(Error::SendWithFd)?;
                    } else {
                        stream.write_all(&buf).map_err(Error::StreamWrite)?;
                    }
                } else {
                    stream
                        .write_all(reply.as_slice())
                        .map_err(Error::StreamWrite)?;
                }
            }
            Command::GetIrqInfo => {
                if header.no_reply() {
                    return Err(Error::UnexpectedNoReply(Command::GetIrqInfo));
                }

                let mut cmd = GetIrqInfo {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                if cmd.index as usize >= self.irqs.len() {
                    return Err(Error::InvalidInput);
                }

                let irq = &self.irqs[cmd.index as usize];

                let reply = GetIrqInfo {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::GetIrqInfo as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<GetIrqInfo>() as u32,
                        ..Default::default()
                    },
                    argsz: (size_of::<GetIrqInfo>() - size_of::<Header>()) as u32,
                    index: irq.index,
                    flags: irq.flags,
                    count: irq.count,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::SetIrqs => {
                let mut cmd = SetIrqs {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                if cmd.index as usize >= self.irqs.len() {
                    return Err(Error::InvalidInput);
                }

                if cmd.flags & VFIO_IRQ_SET_DATA_BOOL > 0 {
                    return Err(Error::UnsupportedFeature);
                }

                backend
                    .set_irqs(cmd.index, cmd.flags, cmd.start, cmd.count, fds)
                    .map_err(Error::Backend)?;

                if header.no_reply() {
                    return Ok(());
                }

                let reply = Header {
                    message_id: cmd.header.message_id,
                    command: Command::SetIrqs as u16,
                    flags: HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    ..Default::default()
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::RegionRead => {
                if header.no_reply() {
                    return Err(Error::UnexpectedNoReply(Command::RegionRead));
                }

                let mut cmd = RegionAccess {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let (region, offset, count) = (cmd.region, cmd.offset, cmd.count);

                if region as usize >= self.regions.len() {
                    return Err(Error::InvalidInput);
                }

                let mut data = vec![0u8; count as usize];
                backend
                    .region_read(region, offset, &mut data)
                    .map_err(Error::Backend)?;

                let reply = RegionAccess {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::RegionRead as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<RegionAccess>() as u32 + count,
                        ..Default::default()
                    },
                    region,
                    offset,
                    count,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
                stream.write_all(&data).map_err(Error::StreamWrite)?;
            }
            Command::RegionWrite => {
                let mut cmd = RegionAccess {
                    header,
                    ..Default::default()
                };
                stream
                    .read_exact(&mut cmd.as_mut_slice()[size_of::<Header>()..])
                    .map_err(Error::StreamRead)?;

                let (region, offset, count) = (cmd.region, cmd.offset, cmd.count);

                if region as usize >= self.regions.len() {
                    return Err(Error::InvalidInput);
                }

                let mut data = vec![0u8; count as usize];
                stream.read_exact(&mut data).map_err(Error::StreamRead)?;
                backend
                    .region_write(region, offset, &data)
                    .map_err(Error::Backend)?;

                if header.no_reply() {
                    return Ok(());
                }

                let reply = RegionAccess {
                    header: Header {
                        message_id: cmd.header.message_id,
                        command: Command::RegionWrite as u16,
                        flags: HeaderFlags::Reply as u32,
                        message_size: size_of::<RegionAccess>() as u32,
                        ..Default::default()
                    },
                    region,
                    offset,
                    count,
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
            Command::DeviceReset => {
                backend.reset().map_err(Error::Backend)?;

                if header.no_reply() {
                    return Ok(());
                }

                let reply = Header {
                    message_id: header.message_id,
                    command: Command::DeviceReset as u16,
                    flags: HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    ..Default::default()
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
        }

        Ok(())
    }

    pub fn run(&self, backend: &mut dyn ServerBackend) -> Result<(), Error> {
        let (mut stream, _) = self.listener.accept().map_err(Error::SocketAccept)?;

        loop {
            let mut header = Header::default();

            // The maximum number of FDs that can be sent is 16 so that is
            // also the maximum that can be received.
            let mut fds = vec![0; 16];
            let mut iovecs = vec![iovec {
                iov_base: header.as_mut_slice().as_mut_ptr() as *mut c_void,
                iov_len: header.as_mut_slice().len(),
            }];
            // SAFETY: Safe as the iovect is correctly initialised and fds is big enough
            let (bytes, fds_received) = unsafe {
                stream
                    .recv_with_fds(&mut iovecs, &mut fds)
                    .map_err(Error::ReceiveWithFd)?
            };

            // Other end closed connection
            if bytes == 0 {
                info!("Connection closed");
                break;
            }

            fds.resize(fds_received, 0);

            let fds: Vec<File> = fds
                .iter()
                // SAFETY: Safe as we have only valid FDs in the vector now
                .map(|fd| unsafe { File::from_raw_fd(*fd) })
                .collect();

            if let Err(e) = self.handle_command(backend, &mut stream, header, fds) {
                error!("Error handling command: {:?}: {e}", header.command);
                let reply = Header {
                    message_id: header.message_id,
                    command: header.command,
                    flags: HeaderFlags::Error as u32 | HeaderFlags::Reply as u32,
                    message_size: size_of::<Header>() as u32,
                    error: if matches!(e, Error::InvalidInput) {
                        EINVAL as u32
                    } else {
                        0
                    },
                };
                stream
                    .write_all(reply.as_slice())
                    .map_err(Error::StreamWrite)?;
            }
        }

        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    fn build_sparse_cap_data(areas: &[vfio_region_sparse_mmap_area]) -> Vec<u8> {
        let mut cap_data: Vec<u8> = Vec::new();
        let cap_header = vfio_info_cap_header {
            id: VFIO_REGION_INFO_CAP_SPARSE_MMAP as u16,
            version: 1,
            next: 0,
        };
        // SAFETY: `cap_header` is a valid, initialized repr(C) struct.
        cap_data.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &cap_header as *const vfio_info_cap_header as *const u8,
                size_of::<vfio_info_cap_header>(),
            )
        });
        cap_data.extend_from_slice(&(areas.len() as u32).to_le_bytes());
        cap_data.extend_from_slice(&0u32.to_le_bytes());
        for area in areas {
            // SAFETY: `area` is a valid, initialized repr(C) struct.
            cap_data.extend_from_slice(unsafe {
                std::slice::from_raw_parts(
                    area as *const vfio_region_sparse_mmap_area as *const u8,
                    size_of::<vfio_region_sparse_mmap_area>(),
                )
            });
        }
        cap_data
    }

    #[test]
    fn test_parse_sparse_mmap_caps() {
        let areas = vec![
            vfio_region_sparse_mmap_area {
                offset: 0x0,
                size: 0x1000,
            },
            vfio_region_sparse_mmap_area {
                offset: 0x2000,
                size: 0x3000,
            },
        ];

        let cap_data = build_sparse_cap_data(&areas);

        let region_info = vfio_region_info {
            argsz: (size_of::<vfio_region_info>() + cap_data.len()) as u32,
            flags: VFIO_REGION_INFO_FLAG_CAPS,
            cap_offset: size_of::<vfio_region_info>() as u32,
            ..Default::default()
        };

        let parsed = Client::parse_region_caps(&cap_data, &region_info).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].offset, 0x0);
        assert_eq!(parsed[0].size, 0x1000);
        assert_eq!(parsed[1].offset, 0x2000);
        assert_eq!(parsed[1].size, 0x3000);
    }

    #[test]
    fn test_parse_empty_sparse_mmap_caps() {
        let cap_data = build_sparse_cap_data(&[]);

        let region_info = vfio_region_info {
            argsz: (size_of::<vfio_region_info>() + cap_data.len()) as u32,
            flags: VFIO_REGION_INFO_FLAG_CAPS,
            cap_offset: size_of::<vfio_region_info>() as u32,
            ..Default::default()
        };

        let parsed = Client::parse_region_caps(&cap_data, &region_info).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_no_caps_returns_empty() {
        let region_info = vfio_region_info {
            argsz: size_of::<vfio_region_info>() as u32,
            flags: 0,
            cap_offset: 0,
            ..Default::default()
        };

        let parsed = Client::parse_region_caps(&[], &region_info).unwrap();
        assert!(parsed.is_empty());
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use std::io::Read;
    use std::num::Wrapping;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    /// A tiny migratable mock device: an FSM, a fixed device-state blob, and a dirty bitmap.
    #[derive(Default)]
    struct MockMig {
        state: u32,
        read_pos: usize,
        write_buf: Vec<u8>,
        blob: Vec<u8>,
        dma_active: bool,
        dma_page_size: u64,
    }
    impl ServerBackend for MockMig {
        fn region_read(&mut self, _r: u32, _o: u64, _d: &mut [u8]) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn region_write(&mut self, _r: u32, _o: u64, _d: &[u8]) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn dma_map(
            &mut self,
            _f: DmaMapFlags,
            _o: u64,
            _a: u64,
            _s: u64,
            _fd: Option<File>,
        ) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn dma_unmap(&mut self, _f: DmaUnmapFlags, _a: u64, _s: u64) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn reset(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn set_irqs(
            &mut self,
            _i: u32,
            _f: u32,
            _s: u32,
            _c: u32,
            _fds: Vec<File>,
        ) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn migration_flags(&mut self) -> Option<u64> {
            Some(VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_PRE_COPY)
        }
        fn migration_set_state(&mut self, s: u32) -> Result<(), std::io::Error> {
            self.state = s;
            if s == VFIO_DEVICE_STATE_STOP_COPY {
                self.read_pos = 0;
                self.blob = b"NVMEDEV-STATE-blob-1234567890-ABCDEF".to_vec();
            }
            if s == VFIO_DEVICE_STATE_RESUMING {
                self.write_buf.clear();
            }
            Ok(())
        }
        fn migration_get_state(&mut self) -> Result<u32, std::io::Error> {
            Ok(self.state)
        }
        fn migration_read_data(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
            let n = (self.blob.len() - self.read_pos).min(buf.len());
            buf[..n].copy_from_slice(&self.blob[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            Ok(n)
        }
        fn migration_write_data(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
            self.write_buf.extend_from_slice(buf);
            Ok(())
        }
        fn dma_logging_start(
            &mut self,
            page_size: u64,
            _ranges: &[(u64, u64)],
        ) -> Result<(), std::io::Error> {
            self.dma_active = true;
            self.dma_page_size = page_size;
            Ok(())
        }
        fn dma_logging_stop(&mut self) -> Result<(), std::io::Error> {
            self.dma_active = false;
            Ok(())
        }
        fn dma_logging_report(
            &mut self,
            _iova: u64,
            _len: u64,
            _ps: u64,
            bitmap: &mut [u8],
        ) -> Result<(), std::io::Error> {
            // Mark pages 0 and 2 dirty (LSB-first): bit0 | bit2 = 0b0000_0101.
            if !bitmap.is_empty() {
                bitmap[0] = 0b0000_0101;
            }
            Ok(())
        }
    }

    /// Full device-state migration round-trip (FSM + MIG_DATA read/write + DMA logging) driven by
    /// the Client over a socketpair against the Server dispatch + a mock backend.
    #[test]
    fn migration_v2_roundtrip() {
        let (client_s, server_s) = UnixStream::pair().unwrap();
        let backend = Arc::new(Mutex::new(MockMig::default()));
        let backend2 = backend.clone();

        let server_thread = std::thread::spawn(move || {
            let tmp = format!("/tmp/vfu-migtest-{}.sock", std::process::id());
            let _ = std::fs::remove_file(&tmp);
            let server = Server::new(Path::new(&tmp), true, vec![], vec![]).unwrap();
            let mut s = server_s;
            loop {
                let mut h = Header::default();
                if s.read_exact(h.as_mut_slice()).is_err() {
                    break;
                }
                let mut guard = backend2.lock().unwrap();
                if server
                    .handle_command(&mut *guard, &mut s, h, vec![])
                    .is_err()
                {
                    break;
                }
            }
            let _ = std::fs::remove_file(&tmp);
        });

        let mut client = Client {
            stream: client_s,
            next_message_id: Wrapping(0),
            num_irqs: 0,
            resettable: false,
            regions: vec![],
        };

        // 1) advertise/query migration support
        assert_eq!(
            client.query_migration().unwrap(),
            VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_PRE_COPY
        );
        // 2) FSM: RUNNING -> STOP -> STOP_COPY, and read it back
        client.set_device_state(VFIO_DEVICE_STATE_STOP).unwrap();
        client
            .set_device_state(VFIO_DEVICE_STATE_STOP_COPY)
            .unwrap();
        assert_eq!(
            client.get_device_state().unwrap(),
            VFIO_DEVICE_STATE_STOP_COPY
        );
        // 3) stream the device-state blob in small chunks until EOF
        let mut blob = Vec::new();
        let mut buf = [0u8; 8];
        loop {
            let n = client.read_migration_data(&mut buf).unwrap();
            blob.extend_from_slice(&buf[..n]);
            if n < buf.len() {
                break; // short read (incl. 0) == end of stream
            }
        }
        assert_eq!(blob, b"NVMEDEV-STATE-blob-1234567890-ABCDEF");
        // 4) destination: RESUMING, write the blob back, verify it round-tripped byte-for-byte
        client.set_device_state(VFIO_DEVICE_STATE_RESUMING).unwrap();
        for chunk in blob.chunks(7) {
            client.write_migration_data(chunk).unwrap();
        }
        assert_eq!(backend.lock().unwrap().write_buf, blob);
        // 5) DMA dirty logging: start, report (bitmap), stop
        client.dma_logging_start(4096, &[(0, 4096 * 8)]).unwrap();
        assert!(backend.lock().unwrap().dma_active);
        let bm = client.dma_logging_report(0, 4096 * 8, 4096).unwrap();
        assert_eq!(bm[0], 0b0000_0101); // pages 0 and 2 dirty
        client.dma_logging_stop().unwrap();
        assert!(!backend.lock().unwrap().dma_active);

        drop(client); // ends the server loop
        server_thread.join().unwrap();
    }
}
