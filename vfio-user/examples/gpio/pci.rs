// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
// SPDX-License-Identifier: BSD-3-Clause

use log::warn;
use std::convert::TryInto;
use thiserror::Error;

/// PCI has four interrupt pins A->D.
#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PciInterruptPin {
    IntA,
    IntB,
    IntC,
    IntD,
}

// The number of 32bit registers in the config space, 256 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 64;
#[allow(dead_code)]
pub const PCI_ID_REG: usize = 0;
pub const COMMAND_REG: usize = 1;
pub const COMMAND_REG_IO_SPACE_MASK: u32 = 0x0000_0001;
pub const COMMAND_REG_MEMORY_SPACE_MASK: u32 = 0x0000_0002;
#[allow(dead_code)]
const STATUS_REG: usize = 1;
#[allow(dead_code)]
pub const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
#[allow(dead_code)]
pub const CLASS_REG: usize = 2;
#[allow(dead_code)]
pub const HEADER_TYPE_REG: usize = 3;
#[allow(dead_code)]
pub const HEADER_TYPE_MULTIFUNCTION_MASK: u32 = 0x0080_0000;
pub const BAR0_REG: usize = 4;
const BAR_IO_ADDR_MASK: u32 = 0xffff_fffc;
const BAR_IO_MIN_SIZE: u64 = 4;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const BAR_MEM_MIN_SIZE: u64 = 16;
const BAR_ROM_MIN_SIZE: u64 = 2048;
pub const NUM_BAR_REGS: usize = 7; // 6 normal BARs + expansion ROM BAR.
pub const ROM_BAR_IDX: PciBarIndex = 6;
pub const ROM_BAR_REG: usize = 12;
#[allow(dead_code)]
pub const CAPABILITY_LIST_HEAD_OFFSET: usize = 0x34;
#[allow(dead_code)]
pub const PCI_CAP_NEXT_POINTER: usize = 0x1;
#[allow(dead_code)]
const FIRST_CAPABILITY_OFFSET: usize = 0x40;
#[allow(dead_code)]
pub const CAPABILITY_MAX_OFFSET: usize = 255;

const INTERRUPT_LINE_PIN_REG: usize = 15;

/// Represents the types of PCI headers allowed in the configuration registers.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciHeaderType {
    Device,
    Bridge,
}

/// Classes of PCI nodes.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciClassCode {
    TooOld,
    MassStorage,
    NetworkController,
    DisplayController,
    MultimediaController,
    MemoryController,
    BridgeDevice,
    SimpleCommunicationController,
    BaseSystemPeripheral,
    InputDevice,
    DockingStation,
    Processor,
    SerialBusController,
    WirelessController,
    IntelligentIoController,
    SatelliteCommunicationController,
    EncryptionController,
    DataAcquisitionSignalProcessing,
    ProcessingAccelerator,
    NonEssentialInstrumentation,
    Other = 0xff,
}

impl PciClassCode {
    pub fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// A PCI sublcass. Each class in `PciClassCode` can specify a unique set of subclasses. This trait
/// is implemented by each subclass. It allows use of a trait object to generate configurations.
pub trait PciSubclass {
    /// Convert this subclass to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Subclasses of the DisplayController class.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciDisplaySubclass {
    VgaCompatibleController = 0x00,
    XgaCompatibleController = 0x01,
    ThreeDController = 0x02,
    Other = 0x80,
}

impl PciSubclass for PciDisplaySubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclasses of the MultimediaController class.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciMultimediaSubclass {
    VideoController = 0x00,
    AudioController = 0x01,
    TelephonyDevice = 0x02,
    AudioDevice = 0x03,
    Other = 0x80,
}

impl PciSubclass for PciMultimediaSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclasses of the BridgeDevice
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciBridgeSubclass {
    HostBridge = 0x00,
    IsaBridge = 0x01,
    EisaBridge = 0x02,
    McaBridge = 0x03,
    PciToPciBridge = 0x04,
    PcmciaBridge = 0x05,
    NuBusBridge = 0x06,
    CardBusBridge = 0x07,
    RaceWayBridge = 0x08,
    PciToPciSemiTransparentBridge = 0x09,
    InfiniBrandToPciHostBridge = 0x0a,
    OtherBridgeDevice = 0x80,
}

impl PciSubclass for PciBridgeSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclass of the SerialBus
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciSerialBusSubClass {
    Firewire = 0x00,
    AccessBus = 0x01,
    Ssa = 0x02,
    Usb = 0x03,
}

impl PciSubclass for PciSerialBusSubClass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclasses for PciClassCode Other.
#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(u8)]
pub enum PciOtherSubclass {
    Other = 0xff,
}

impl PciSubclass for PciOtherSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// A PCI class programming interface. Each combination of `PciClassCode` and
/// `PciSubclass` can specify a set of register-level programming interfaces.
/// This trait is implemented by each programming interface.
/// It allows use of a trait object to generate configurations.
pub trait PciProgrammingInterface {
    /// Convert this programming interface to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Types of PCI capabilities.
#[allow(dead_code)]
pub enum PciCapabilityID {
    ListID = 0,
    PowerManagement = 0x01,
    AcceleratedGraphicsPort = 0x02,
    VitalProductData = 0x03,
    SlotIdentification = 0x04,
    MessageSignalledInterrupts = 0x05,
    CompactPciHotSwap = 0x06,
    Pcix = 0x07,
    HyperTransport = 0x08,
    VendorSpecific = 0x09,
    Debugport = 0x0A,
    CompactPciCentralResourceControl = 0x0B,
    PciStandardHotPlugController = 0x0C,
    BridgeSubsystemVendorDeviceID = 0x0D,
    AgpTargetPciPciBridge = 0x0E,
    SecureDevice = 0x0F,
    PciExpress = 0x10,
    Msix = 0x11,
    SataDataIndexConf = 0x12,
    PciAdvancedFeatures = 0x13,
    PciEnhancedAllocation = 0x14,
}

/// A PCI capability list. Devices can optionally specify capabilities in their configuration space.
pub trait PciCapability {
    fn bytes(&self) -> &[u8];
    fn id(&self) -> PciCapabilityID;
    fn writable_bits(&self) -> Vec<u32>;
}

/// Contains the configuration space of a PCI node.
/// See the [specification](https://en.wikipedia.org/wiki/PCI_configuration_space).
/// The configuration space is accessed with DWORD reads and writes from the guest.
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS], // writable bits for each register.
    bar_used: [bool; NUM_BAR_REGS],
    bar_configs: [Option<PciBarConfiguration>; NUM_BAR_REGS],
    // Contains the byte offset and size of the last capability.
    #[allow(dead_code)]
    last_capability: Option<(usize, usize)>,
}

/// See pci_regs.h in kernel
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum PciBarRegionType {
    Memory32BitRegion = 0,
    IoRegion = 0x01,
    Memory64BitRegion = 0x04,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PciBarPrefetchable {
    NotPrefetchable = 0,
    Prefetchable = 0x08,
}

pub type PciBarIndex = usize;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciBarConfiguration {
    addr: u64,
    size: u64,
    bar_idx: PciBarIndex,
    region_type: PciBarRegionType,
    prefetchable: PciBarPrefetchable,
}

pub struct PciBarIter<'a> {
    config: &'a PciConfiguration,
    bar_num: PciBarIndex,
}

impl Iterator for PciBarIter<'_> {
    type Item = PciBarConfiguration;

    fn next(&mut self) -> Option<Self::Item> {
        while self.bar_num < NUM_BAR_REGS {
            let bar_config = self.config.get_bar_configuration(self.bar_num);
            self.bar_num += 1;
            if let Some(bar_config) = bar_config {
                return Some(bar_config);
            }
        }

        None
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Error {
    #[error("address {0} size {1} too big")]
    BarAddressInvalid(u64, u64),
    #[error("address {0} is not aligned to size {1}")]
    BarAlignmentInvalid(u64, u64),
    #[error("bar {0} already used")]
    BarInUse(PciBarIndex),
    #[error("64bit bar {0} already used (requires two regs)")]
    BarInUse64(PciBarIndex),
    #[error("bar {bar_index} invalid, max {max}", bar_index = .0, max = NUM_BAR_REGS - 1)]
    BarInvalid(PciBarIndex),
    #[error("64bitbar {bar_index} invalid, requires two regs, {max}", bar_index = .0, max = ROM_BAR_IDX - 1)]
    BarInvalid64(PciBarIndex),
    #[error("expansion rom bar must be a memory region")]
    BarInvalidRomType,
    #[error("bar address {0} not a power of two")]
    BarSizeInvalid(u64),
    #[error("empty capabilities are invalid")]
    CapabilityEmpty,
    #[error("Invalid capability length {0}")]
    CapabilityLengthInvalid(usize),
    #[error("capability of size {0} doesn't fit")]
    CapabilitySpaceFull(usize),
}

pub type Result<T> = std::result::Result<T, Error>;

impl PciConfiguration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        class_code: PciClassCode,
        subclass: &dyn PciSubclass,
        programming_interface: Option<&dyn PciProgrammingInterface>,
        header_type: PciHeaderType,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
        revision_id: u8,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];
        registers[0] = (u32::from(device_id) << 16) | u32::from(vendor_id);
        // TODO(dverkamp): Status should be write-1-to-clear
        writable_bits[1] = 0x0000_ffff; // Status (r/o), command (r/w)
        let pi = if let Some(pi) = programming_interface {
            pi.get_register_value()
        } else {
            0
        };
        registers[2] = (u32::from(class_code.get_register_value()) << 24)
            | (u32::from(subclass.get_register_value()) << 16)
            | (u32::from(pi) << 8)
            | u32::from(revision_id);
        writable_bits[3] = 0x0000_00ff; // Cacheline size (r/w)
        match header_type {
            PciHeaderType::Device => {
                registers[3] = 0x0000_0000; // Header type 0 (device)
                writable_bits[15] = 0x0000_00ff; // Interrupt line (r/w)
                registers[11] = (u32::from(subsystem_id) << 16) | u32::from(subsystem_vendor_id);
            }
            PciHeaderType::Bridge => {
                registers[3] = 0x0001_0000; // Header type 1 (bridge)
                writable_bits[6] = 0x00ff_ffff; // Primary/secondary/subordinate bus number,
                                                // secondary latency timer
                registers[7] = 0x0000_00f0; // IO base > IO Limit, no IO address on secondary side at initialize
                writable_bits[7] = 0xf900_0000; // IO base and limit, secondary status,
                registers[8] = 0x0000_fff0; // mem base > mem Limit, no MMIO address on secondary side at initialize
                writable_bits[8] = 0xfff0_fff0; // Memory base and limit
                registers[9] = 0x0001_fff1; // pmem base > pmem Limit, no prefetch MMIO address on secondary side at initialize
                writable_bits[9] = 0xfff0_fff0; // Prefetchable base and limit
                writable_bits[10] = 0xffff_ffff; // Prefetchable base upper 32 bits
                writable_bits[11] = 0xffff_ffff; // Prefetchable limit upper 32 bits
                writable_bits[15] = 0xffff_00ff; // Bridge control (r/w), interrupt line (r/w)
            }
        };

        PciConfiguration {
            registers,
            writable_bits,
            bar_used: [false; NUM_BAR_REGS],
            bar_configs: [None; NUM_BAR_REGS],
            last_capability: None,
        }
    }

    /// Reads a 32bit register from `reg_idx` in the register map.
    pub fn read_reg(&self, reg_idx: usize) -> u32 {
        *(self.registers.get(reg_idx).unwrap_or(&0xffff_ffff))
    }

    /// Writes data to PciConfiguration.registers.
    /// `reg_idx` - index into PciConfiguration.registers.
    /// `offset`  - PciConfiguration.registers is in unit of DWord, offset define byte
    ///             offset in the DWrod.
    /// `data`    - The data to write.
    pub fn write_reg(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        let reg_offset = reg_idx * 4 + offset as usize;
        match data.len() {
            1 => self.write_byte(reg_offset, data[0]),
            2 => self.write_word(reg_offset, u16::from_le_bytes(data.try_into().unwrap())),
            4 => self.write_dword(reg_offset, u32::from_le_bytes(data.try_into().unwrap())),
            _ => (),
        }
    }

    /// Writes a 32bit dword to `offset`. `offset` must be 32bit aligned.
    fn write_dword(&mut self, offset: usize, value: u32) {
        if offset % 4 != 0 {
            warn!("bad PCI config dword write offset {offset}");
            return;
        }
        let reg_idx = offset / 4;
        if let Some(r) = self.registers.get_mut(reg_idx) {
            *r = (*r & !self.writable_bits[reg_idx]) | (value & self.writable_bits[reg_idx]);
        } else {
            warn!("bad PCI dword write {offset}");
        }
    }

    /// Writes a 16bit word to `offset`. `offset` must be 16bit aligned.
    fn write_word(&mut self, offset: usize, value: u16) {
        let shift = match offset % 4 {
            0 => 0,
            2 => 16,
            _ => {
                warn!("bad PCI config word write offset {offset}");
                return;
            }
        };
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = self.writable_bits[reg_idx];
            let mask = (0xffffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config word write offset {offset}");
        }
    }

    /// Writes a byte to `offset`.
    fn write_byte(&mut self, offset: usize, value: u8) {
        self.write_byte_internal(offset, value, true);
    }

    /// Writes a byte to `offset`, optionally enforcing read-only bits.
    fn write_byte_internal(&mut self, offset: usize, value: u8, apply_writable_mask: bool) {
        let shift = (offset % 4) * 8;
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = if apply_writable_mask {
                self.writable_bits[reg_idx]
            } else {
                0xffff_ffff
            };
            let mask = (0xffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config byte write offset {offset}");
        }
    }

    /// Adds a region specified by `config`.  Configures the specified BAR(s) to
    /// report this region and size to the guest kernel.  Enforces a few constraints
    /// (i.e, region size must be power of two, register not already used). Returns 'None' on
    /// failure all, `Some(BarIndex)` on success.
    pub fn add_pci_bar(&mut self, config: PciBarConfiguration) -> Result<PciBarIndex> {
        if config.bar_idx >= NUM_BAR_REGS {
            return Err(Error::BarInvalid(config.bar_idx));
        }

        if self.bar_used[config.bar_idx] {
            return Err(Error::BarInUse(config.bar_idx));
        }

        if config.size.count_ones() != 1 {
            return Err(Error::BarSizeInvalid(config.size));
        }

        if config.is_expansion_rom() && config.region_type != PciBarRegionType::Memory32BitRegion {
            return Err(Error::BarInvalidRomType);
        }

        let min_size = if config.is_expansion_rom() {
            BAR_ROM_MIN_SIZE
        } else if config.region_type == PciBarRegionType::IoRegion {
            BAR_IO_MIN_SIZE
        } else {
            BAR_MEM_MIN_SIZE
        };

        if config.size < min_size {
            return Err(Error::BarSizeInvalid(config.size));
        }

        if config.addr % config.size != 0 {
            return Err(Error::BarAlignmentInvalid(config.addr, config.size));
        }

        let reg_idx = config.reg_index();
        let end_addr = config
            .addr
            .checked_add(config.size)
            .ok_or(Error::BarAddressInvalid(config.addr, config.size))?;
        match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::IoRegion => {
                if end_addr > u64::from(u32::MAX) {
                    return Err(Error::BarAddressInvalid(config.addr, config.size));
                }
            }
            PciBarRegionType::Memory64BitRegion => {
                // The expansion ROM BAR cannot be used for part of a 64-bit BAR.
                if config.bar_idx + 1 >= ROM_BAR_IDX {
                    return Err(Error::BarInvalid64(config.bar_idx));
                }

                if end_addr > u64::from(u32::MAX) {
                    return Err(Error::BarAddressInvalid(config.addr, config.size));
                }

                if self.bar_used[config.bar_idx + 1] {
                    return Err(Error::BarInUse64(config.bar_idx));
                }

                self.registers[reg_idx + 1] = (config.addr >> 32) as u32;
                self.writable_bits[reg_idx + 1] = !((config.size - 1) >> 32) as u32;
                self.bar_used[config.bar_idx + 1] = true;
            }
        }

        let (mask, lower_bits) = match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => {
                self.registers[COMMAND_REG] |= COMMAND_REG_MEMORY_SPACE_MASK;
                (
                    BAR_MEM_ADDR_MASK,
                    config.prefetchable as u32 | config.region_type as u32,
                )
            }
            PciBarRegionType::IoRegion => {
                self.registers[COMMAND_REG] |= COMMAND_REG_IO_SPACE_MASK;
                (BAR_IO_ADDR_MASK, config.region_type as u32)
            }
        };

        self.registers[reg_idx] = ((config.addr as u32) & mask) | lower_bits;
        self.writable_bits[reg_idx] = !(config.size - 1) as u32;
        if config.is_expansion_rom() {
            self.writable_bits[reg_idx] |= 1; // Expansion ROM enable bit.
        }
        self.bar_used[config.bar_idx] = true;
        self.bar_configs[config.bar_idx] = Some(config);
        Ok(config.bar_idx)
    }

    /// Returns an iterator of the currently configured base address registers.
    #[allow(dead_code)] // TODO(dverkamp): remove this once used
    pub fn get_bars(&self) -> PciBarIter<'_> {
        PciBarIter {
            config: self,
            bar_num: 0,
        }
    }

    /// Returns the configuration of a base address register, if present.
    pub fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        let config = self.bar_configs.get(bar_num)?;

        if let Some(mut config) = config {
            let command = self.read_reg(COMMAND_REG);
            if (config.is_memory() && (command & COMMAND_REG_MEMORY_SPACE_MASK == 0))
                || (config.is_io() && (command & COMMAND_REG_IO_SPACE_MASK == 0))
            {
                return None;
            }

            // The address may have been modified by the guest, so the value in bar_configs
            // may be outdated. Replace it with the current value.
            config.addr = self.get_bar_addr(bar_num);
            Some(config)
        } else {
            None
        }
    }

    /// Returns the type of the given BAR region.
    pub fn get_bar_type(&self, bar_num: PciBarIndex) -> Option<PciBarRegionType> {
        self.bar_configs.get(bar_num)?.map(|c| c.region_type)
    }

    /// Returns the address of the given BAR region.
    pub fn get_bar_addr(&self, bar_num: PciBarIndex) -> u64 {
        let bar_idx = if bar_num == ROM_BAR_IDX {
            ROM_BAR_REG
        } else {
            BAR0_REG + bar_num
        };

        let bar_type = match self.get_bar_type(bar_num) {
            Some(t) => t,
            None => return 0,
        };

        match bar_type {
            PciBarRegionType::IoRegion => u64::from(self.registers[bar_idx] & BAR_IO_ADDR_MASK),
            PciBarRegionType::Memory32BitRegion => {
                u64::from(self.registers[bar_idx] & BAR_MEM_ADDR_MASK)
            }
            PciBarRegionType::Memory64BitRegion => {
                u64::from(self.registers[bar_idx] & BAR_MEM_ADDR_MASK)
                    | (u64::from(self.registers[bar_idx + 1]) << 32)
            }
        }
    }

    /// Configures the IRQ line and pin used by this device.
    pub fn set_irq(&mut self, line: u8, pin: PciInterruptPin) {
        // `pin` is 1-based in the pci config space.
        let pin_idx = (pin as u32) + 1;
        self.registers[INTERRUPT_LINE_PIN_REG] = (self.registers[INTERRUPT_LINE_PIN_REG]
            & 0xffff_0000)
            | (pin_idx << 8)
            | u32::from(line);
    }

    /// Adds the capability `cap_data` to the list of capabilities.
    /// `cap_data` should include the two-byte PCI capability header (type, next),
    /// but not populate it. Correct values will be generated automatically based
    /// on `cap_data.id()`.
    #[allow(dead_code)]
    pub fn add_capability(&mut self, cap_data: &dyn PciCapability) -> Result<usize> {
        let total_len = cap_data.bytes().len();
        // Check that the length is valid.
        if cap_data.bytes().is_empty() {
            return Err(Error::CapabilityEmpty);
        }
        let (cap_offset, tail_offset) = match self.last_capability {
            Some((offset, len)) => (Self::next_dword(offset, len), offset + 1),
            None => (FIRST_CAPABILITY_OFFSET, CAPABILITY_LIST_HEAD_OFFSET),
        };
        let end_offset = cap_offset
            .checked_add(total_len)
            .ok_or(Error::CapabilitySpaceFull(total_len))?;
        if end_offset > CAPABILITY_MAX_OFFSET {
            return Err(Error::CapabilitySpaceFull(total_len));
        }
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;
        self.write_byte_internal(tail_offset, cap_offset as u8, false);
        self.write_byte_internal(cap_offset, cap_data.id() as u8, false);
        self.write_byte_internal(cap_offset + 1, 0, false); // Next pointer.
        for (i, byte) in cap_data.bytes().iter().enumerate().skip(2) {
            self.write_byte_internal(cap_offset + i, *byte, false);
        }
        let reg_idx = cap_offset / 4;
        for (i, dword) in cap_data.writable_bits().iter().enumerate() {
            self.writable_bits[reg_idx + i] = *dword;
        }
        self.last_capability = Some((cap_offset, total_len));
        Ok(cap_offset)
    }

    // Find the next aligned offset after the one given.
    fn next_dword(offset: usize, len: usize) -> usize {
        let next = offset + len;
        (next + 3) & !3
    }
}

impl PciBarConfiguration {
    pub fn new(
        bar_idx: PciBarIndex,
        size: u64,
        region_type: PciBarRegionType,
        prefetchable: PciBarPrefetchable,
    ) -> Self {
        PciBarConfiguration {
            bar_idx,
            addr: 0,
            size,
            region_type,
            prefetchable,
        }
    }
    #[allow(dead_code)]
    pub fn bar_index(&self) -> PciBarIndex {
        self.bar_idx
    }

    pub fn reg_index(&self) -> usize {
        if self.bar_idx == ROM_BAR_IDX {
            ROM_BAR_REG
        } else {
            BAR0_REG + self.bar_idx
        }
    }
    #[allow(dead_code)]
    pub fn address(&self) -> u64 {
        self.addr
    }
    #[allow(dead_code)]
    pub fn address_range(&self) -> std::ops::Range<u64> {
        self.addr..self.addr + self.size
    }
    #[allow(dead_code)]
    pub fn set_address(mut self, addr: u64) -> Self {
        self.addr = addr;
        self
    }
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn is_expansion_rom(&self) -> bool {
        self.bar_idx == ROM_BAR_IDX
    }

    pub fn is_memory(&self) -> bool {
        matches!(
            self.region_type,
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion
        )
    }
    #[allow(dead_code)]
    pub fn is_64bit_memory(&self) -> bool {
        self.region_type == PciBarRegionType::Memory64BitRegion
    }

    pub fn is_io(&self) -> bool {
        self.region_type == PciBarRegionType::IoRegion
    }

    #[allow(dead_code)]
    pub fn is_prefetchable(&self) -> bool {
        self.is_memory() && self.prefetchable == PciBarPrefetchable::Prefetchable
    }
}
