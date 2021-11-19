// Copyright 2020-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::bitfields::{
    Busy, CryptoMode, HashControl, Interrupts, LliWord1, PaddingConfig, RgfEndianness, Task,
};
use tock_registers::{
    register_structs,
    registers::{ReadOnly, ReadWrite, WriteOnly},
};

register_structs! {
    pub CryptoCellControlRegisters {
        /// Defines the cryptographic flow
        (0x0000 => pub crypto_ctl: WriteOnly<u32, CryptoMode::Register>),
        (0x0004 => _reserved0),
        /// This register is set whent the cryptographic core is busy
        (0x0010 => pub crypto_busy: ReadOnly<u32, Busy::Register>),
        (0x0014 => _reserved1),
        /// This register is set when the Hash engine is busy
        (0x001C => pub hash_busy: ReadOnly<u32, Busy::Register>),
        (0x0020 => @END),
    }
}

register_structs! {
    pub CryptoCellDinRegisters {
        (0x0000 => _reserved0),
        /// Indicates whether memoty (AXI) source DMA (DIN) is busy
        (0x0020 => pub mem_dma_busy: ReadOnly<u32, Busy::Register>),
        (0x0024 => _reserved1),
        /// This register is used in direct LLI mode - holds the location of the data source
        /// in the memory (AXI)
        (0x0028 => pub src_lli_word0: WriteOnly<u32>),
        /// This register is used in direct LLI mode - holds the number of bytes to be read
        /// from the memory (AXI).
        /// Writing to this register triggers the DMA.
        (0x002C => pub src_lli_word1: WriteOnly<u32, LliWord1::Register>),
        (0x0030 => @END),
    }
}

register_structs! {
    pub CryptoCellHashRegisters {
        /// Write initial hash value or read final hash value
        (0x0000 => pub hash: [ReadWrite<u32>; 9]),
        (0x0024 => _reserved0),
        /// HW padding automatically activated by engine.
        /// For the special case of ZERO bytes data vector this register should not be used! instead use HASH_PAD_CFG
        (0x0044 => pub auto_hw_padding: WriteOnly<u32, Task::Register>),
        (0x0048 => _reserved1),
        /// Selects which HASH mode to run
        (0x0180 => pub control: ReadWrite<u32, HashControl::Register>),
        /// This register enables the hash hw padding.
        (0x0184 => pub padding: ReadWrite<u32, Task::Register>),
        /// HASH_PAD_CFG Register.
        (0x0188 => pub pad_config: ReadWrite<u32, PaddingConfig::Register>),
        /// This register hold the length of current hash operation
        (0x018C => pub hash_len_lsb: ReadWrite<u32>),
        /// This register hold the length of current hash operation
        (0x0190 => pub hash_len_msb: ReadWrite<u32>),
        (0x0194 => @END),
    }
}

register_structs! {
    pub CryptoCellHostRgfRegisters {
        /// The Interrupt Request register.
        /// Each bit of this register holds the interrupt status of a single interrupt source.
        (0x0000 => pub interrupts: ReadOnly<u32, Interrupts::Register>),
        /// The Interrupt Mask register. Each bit of this register holds the mask of a single
        /// interrupt source.
        (0x0004 => pub interrupt_mask: ReadWrite<u32, Interrupts::Register>),
        /// Interrupt Clear Register
        (0x0008 => pub interrupt_clear: WriteOnly<u32, Interrupts::Register>),
        /// This register defines the endianness of the Host-accessible registers.
        (0x000C => pub endian: ReadWrite<u32, RgfEndianness::Register>),
        (0x0010 => _reserved0),
        /// This register holds the CryptoCell product signature.
        (0x0024 => pub signature: ReadOnly<u32>),
        (0x0028 => @END),
    }
}

register_structs! {
    pub CryptoCellMiscRegisters {
        (0x0000 => _reserved0),
        /// The HASH clock enable register
        (0x0018 => pub hash_clk_enable: ReadWrite<u32, Task::Register>),
        /// The PKA clock enable register
        (0x001C => _reserved1),
        /// The DMA clock enable register
        (0x0020 => pub dma_clk_enable: ReadWrite<u32, Task::Register>),
        /// the CryptoCell clocks' status register
        (0x0024 => @END),
    }
}

register_structs! {
    pub NordicCC310Registers {
        (0x0000 => pub enable: ReadWrite<u32, Task::Register>),
        (0x0004 => @END),
    },

    pub CryptoCellRegisters {
        (0x0000 => _reserved0),
        /// HASH registers
        /// - Base address: 0x0640
        (0x0640 => pub hash: CryptoCellHashRegisters),
        (0x07D4 => _reserved1),
        /// Misc registers
        /// - Base address: 0x0800
        (0x0800 => pub misc: CryptoCellMiscRegisters),
        (0x0824 => _reserved2),
        /// CryptoCell control registers
        /// - Base address: 0x0900
        (0x0900 => pub ctrl: CryptoCellControlRegisters),
        (0x0920 => _reserved3),
        /// HOST_RGF registers
        /// - Base address: 0x0A00
        (0x0A00 => pub host_rgf: CryptoCellHostRgfRegisters),
        (0x0A28 => _reserved4),
        /// DIN registers
        /// - Base address: 0x0C00
        (0x0C00 => pub din: CryptoCellDinRegisters),
        (0x0C30 => @END),
    }
}
