// Copyright 2019-2022 Google LLC
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

//! CryptoCell 310
//!
//! Author
//! -------------------
//!
//! * Author: Jean-Michel Picod <jmichel@google.com>
//! * Date: October 1 2019

use super::bitfields;
use super::registers::{CryptoCellRegisters, NordicCC310Registers};
use super::static_ref::StaticRef;
use core::cell::Cell;
#[cfg(debug_assertions)]
use rtt_target::rprintln;

const SHA256_INIT_VALUE: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

#[derive(Copy, Clone)]
enum DigestAlgorithm {
    Sha256 = 2,
}

#[derive(Copy, Clone)]
enum OperationMode {
    Idle,
    Hash,
}

pub struct CryptoCell310 {
    registers: StaticRef<CryptoCellRegisters>,
    power: StaticRef<NordicCC310Registers>,
    current_op: Cell<OperationMode>,

    hash_ctx: Cell<[u32; 8]>,
    hash_total_size: Cell<u64>,
}

const CC310_BASE: StaticRef<CryptoCellRegisters> =
    unsafe { StaticRef::new(0x5002B000 as *const CryptoCellRegisters) };
const CC310_POWER: StaticRef<NordicCC310Registers> =
    unsafe { StaticRef::new(0x5002A500 as *const NordicCC310Registers) };

// Identification "signature" for CryptoCell. According to the documentation, the value
// held by this register is a fixed value, used by Host driver to verify CryptoCell presence
// at this address.
// This value was read from a CryptoCell-310 on a nRF52840-dongle kit.
const CC310_SIGNATURE: u32 = 0x20E00000;

impl CryptoCell310 {
    /// Creates a new instance of cryptocell state.
    pub const fn new() -> Self {
        CryptoCell310 {
            registers: CC310_BASE,
            power: CC310_POWER,
            current_op: Cell::new(OperationMode::Idle),

            hash_ctx: Cell::new(SHA256_INIT_VALUE),
            hash_total_size: Cell::new(0),
        }
    }

    fn enable(&self) {
        self.power.enable.write(bitfields::Task::ENABLE::SET);
        for _i in 1..10 {
            let read_signature = self.registers.host_rgf.signature.get();
            if read_signature != CC310_SIGNATURE {
                #[cfg(debug_assertions)]
                rprintln!(
                    "[loop {}] Invalid CC310 signature. Expected {}, got {}\n",
                    _i,
                    CC310_SIGNATURE,
                    read_signature
                );
            } else {
                break;
            }
        }
        if self.registers.host_rgf.signature.get() != CC310_SIGNATURE {
            panic!("Failed to initialize CC310");
        }
        // Make sure everything is set to little endian
        self.registers.host_rgf.endian.write(
            bitfields::RgfEndianness::DOUT_WR_BG::LittleEndian
                + bitfields::RgfEndianness::DIN_RD_BG::LittleEndian
                + bitfields::RgfEndianness::DOUT_WR_WBG::LittleEndian
                + bitfields::RgfEndianness::DIN_RD_WBG::LittleEndian,
        );
        // Always start the clock for DMA engine. It's too hard to keep
        // track of which submodule needs DMA otherwise.
        self.registers
            .misc
            .dma_clk_enable
            .write(bitfields::Task::ENABLE::SET);
        self.registers.host_rgf.interrupt_mask.write(
            bitfields::Interrupts::SRAM_TO_DIN::CLEAR
                + bitfields::Interrupts::DOUT_TO_SRAM::CLEAR
                + bitfields::Interrupts::MEM_TO_DIN::CLEAR
                + bitfields::Interrupts::DOUT_TO_MEM::CLEAR
                + bitfields::Interrupts::AXI_ERROR::SET
                + bitfields::Interrupts::PKA_EXP::SET
                + bitfields::Interrupts::RNG::SET
                + bitfields::Interrupts::SYM_DMA_COMPLETED::CLEAR,
        );
    }

    fn disable(&self) {
        self.registers.host_rgf.interrupt_mask.set(0);
        self.power.enable.write(bitfields::Task::ENABLE::CLEAR);
        self.registers
            .misc
            .dma_clk_enable
            .write(bitfields::Task::ENABLE::CLEAR);
    }

    fn clear_data(&self) {
        let mut ctx = self.hash_ctx.get();
        ctx.iter_mut().for_each(|b| *b = 0);
        self.hash_ctx.set(ctx);
        self.hash_total_size.set(0);
    }

    /// Adds data to the current hash computation.
    ///
    /// You have to know in advance if is this is going to be the last block, and indicate that
    /// correctly. Sizes of chunks before the last need to be multiples of 64.
    pub fn update(&self, data: &[u8], is_last_block: bool) {
        // Start CryptoCell
        self.enable();

        while self.registers.ctrl.hash_busy.is_set(bitfields::Busy::BUSY) {}
        while self
            .registers
            .ctrl
            .crypto_busy
            .is_set(bitfields::Busy::BUSY)
        {}
        while self
            .registers
            .din
            .mem_dma_busy
            .is_set(bitfields::Busy::BUSY)
        {}

        // Start HASH module and configure it
        self.current_op.set(OperationMode::Hash);
        self.registers
            .misc
            .hash_clk_enable
            .write(bitfields::Task::ENABLE::SET);
        self.registers
            .ctrl
            .crypto_ctl
            .write(bitfields::CryptoMode::MODE::Hash);
        self.registers
            .hash
            .padding
            .write(bitfields::Task::ENABLE::SET);
        let size = self.hash_total_size.get();
        self.registers.hash.hash_len_lsb.set(size as u32);
        self.registers
            .hash
            .hash_len_msb
            .set(size.wrapping_shr(32) as u32);
        self.registers
            .hash
            .control
            .set(DigestAlgorithm::Sha256 as u32);

        // Digest must be set backwards because writing to HASH[0]
        // starts computation
        let mut digest = self.hash_ctx.get();
        for i in (0..digest.len()).rev() {
            self.registers.hash.hash[i].set(digest[i]);
        }
        while self.registers.ctrl.hash_busy.is_set(bitfields::Busy::BUSY) {}

        // Process data
        if !data.is_empty() {
            if is_last_block {
                self.registers
                    .hash
                    .auto_hw_padding
                    .write(bitfields::Task::ENABLE::SET);
            }
            self.registers.din.src_lli_word0.set(data.as_ptr() as u32);
            self.registers
                .din
                .src_lli_word1
                .write(bitfields::LliWord1::BYTES_NUM.val(data.len() as u32));
            while !self
                .registers
                .host_rgf
                .interrupts
                .is_set(bitfields::Interrupts::MEM_TO_DIN)
            {}
            self.registers
                .host_rgf
                .interrupt_clear
                .write(bitfields::Interrupts::MEM_TO_DIN::SET);
        } else {
            // use DO_PAD to complete padding of previous operation
            self.registers
                .hash
                .pad_config
                .write(bitfields::PaddingConfig::DO_PAD::SET);
        }
        while self
            .registers
            .ctrl
            .crypto_busy
            .is_set(bitfields::Busy::BUSY)
        {}
        while self
            .registers
            .din
            .mem_dma_busy
            .is_set(bitfields::Busy::BUSY)
        {}

        // Update context and total size
        for i in (0..digest.len()).rev() {
            digest[i] = self.registers.hash.hash[i].get();
        }
        self.hash_ctx.set(digest);
        let new_size: u64 = ((self.registers.hash.hash_len_msb.get() as u64) << 32)
            + (self.registers.hash.hash_len_lsb.get() as u64);
        self.hash_total_size.set(new_size);

        // Disable HASH module
        self.registers
            .hash
            .padding
            .write(bitfields::Task::ENABLE::SET);
        self.registers
            .hash
            .auto_hw_padding
            .write(bitfields::Task::ENABLE::CLEAR);
        self.registers
            .hash
            .pad_config
            .write(bitfields::PaddingConfig::DO_PAD::CLEAR);
        while self
            .registers
            .ctrl
            .crypto_busy
            .is_set(bitfields::Busy::BUSY)
        {}
        self.registers
            .misc
            .hash_clk_enable
            .write(bitfields::Task::ENABLE::CLEAR);

        self.disable();
    }

    /// Clears the data for potential reuse, and returns the result.
    pub fn finalize_and_clear(&self) -> [u8; 32] {
        use byteorder::{BigEndian, ByteOrder};
        let words = self.hash_ctx.get();
        let mut bytes = [0u8; 32];
        for (i, word) in words.iter().enumerate() {
            BigEndian::write_u32(&mut bytes[4 * i..4 * i + 4], *word);
        }
        self.clear_data();
        bytes
    }
}
