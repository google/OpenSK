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

use tock_registers::register_bitfields;

register_bitfields! [u32,
    // Generic or shared bitfields
    pub Task [
        ENABLE OFFSET(0) NUMBITS(1)
    ],

    pub Byte [
        VALUE OFFSET(0) NUMBITS(8)
    ],

    pub Busy [
        /// Asserted when AES_BUSY or DES_BUSY or HASH_BUSY are asserted or when the DIN FIFO is not empty
        BUSY OFFSET(0) NUMBITS(1) [
            Ready = 0,
            Busy = 1
        ]
    ],

    // CC_CTL register bitfields
    pub CryptoMode [
        /// Determines the active cryptographic engine
        MODE OFFSET(0) NUMBITS(5) [
            Bypass = 0,
            Aes = 1,
            AesToHash = 2,
            AesAndHash = 3,
            Des = 4,
            DesToHash = 5,
            DesAndHash = 6,
            Hash = 7,
            AesMacAndBypass = 9,
            AesToHashAndDout = 10
        ]
    ],

    // HOST_RGF register bitfields
    pub Interrupts [
        /// This interrupt is asserted when all data was delivered to DIN buffer from SRAM
        SRAM_TO_DIN OFFSET(4) NUMBITS(1),
        /// This interrupt is asserted when all data was delivered to SRAM buffer from DOUT
        DOUT_TO_SRAM OFFSET(5) NUMBITS(1),
        /// This interrupt is asserted when all data was delivered to DIN buffer from memory
        MEM_TO_DIN OFFSET(6) NUMBITS(1),
        /// This interrupt is asserted when all data was delivered to memory buffer from DOUT
        DOUT_TO_MEM OFFSET(7) NUMBITS(1),
        AXI_ERROR OFFSET(8) NUMBITS(1),
        /// The PKA end of operation interrupt status
        PKA_EXP OFFSET(9) NUMBITS(1),
        /// The RNG interrupt status
        RNG OFFSET(10) NUMBITS(1),
        /// The GPR interrupt status
        SYM_DMA_COMPLETED OFFSET(11) NUMBITS(1)
    ],

    pub RgfEndianness [
        /// DOUT write endianness
        DOUT_WR_BG OFFSET(3) NUMBITS(1) [
            LittleEndian = 0,
            BigEndian = 1
        ],
        /// DIN write endianness
        DIN_RD_BG OFFSET(7) NUMBITS(1) [
            LittleEndian = 0,
            BigEndian = 1
        ],
        /// DOUT write word endianness
        DOUT_WR_WBG OFFSET(11) NUMBITS(1) [
            LittleEndian = 0,
            BigEndian = 1
        ],
        /// DIN write word endianness
        DIN_RD_WBG OFFSET(15) NUMBITS(1) [
            LittleEndian = 0,
            BigEndian = 1
        ]
    ],

    // DIN and DOUT register bitfields
    pub LliWord1 [
        /// Total number of bytes to read using DMA in this entry
        BYTES_NUM OFFSET(0) NUMBITS(30),
        /// Indicates the first LLI entry
        FIRST OFFSET(30) NUMBITS(1),
        /// Indicates the last LLI entry
        LAST OFFSET(31) NUMBITS(1)
    ],

    pub HashControl [
        // bit 2 is reserved but to simplify the logic we include it in the bitfield.
        MODE OFFSET(0) NUMBITS(4) [
            MD5 = 0,
            SHA1 = 1,
            SHA256 = 2,
            SHA224 = 10
        ]
    ],

    pub PaddingConfig [
        /// Enable Padding generation. must be reset upon completion of padding.
        DO_PAD OFFSET(2) NUMBITS(1)
    ]
];
