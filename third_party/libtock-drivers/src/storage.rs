// Copyright 2023 Google LLC
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

use crate::result::{TockError, TockResult};
use crate::util::Util;
use core::cell::Cell;
use core::convert::TryFrom;
use libtock_platform as platform;
use libtock_platform::{share, syscall_class, DefaultConfig, ErrorCode, Syscalls};

const DRIVER_NUMBER: u32 = 0x50003;

mod subscribe_nr {
    pub const DONE: u32 = 0;
}

mod command_nr {
    pub const GET_INFO: u32 = 1;
    pub mod get_info_nr {
        pub const WORD_SIZE: u32 = 0;
        pub const PAGE_SIZE: u32 = 1;
        pub const MAX_WORD_WRITES: u32 = 2;
        pub const MAX_PAGE_ERASES: u32 = 3;
    }
    pub const WRITE_SLICE: u32 = 2;
    pub const ERASE_PAGE: u32 = 3;
}

mod ro_allow_nr {
    pub const WRITE_SLICE: u32 = 0;
}

mod memop_nr {
    pub const STORAGE_CNT: u32 = 12;
    pub const STORAGE_PTR: u32 = 13;
    pub const STORAGE_LEN: u32 = 14;
    pub const STORAGE_TYPE: u32 = 15;
}

pub enum StorageType {
    Store = 1,
    Partition = 2,
}

impl TryFrom<u32> for StorageType {
    type Error = TockError;

    fn try_from(number: u32) -> Result<Self, TockError> {
        match number {
            1 => Ok(StorageType::Store),
            2 => Ok(StorageType::Partition),
            _ => Err(TockError::from(ErrorCode::Fail)),
        }
    }
}

pub struct Storage<
    S: Syscalls,
    C: platform::subscribe::Config + platform::allow_ro::Config = DefaultConfig,
>(S, C);

impl<S: Syscalls, C: platform::subscribe::Config + platform::allow_ro::Config> Storage<S, C> {
    fn get_info(nr: u32, arg: u32) -> TockResult<u32> {
        Ok(S::command(DRIVER_NUMBER, command_nr::GET_INFO, nr, arg)
            .to_result::<u32, ErrorCode>()?)
    }

    fn memop(nr: u32, arg: u32) -> TockResult<u32> {
        let registers = unsafe { S::syscall2::<{ syscall_class::MEMOP }>([nr.into(), arg.into()]) };

        let r0 = registers[0].as_u32();
        let r1 = registers[1].as_u32();

        // Make sure r0 is the `success with u32` (129) return variant.
        // Then return the value in r1 as u32. See:
        // https://github.com/tock/tock/blob/master/doc/reference/trd104-syscalls.md#32-return-values
        match (r0, r1) {
            (129, r1) => Ok(r1),
            (_, _) => Err(TockError::from(ErrorCode::Fail)),
        }
    }

    fn block_command(driver: u32, cmd: u32, arg1: u32, arg2: u32) -> TockResult<()> {
        let called: Cell<Option<(u32,)>> = Cell::new(None);

        Ok(share::scope(|subscribe| {
            S::subscribe::<_, _, C, DRIVER_NUMBER, { subscribe_nr::DONE }>(subscribe, &called)?;
            S::command(driver, cmd, arg1, arg2).to_result::<(), ErrorCode>()?;
            Util::<S>::yieldk_for(|| called.get().is_some());
            if called.get().unwrap().0 == 0 {
                Ok(())
            } else {
                Err(ErrorCode::Fail)
            }
        })?)
    }

    pub fn write_slice(ptr: usize, value: &[u8]) -> TockResult<()> {
        share::scope(|allow_ro| {
            S::allow_ro::<C, DRIVER_NUMBER, { ro_allow_nr::WRITE_SLICE }>(allow_ro, value)?;
            Self::block_command(
                DRIVER_NUMBER,
                command_nr::WRITE_SLICE,
                ptr as u32,
                value.len() as u32,
            )
        })
    }

    pub fn erase_page(ptr: usize, page_length: usize) -> TockResult<()> {
        Self::block_command(
            DRIVER_NUMBER,
            command_nr::ERASE_PAGE,
            ptr as u32,
            page_length as u32,
        )
    }

    pub fn word_size() -> TockResult<usize> {
        Ok(Self::get_info(command_nr::get_info_nr::WORD_SIZE, 0)? as usize)
    }

    pub fn page_size() -> TockResult<usize> {
        Ok(Self::get_info(command_nr::get_info_nr::PAGE_SIZE, 0)? as usize)
    }

    pub fn max_word_writes() -> TockResult<usize> {
        Ok(Self::get_info(command_nr::get_info_nr::MAX_WORD_WRITES, 0)? as usize)
    }

    pub fn max_page_erases() -> TockResult<usize> {
        Ok(Self::get_info(command_nr::get_info_nr::MAX_PAGE_ERASES, 0)? as usize)
    }

    pub fn storage_cnt() -> TockResult<usize> {
        Ok(Self::memop(memop_nr::STORAGE_CNT, 0)? as usize)
    }

    pub fn storage_ptr(index: usize) -> TockResult<usize> {
        Ok(Self::memop(memop_nr::STORAGE_PTR, index as u32)? as usize)
    }

    pub fn storage_len(index: usize) -> TockResult<usize> {
        Ok(Self::memop(memop_nr::STORAGE_LEN, index as u32)? as usize)
    }

    pub fn storage_type(index: usize) -> TockResult<StorageType> {
        StorageType::try_from(Self::memop(memop_nr::STORAGE_TYPE, index as u32)?)
    }
}
