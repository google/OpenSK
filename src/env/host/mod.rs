// FIXME: Add license, descriptions.

use crate::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::upgrade_storage::UpgradeStorage;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::{Channel, Transport};
use crate::env::{Env, IOChannel, SendOrRecvStatus, UserPresence};
use persistent_store::{FileOptions, FileStorage, StorageError, StorageResult, Store};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rng256::Rng256;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub struct HostEnv {
    rng: HostRng256,
    user_presence: HostUserPresence,
    store: Store<FileStorage>,
    io_channel: HostIOChannel,
}

pub enum HostIOChannel {
    Stdio,
    UnixSocket(UnixStream),
    // TODO: add UHIDDevice, TCPStream, Pipe etc.
}

impl HostIOChannel {
    fn set_read_timeout(&mut self, timeout: isize) -> io::Result<()> {
        match self {
            // FIXME: Implement timeout on Stdio.
            HostIOChannel::Stdio => Ok(()),
            HostIOChannel::UnixSocket(unix_stream) => {
                unix_stream.set_read_timeout(if timeout < 0 {
                    None
                } else {
                    Some(Duration::from_millis(timeout as u64))
                })
            }
        }
    }

    fn set_write_timeout(&mut self, timeout: isize) -> io::Result<()> {
        match self {
            // FIXME: Implement timeout on Stdio.
            HostIOChannel::Stdio => Ok(()),
            HostIOChannel::UnixSocket(unix_stream) => {
                unix_stream.set_write_timeout(if timeout < 0 {
                    None
                } else {
                    Some(Duration::from_millis(timeout as u64))
                })
            }
        }
    }

    fn read_buf(&mut self, buf: &mut [u8; 64], timeout: isize) -> io::Result<()> {
        self.set_read_timeout(timeout)?;
        match self {
            HostIOChannel::Stdio => io::stdin().read_exact(buf),
            HostIOChannel::UnixSocket(unix_stream) => unix_stream.read_exact(buf),
        }
    }

    fn write_buf(&mut self, buf: &mut [u8; 64], timeout: isize) -> io::Result<()> {
        self.set_write_timeout(timeout)?;
        match self {
            HostIOChannel::Stdio => {
                io::stdout().write_all(buf)?;
                io::stdout().flush()
            }
            HostIOChannel::UnixSocket(unix_stream) => {
                unix_stream.write_all(buf)?;
                unix_stream.flush()
            }
        }
    }
}

impl IOChannel for HostIOChannel {
    fn recv_with_timeout(
        &mut self,
        buf: &mut [u8; 64],
        timeout: isize,
    ) -> Option<SendOrRecvStatus> {
        match self.read_buf(buf, timeout) {
            Ok(_) => Some(SendOrRecvStatus::Received(Transport::MainHid)),
            Err(_) => Some(SendOrRecvStatus::Error),
        }
    }
    fn send_or_recv_with_timeout(
        &mut self,
        buf: &mut [u8; 64],
        timeout: isize,
        _transport: Transport,
    ) -> Option<SendOrRecvStatus> {
        match self.write_buf(buf, timeout) {
            Ok(_) => Some(SendOrRecvStatus::Sent),
            Err(_) => Some(SendOrRecvStatus::Error),
        }
    }
}

pub struct HostRng256 {
    rng: StdRng,
}

impl HostRng256 {
    pub fn seed_from_u64(&mut self, state: u64) {
        self.rng = StdRng::seed_from_u64(state);
    }
}

impl Rng256 for HostRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        let mut result = [Default::default(); 32];
        self.rng.fill(&mut result);
        result
    }
}

pub struct HostUserPresence {
    check: Box<dyn Fn(Channel) -> Result<(), Ctap2StatusCode>>,
}

pub struct TestWrite;

impl core::fmt::Write for TestWrite {
    fn write_str(&mut self, _: &str) -> core::fmt::Result {
        Ok(())
    }
}

fn new_storage(path: &Path, options: FileOptions) -> StorageResult<FileStorage> {
    FileStorage::new(path, options)
}

impl HostEnv {
    pub fn new(storage_path: &Path) -> Self {
        let rng = HostRng256 {
            rng: StdRng::seed_from_u64(0),
        };
        // TODO: Implement real user presence check, instead of automatic "yes".
        let user_presence = HostUserPresence {
            check: Box::new(|_| Ok(())),
        };
        // FIXME: Move to parameters.
        let options = FileOptions {
            word_size: 4,
            page_size: 0x1000,
            num_pages: 20,
        };
        let storage = new_storage(storage_path, options).unwrap();
        let store = Store::new(storage).ok().unwrap();
        // FIXME: Move to parameters.
        let io_channel = HostIOChannel::Stdio;
        HostEnv {
            rng,
            user_presence,
            store,
            io_channel,
        }
    }

    pub fn rng(&mut self) -> &mut HostRng256 {
        &mut self.rng
    }
}

impl HostUserPresence {
    pub fn set(&mut self, check: impl Fn(Channel) -> Result<(), Ctap2StatusCode> + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for HostUserPresence {
    fn check(&mut self, channel: Channel) -> Result<(), Ctap2StatusCode> {
        (self.check)(channel)
    }
}

impl UpgradeStorage for HostEnv {
    #[allow(unused_variables)]
    fn read_partition(&self, offset: usize, length: usize) -> StorageResult<&[u8]> {
        Err(StorageError::CustomError)
    }

    #[allow(unused_variables)]
    fn write_partition(&mut self, offset: usize, data: &[u8]) -> StorageResult<()> {
        Err(StorageError::CustomError)
    }

    fn partition_address(&self) -> usize {
        0
    }

    fn partition_length(&self) -> usize {
        0
    }

    fn read_metadata(&self) -> StorageResult<&[u8]> {
        Err(StorageError::CustomError)
    }

    #[allow(unused_variables)]
    fn write_metadata(&mut self, data: &[u8]) -> StorageResult<()> {
        Err(StorageError::CustomError)
    }
}

impl FirmwareProtection for HostEnv {
    fn lock(&mut self) -> bool {
        true
    }
}

impl Env for HostEnv {
    type Rng = HostRng256;
    type UserPresence = HostUserPresence;
    type Storage = FileStorage;
    type FirmwareProtection = Self;
    type UpgradeStorage = Self;
    type Write = TestWrite;
    type Customization = CustomizationImpl;
    type IOChannel = HostIOChannel;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn store(&mut self) -> &mut Store<Self::Storage> {
        &mut self.store
    }

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection {
        self
    }

    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage> {
        None
    }

    fn write(&mut self) -> Self::Write {
        TestWrite
    }

    fn customization(&self) -> &Self::Customization {
        &DEFAULT_CUSTOMIZATION
    }

    fn io_channel(&mut self) -> &mut Self::IOChannel {
        &mut self.io_channel
    }
}
