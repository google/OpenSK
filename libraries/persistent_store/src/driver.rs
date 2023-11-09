// Copyright 2019-2020 Google LLC
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

//! Store wrapper for testing.
//!
//! [`StoreDriver`] wraps a [`Store`] and compares its behavior with its associated [`StoreModel`].

use crate::format::{Format, Position};
#[cfg(feature = "std")]
use crate::StoreUpdate;
use crate::{
    BufferCorruptFunction, BufferOptions, BufferStorage, Nat, Store, StoreError, StoreHandle,
    StoreModel, StoreOperation, StoreResult,
};

/// Tracks the store behavior against its model and its storage.
#[derive(Clone)]
pub enum StoreDriver {
    /// When the store is running.
    On(StoreDriverOn),

    /// When the store is off.
    Off(StoreDriverOff),
}

/// Keeps a power-on store and its model in sync.
#[derive(Clone)]
pub struct StoreDriverOn {
    /// The store being tracked.
    store: Store<BufferStorage>,

    /// The model associated to the store.
    model: StoreModel,
}

/// Keeps a power-off store and its potential models in sync.
#[derive(Clone)]
pub struct StoreDriverOff {
    /// The storage of the store being tracked.
    storage: BufferStorage,

    /// The last valid model before power off.
    model: StoreModel,

    /// In case of interrupted operation, the invariant after completion.
    complete: Option<Complete>,
}

/// The invariant a store must satisfy if an interrupted operation completes.
#[derive(Clone)]
struct Complete {
    /// The model after the operation completes.
    model: StoreModel,

    /// The entries that should be deleted after the operation completes.
    deleted: Vec<StoreHandle>,
}

/// Specifies an interruption.
pub struct StoreInterruption<'a> {
    /// After how many storage operations the interruption should happen.
    pub delay: usize,

    /// How the interrupted operation should be corrupted.
    pub corrupt: BufferCorruptFunction<'a>,
}

/// Possible ways a driver operation may fail.
#[derive(Debug)]
pub enum StoreInvariant {
    /// The store reached its lifetime.
    ///
    /// This is not simulated by the model. So the operation should be ignored.
    NoLifetime,

    /// The store returned an unexpected error.
    StoreError(StoreError),

    /// The store did not recover an interrupted operation.
    Interrupted {
        /// The reason why the store didn't rollback the operation.
        rollback: Box<StoreInvariant>,

        /// The reason why the store didn't complete the operation.
        complete: Box<StoreInvariant>,
    },

    /// The store returned a different result than the model.
    DifferentResult {
        /// The result of the store.
        store: StoreResult<()>,

        /// The result of the model.
        model: StoreResult<()>,
    },

    /// The store did not wipe an entry.
    NotWiped {
        /// The key of the entry that has not been wiped.
        key: usize,

        /// The value of the entry in the storage.
        value: Vec<u8>,
    },

    /// The store has an entry not present in the model.
    OnlyInStore {
        /// The key of the additional entry.
        key: usize,
    },

    /// The store has a different value than the model for an entry.
    DifferentValue {
        /// The key of the entry with a different value.
        key: usize,

        /// The value of the entry in the store.
        store: Box<[u8]>,

        /// The value of the entry in the model.
        model: Box<[u8]>,
    },

    /// The store is missing an entry from the model.
    OnlyInModel {
        /// The key of the missing entry.
        key: usize,
    },

    /// The store reports a different capacity than the model.
    DifferentCapacity {
        /// The capacity according to the store.
        store: usize,

        /// The capacity according to the model.
        model: usize,
    },

    /// The store failed to track the number of erase cycles correctly.
    DifferentErase {
        /// The first page in physical storage order with a wrong value.
        page: usize,

        /// How many times the page has been erased according to the store.
        store: usize,

        /// How many times the page has been erased according to the model.
        model: usize,
    },

    /// The store failed to track the number of word writes correctly.
    DifferentWrite {
        /// The first page in physical storage order with a wrong value.
        page: usize,

        /// The first word in the page with a wrong value.
        word: usize,

        /// How many times the word has been written according to the store.
        ///
        /// This value is exact only for the metadata of the page. For the content of the page, it
        /// is set to:
        /// - 0 if the word is after the tail. Such word should not have been written.
        /// - 1 if the word is before the tail. Such word may or may not have been written.
        store: usize,

        /// How many times the word has been written according to the model.
        ///
        /// This value is exact only for the metadata of the page. For the content of the page, it
        /// is set to:
        /// - 0 if the word was not written.
        /// - 1 if the word was written.
        model: usize,
    },
}

impl From<StoreError> for StoreInvariant {
    fn from(error: StoreError) -> StoreInvariant {
        StoreInvariant::StoreError(error)
    }
}

impl StoreDriver {
    /// Provides read-only access to the storage.
    pub fn storage(&self) -> &BufferStorage {
        match self {
            StoreDriver::On(x) => x.store().storage(),
            StoreDriver::Off(x) => x.storage(),
        }
    }

    /// Provides read-only access to the model.
    pub fn model(&self) -> &StoreModel {
        match self {
            StoreDriver::On(x) => x.model(),
            StoreDriver::Off(x) => x.model(),
        }
    }

    /// Extracts the power-on version of the driver.
    pub fn on(self) -> Option<StoreDriverOn> {
        match self {
            StoreDriver::On(x) => Some(x),
            StoreDriver::Off(_) => None,
        }
    }

    /// Powers on the store if not already on.
    pub fn power_on(self) -> Result<StoreDriverOn, StoreInvariant> {
        match self {
            StoreDriver::On(x) => Ok(x),
            StoreDriver::Off(x) => x.power_on(),
        }
    }

    /// Extracts the power-off version of the driver.
    pub fn off(self) -> Option<StoreDriverOff> {
        match self {
            StoreDriver::On(_) => None,
            StoreDriver::Off(x) => Some(x),
        }
    }
}

impl StoreDriverOff {
    /// Starts a simulation with a clean storage given its configuration.
    pub fn new(options: BufferOptions, num_pages: usize) -> StoreDriverOff {
        let storage = vec![0xff; num_pages * options.page_size].into_boxed_slice();
        let storage = BufferStorage::new(storage, options);
        StoreDriverOff::new_dirty(storage)
    }

    /// Starts a simulation from an existing storage.
    pub fn new_dirty(storage: BufferStorage) -> StoreDriverOff {
        let format = Format::new(&storage).unwrap();
        StoreDriverOff {
            storage,
            model: StoreModel::new(format),
            complete: None,
        }
    }

    /// Provides read-only access to the storage.
    pub fn storage(&self) -> &BufferStorage {
        &self.storage
    }

    /// Provides mutable access to the storage.
    pub fn storage_mut(&mut self) -> &mut BufferStorage {
        &mut self.storage
    }

    /// Provides read-only access to the model.
    pub fn model(&self) -> &StoreModel {
        &self.model
    }

    /// Powers on the store without interruption.
    ///
    /// # Panics
    ///
    /// Panics if the store cannot be powered on.
    pub fn power_on(self) -> Result<StoreDriverOn, StoreInvariant> {
        Ok(self
            .partial_power_on(StoreInterruption::none())
            .map_err(|x| x.1)?
            .on()
            .unwrap())
    }

    /// Powers on the store with a possible interruption.
    pub fn partial_power_on(
        mut self,
        interruption: StoreInterruption,
    ) -> Result<StoreDriver, (BufferStorage, StoreInvariant)> {
        self.storage.arm_interruption(interruption.delay);
        Ok(match Store::new(self.storage) {
            Ok(mut store) => {
                store.storage_mut().disarm_interruption();
                let mut error = None;
                if let Some(complete) = self.complete {
                    match StoreDriverOn::new(store, complete.model, &complete.deleted) {
                        Ok(driver) => return Ok(StoreDriver::On(driver)),
                        Err((e, x)) => {
                            error = Some(e);
                            store = x;
                        }
                    }
                };
                StoreDriver::On(StoreDriverOn::new(store, self.model, &[]).map_err(
                    |(rollback, store)| {
                        let storage = store.extract_storage();
                        match error {
                            None => (storage, rollback),
                            Some(complete) => {
                                let rollback = Box::new(rollback);
                                let complete = Box::new(complete);
                                (storage, StoreInvariant::Interrupted { rollback, complete })
                            }
                        }
                    },
                )?)
            }
            Err((StoreError::StorageError, mut storage)) => {
                storage.corrupt_operation(interruption.corrupt);
                StoreDriver::Off(StoreDriverOff { storage, ..self })
            }
            Err((error, mut storage)) => {
                storage.reset_interruption();
                return Err((storage, StoreInvariant::StoreError(error)));
            }
        })
    }

    /// Returns the number of storage operations to power on.
    ///
    /// Returns `None` if the store cannot power on successfully.
    pub fn count_operations(&self) -> Option<usize> {
        let initial_delay = usize::MAX;
        let mut storage = self.storage.clone();
        storage.arm_interruption(initial_delay);
        let mut store = Store::new(storage).ok()?;
        Some(initial_delay - store.storage_mut().disarm_interruption())
    }
}

impl StoreDriverOn {
    /// Provides read-only access to the store.
    pub fn store(&self) -> &Store<BufferStorage> {
        &self.store
    }

    /// Extracts the store.
    pub fn extract_store(self) -> Store<BufferStorage> {
        self.store
    }

    /// Provides mutable access to the store.
    pub fn store_mut(&mut self) -> &mut Store<BufferStorage> {
        &mut self.store
    }

    /// Provides read-only access to the model.
    pub fn model(&self) -> &StoreModel {
        &self.model
    }

    /// Applies a store operation to the store and model without interruption.
    pub fn apply(&mut self, operation: StoreOperation) -> Result<(), StoreInvariant> {
        let (deleted, store_result) = self.store.apply(&operation);
        let model_result = self.model.apply(operation);
        if store_result != model_result {
            return Err(StoreInvariant::DifferentResult {
                store: store_result,
                model: model_result,
            });
        }
        self.check_deleted(&deleted)?;
        Ok(())
    }

    /// Applies a store operation to the store and model with a possible interruption.
    pub fn partial_apply(
        mut self,
        operation: StoreOperation,
        interruption: StoreInterruption,
    ) -> Result<(Option<StoreError>, StoreDriver), (Store<BufferStorage>, StoreInvariant)> {
        self.store
            .storage_mut()
            .arm_interruption(interruption.delay);
        let (deleted, store_result) = self.store.apply(&operation);
        Ok(match store_result {
            Err(StoreError::NoLifetime) => return Err((self.store, StoreInvariant::NoLifetime)),
            Ok(()) | Err(StoreError::NoCapacity) | Err(StoreError::InvalidArgument) => {
                self.store.storage_mut().disarm_interruption();
                let model_result = self.model.apply(operation);
                if store_result != model_result {
                    return Err((
                        self.store,
                        StoreInvariant::DifferentResult {
                            store: store_result,
                            model: model_result,
                        },
                    ));
                }
                if store_result.is_ok() {
                    if let Err(invariant) = self.check_deleted(&deleted) {
                        return Err((self.store, invariant));
                    }
                }
                (store_result.err(), StoreDriver::On(self))
            }
            Err(StoreError::StorageError) => {
                let mut driver = StoreDriverOff {
                    storage: self.store.extract_storage(),
                    model: self.model,
                    complete: None,
                };
                driver.storage.corrupt_operation(interruption.corrupt);
                let mut model = driver.model.clone();
                if model.apply(operation).is_ok() {
                    driver.complete = Some(Complete { model, deleted });
                }
                (None, StoreDriver::Off(driver))
            }
            Err(error) => return Err((self.store, StoreInvariant::StoreError(error))),
        })
    }

    /// Returns the number of storage operations to apply a store operation.
    ///
    /// Returns `None` if the store cannot apply the operation successfully.
    pub fn count_operations(&self, operation: &StoreOperation) -> Option<usize> {
        let initial_delay = usize::MAX;
        let mut store = self.store.clone();
        store.storage_mut().arm_interruption(initial_delay);
        store.apply(operation).1.ok()?;
        Some(initial_delay - store.storage_mut().disarm_interruption())
    }

    /// Powers off the store.
    pub fn power_off(self) -> StoreDriverOff {
        StoreDriverOff {
            storage: self.store.extract_storage(),
            model: self.model,
            complete: None,
        }
    }

    /// Applies an insertion to the store and model without interruption.
    #[cfg(feature = "std")]
    pub fn insert(&mut self, key: usize, value: &[u8]) -> Result<(), StoreInvariant> {
        let value = value.to_vec();
        let updates = vec![StoreUpdate::Insert { key, value }];
        self.apply(StoreOperation::Transaction { updates })
    }

    /// Applies a deletion to the store and model without interruption.
    #[cfg(feature = "std")]
    pub fn remove(&mut self, key: usize) -> Result<(), StoreInvariant> {
        let updates = vec![StoreUpdate::Remove { key }];
        self.apply(StoreOperation::Transaction { updates })
    }

    /// Applies a clear operation to the store and model without interruption.
    #[cfg(feature = "std")]
    pub fn clear(&mut self, min_key: usize) -> Result<(), StoreInvariant> {
        self.apply(StoreOperation::Clear { min_key })
    }

    /// Checks that the store and model are in sync.
    pub fn check(&self) -> Result<(), StoreInvariant> {
        self.recover_check(&[])
    }

    /// Starts a simulation from a power-off store.
    ///
    /// Checks that the store and model are in sync and that the given deleted entries are wiped.
    fn new(
        store: Store<BufferStorage>,
        model: StoreModel,
        deleted: &[StoreHandle],
    ) -> Result<StoreDriverOn, (StoreInvariant, Store<BufferStorage>)> {
        let driver = StoreDriverOn { store, model };
        match driver.recover_check(deleted) {
            Ok(()) => Ok(driver),
            Err(error) => Err((error, driver.store)),
        }
    }

    /// Checks that the store and model are in sync and that the given entries are wiped.
    fn recover_check(&self, deleted: &[StoreHandle]) -> Result<(), StoreInvariant> {
        self.check_deleted(deleted)?;
        self.check_model()?;
        self.check_storage()?;
        Ok(())
    }

    /// Checks that the given entries are wiped from the storage.
    fn check_deleted(&self, deleted: &[StoreHandle]) -> Result<(), StoreInvariant> {
        for handle in deleted {
            let value = self.store.inspect_value(handle);
            if !value.iter().all(|&x| x == 0x00) {
                return Err(StoreInvariant::NotWiped {
                    key: handle.get_key(),
                    value,
                });
            }
        }
        Ok(())
    }

    /// Checks that the store and model are in sync.
    fn check_model(&self) -> Result<(), StoreInvariant> {
        let mut model_content = self.model.content().clone();
        for handle in self.store.iter()? {
            let handle = handle?;
            let model_value = match model_content.remove(&handle.get_key()) {
                None => {
                    return Err(StoreInvariant::OnlyInStore {
                        key: handle.get_key(),
                    })
                }
                Some(x) => x,
            };
            let store_value = handle.get_value(&self.store)?.into_boxed_slice();
            if store_value != model_value {
                return Err(StoreInvariant::DifferentValue {
                    key: handle.get_key(),
                    store: store_value,
                    model: model_value,
                });
            }
        }
        if let Some(&key) = model_content.keys().next() {
            return Err(StoreInvariant::OnlyInModel { key });
        }
        let store_capacity = self.store.capacity()?.remaining();
        let model_capacity = self.model.capacity().remaining();
        if store_capacity != model_capacity {
            return Err(StoreInvariant::DifferentCapacity {
                store: store_capacity,
                model: model_capacity,
            });
        }
        Ok(())
    }

    /// Checks that the store is tracking lifetime correctly.
    fn check_storage(&self) -> Result<(), StoreInvariant> {
        let format = self.model.format();
        let storage = self.store.storage();
        let num_words = format.page_size() / format.word_size();
        let head = self.store.head()?;
        let tail = self.store.tail()?;
        for page in 0..format.num_pages() {
            // Check the erase cycle of the page.
            let store_erase = head.cycle(format) + (page < head.page(format)) as Nat;
            let model_erase = storage.get_page_erases(page as usize);
            if store_erase as usize != model_erase {
                return Err(StoreInvariant::DifferentErase {
                    page: page as usize,
                    store: store_erase as usize,
                    model: model_erase,
                });
            }
            let page_pos = Position::new(format, store_erase, page, 0);

            // Check the init word of the page.
            let mut store_write = (page_pos < tail) as usize;
            if page == 0 && tail == Position::new(format, 0, 0, 0) {
                // When the store is initialized and nothing written yet, the first page is still
                // initialized.
                store_write = 1;
            }
            let model_write = storage.get_word_writes((page * num_words) as usize);
            if store_write != model_write {
                return Err(StoreInvariant::DifferentWrite {
                    page: page as usize,
                    word: 0,
                    store: store_write,
                    model: model_write,
                });
            }

            // Check the compact info of the page.
            let model_write = storage.get_word_writes((page * num_words + 1) as usize);
            let store_write = 0;
            if store_write != model_write {
                return Err(StoreInvariant::DifferentWrite {
                    page: page as usize,
                    word: 1,
                    store: store_write,
                    model: model_write,
                });
            }

            // Check the content of the page. We only check cases where the model says a word was
            // written while the store doesn't think it should be the case. This is because the
            // model doesn't count writes to the same value. Also we only check whether a word is
            // written and not how many times. This is because this is hard to rebuild in the store.
            for word in 2..num_words {
                let store_write = (page_pos + (word - 2) < tail) as usize;
                let model_write =
                    (storage.get_word_writes((page * num_words + word) as usize) > 0) as usize;
                if store_write < model_write {
                    return Err(StoreInvariant::DifferentWrite {
                        page: page as usize,
                        word: word as usize,
                        store: store_write,
                        model: model_write,
                    });
                }
            }
        }
        Ok(())
    }
}

impl<'a> StoreInterruption<'a> {
    /// Builds an interruption that never triggers.
    pub fn none() -> StoreInterruption<'a> {
        StoreInterruption {
            delay: usize::max_value(),
            corrupt: Box::new(|_, _| {}),
        }
    }

    /// Builds an interruption without corruption.
    pub fn pure(delay: usize) -> StoreInterruption<'a> {
        StoreInterruption {
            delay,
            corrupt: Box::new(|_, _| {}),
        }
    }
}
