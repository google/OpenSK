use persistent_store::{BufferOptions, StoreDriverOff, StoreInterruption, StoreOperation};

#[test]
fn interrupted_overflowing_compaction() {
    let options = BufferOptions {
        word_size: 4,
        page_size: 32,
        max_word_writes: 2,
        max_page_erases: 3,
        strict_mode: true,
    };
    let num_pages = 7;
    let mut driver = StoreDriverOff::new(options, num_pages).power_on().unwrap();
    let v = driver.model().format().virt_size() as usize;
    let c = driver.model().format().total_capacity() as usize;
    let q = driver.model().format().virt_page_size() as usize;

    // We setup the storage such that the next 2 compactions are overflowing. This means they copy 1
    // more word than the size of a page.
    let mut k = 0;
    // Fill the first 2 pages with non-deleted entries.
    while k < 2 * q {
        driver.insert(k, &[]).unwrap();
        k += 1;
    }
    // Write enough deleted entries to be able to continue writing without compaction.
    for _ in c..v {
        driver.insert(k, &[]).unwrap();
    }
    // Fill until the end of the window with deleted entries.
    while k < c {
        driver.insert(k, &[]).unwrap();
        driver.remove(k).unwrap();
        k += 1;
    }
    // Make sure we did not compact and we actually filled until the end of the window.
    assert_eq!(driver.store().lifetime().unwrap().used(), v);

    // We trigger 2 interrupted overflowing compactions, which would move the last non-deleted entry
    // out of the window unless additional compactions are done to restore the overflow.
    for _ in 0..2 {
        let interruption = StoreInterruption {
            delay: 0,
            corrupt: Box::new(|old, new| old.copy_from_slice(new)),
        };
        match driver.partial_apply(StoreOperation::Prepare { length: 1 }, interruption) {
            Ok((None, d)) => driver = d.power_on().unwrap(),
            _ => unreachable!(),
        }
    }
}
