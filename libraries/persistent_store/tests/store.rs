use persistent_store::{
    BufferOptions, StoreDriverOff, StoreDriverOn, StoreInterruption, StoreOperation,
};

#[test]
fn interrupted_overflowing_compaction() {
    let num_pages = 7;
    let options = BufferOptions {
        word_size: 4,
        page_size: 32,
        max_word_writes: 2,
        max_page_erases: 3,
        strict_mode: true,
    };
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
        match driver.partial_apply(
            StoreOperation::Prepare { length: 1 },
            StoreInterruption::pure(1),
        ) {
            Ok((None, d)) => driver = d.power_on().unwrap(),
            _ => {
                assert!(false);
                return;
            }
        }
    }
}

#[test]
fn full_compaction_with_max_prefix() {
    let num_pages = 7;
    let options = BufferOptions {
        word_size: 4,
        page_size: 32,
        max_word_writes: 2,
        max_page_erases: 3,
        strict_mode: true,
    };
    let mut driver = StoreDriverOff::new(options, num_pages).power_on().unwrap();
    let max_key = driver.model().format().max_key() as usize;
    let max_value_len = driver.model().format().max_value_len() as usize;
    let n = driver.model().format().num_pages() as usize;
    let v = driver.model().format().virt_size() as usize;
    let c = driver.model().format().total_capacity() as usize;
    let q = driver.model().format().virt_page_size() as usize;
    let m = driver.model().format().max_prefix_len() as usize;
    let get_tail = |driver: &StoreDriverOn| driver.store().lifetime().unwrap().used();
    let mut last_tail = 0;
    let mut check_lifetime = |driver: &StoreDriverOn, used| {
        last_tail += used;
        assert_eq!(get_tail(driver), last_tail);
    };

    // We fill the first page with q + m words of padding. In particular, the last entry overlaps
    // the next page with m words.
    for _ in 0..q - 1 {
        driver.clear(max_key).unwrap();
    }
    driver.insert(0, &vec![0; max_value_len]).unwrap();
    driver.remove(0).unwrap();
    check_lifetime(&driver, q + m);

    // We fill the store with non-deleted entries making sure the last entry always overlaps the
    // next page with m words for the first 3 pages.
    let mut k = 0;
    for _ in 0..c {
        let tail = get_tail(&driver);
        if tail % q == q - 1 && tail < 4 * q {
            driver.insert(k, &vec![0; max_value_len]).unwrap();
        } else {
            driver.insert(k, &[]).unwrap();
        }
        k += 1;
    }
    // We lost 1 word of lifetime because of compacting the first page.
    check_lifetime(&driver, c + 1);

    // We fill the store with padding until compaction would trigger.
    for _ in 0..n - 1 {
        driver.clear(max_key).unwrap();
    }
    check_lifetime(&driver, n - 1);
    assert_eq!(get_tail(&driver), q + m + v);

    // We interrupt all compactions to check the invariant between each compaction.
    for _ in 0..n - 1 {
        match driver.partial_apply(
            StoreOperation::Clear { min_key: max_key },
            StoreInterruption::pure(1),
        ) {
            Ok((None, d)) => driver = d.power_on().unwrap(),
            _ => {
                assert!(false);
                return;
            }
        }
    }
    check_lifetime(&mut driver, c + n - 1);
}
