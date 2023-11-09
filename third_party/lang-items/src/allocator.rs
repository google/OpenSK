use crate::util;
use core::alloc::{GlobalAlloc, Layout};
#[cfg(any(feature = "debug_allocations", feature = "panic_console"))]
use core::fmt::Write;
use core::ptr;
use core::ptr::NonNull;
#[cfg(feature = "debug_allocations")]
use core::sync::atomic;
#[cfg(feature = "debug_allocations")]
use core::sync::atomic::AtomicUsize;
#[cfg(any(feature = "debug_allocations", feature = "panic_console"))]
use libtock_console::Console;
#[cfg(feature = "panic_console")]
use libtock_platform::{ErrorCode, Syscalls};
use libtock_runtime::TockSyscalls;
use linked_list_allocator::Heap;

static mut HEAP: Heap = Heap::empty();

#[no_mangle]
unsafe fn libtock_alloc_init(app_heap_bottom: *mut u8, app_heap_size: usize) {
    HEAP.init(app_heap_bottom, app_heap_size);
}

// With the "debug_allocations" feature, we use `AtomicUsize` to store the
// statistics because:
// - it is `Sync`, so we can use it in a static object (the allocator),
// - it implements interior mutability, so we can use it in the allocator
//   methods (that take an immutable `&self` reference).
struct TockAllocator {
    #[cfg(feature = "debug_allocations")]
    count: AtomicUsize,
    #[cfg(feature = "debug_allocations")]
    size: AtomicUsize,
}

impl TockAllocator {
    const fn new() -> TockAllocator {
        TockAllocator {
            #[cfg(feature = "debug_allocations")]
            count: AtomicUsize::new(0),
            #[cfg(feature = "debug_allocations")]
            size: AtomicUsize::new(0),
        }
    }
}

unsafe impl GlobalAlloc for TockAllocator {
    #[allow(clippy::let_and_return)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = HEAP
            .allocate_first_fit(layout)
            .ok()
            .map_or(ptr::null_mut(), NonNull::as_ptr);
        #[cfg(feature = "debug_allocations")]
        {
            self.count.fetch_add(1, atomic::Ordering::SeqCst);
            self.size.fetch_add(layout.size(), atomic::Ordering::SeqCst);
            writeln!(
                Console::<TockSyscalls>::writer(),
                "alloc[{}, {}] = {:?} ({} ptrs, {} bytes)",
                layout.size(),
                layout.align(),
                ptr,
                self.count.load(atomic::Ordering::SeqCst),
                self.size.load(atomic::Ordering::SeqCst)
            )
            .unwrap();
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(feature = "debug_allocations")]
        {
            self.count.fetch_sub(1, atomic::Ordering::SeqCst);
            self.size.fetch_sub(layout.size(), atomic::Ordering::SeqCst);
            writeln!(
                Console::<TockSyscalls>::writer(),
                "dealloc[{}, {}] = {:?} ({} ptrs, {} bytes)",
                layout.size(),
                layout.align(),
                ptr,
                self.count.load(atomic::Ordering::SeqCst),
                self.size.load(atomic::Ordering::SeqCst)
            )
            .unwrap();
        }
        HEAP.deallocate(NonNull::new_unchecked(ptr), layout)
    }
}

#[cfg(any(target_arch = "arm", target_arch = "riscv32"))]
#[global_allocator]
static ALLOCATOR: TockAllocator = TockAllocator::new();

#[alloc_error_handler]
unsafe fn alloc_error_handler(_layout: Layout) -> ! {
    util::Util::<TockSyscalls>::signal_oom();
    util::Util::<TockSyscalls>::signal_panic();

    #[cfg(feature = "panic_console")]
    {
        writeln!(
            Console::<TockSyscalls>::writer(),
            "Couldn't allocate: {:?}",
            _layout
        )
        .ok();
        TockSyscalls::exit_terminate(ErrorCode::Fail as u32);
    }

    #[cfg(not(feature = "panic_console"))]
    util::Util::<TockSyscalls>::cycle_leds()
}
