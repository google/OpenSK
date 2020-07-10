use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::ptr;
use core::ptr::NonNull;
use linked_list_allocator::Heap;

static mut HEAP: Heap = Heap::empty();

#[no_mangle]
unsafe fn libtock_alloc_init(app_heap_start: usize, app_heap_size: usize) {
    HEAP.init(app_heap_start, app_heap_size);
}

struct TockAllocator;

unsafe impl GlobalAlloc for TockAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HEAP.allocate_first_fit(layout)
            .ok()
            .map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HEAP.deallocate(NonNull::new_unchecked(ptr), layout)
    }
}

#[global_allocator]
static ALLOCATOR: TockAllocator = TockAllocator;

#[cfg(not(feature = "custom_alloc_error_handler"))]
#[alloc_error_handler]
unsafe fn alloc_error_handler(_: Layout) -> ! {
    use crate::syscalls;

    // Print 0x01 using the LowLevelDebug capsule (if available).
    let _ = syscalls::command1_insecure(8, 2, 0x01);

    // Signal a panic using the LowLevelDebug capsule (if available).
    let _ = syscalls::command1_insecure(8, 1, 0x01);

    loop {
        syscalls::raw::yieldk();
    }
}
