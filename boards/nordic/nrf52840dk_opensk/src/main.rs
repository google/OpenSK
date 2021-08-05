//! Tock kernel for the Nordic Semiconductor nRF52840 development kit (DK).
//!
//! It is based on nRF52840 SoC (Cortex M4 core with a BLE transceiver) with
//! many exported I/O and peripherals.
//!
//! Pin Configuration
//! -------------------
//!
//! ### `GPIO`
//!
//! | #  | Pin   | Ix | Header | Arduino |
//! |----|-------|----|--------|---------|
//! | 0  | P1.01 | 33 | P3 1   | D0      |
//! | 1  | P1.02 | 34 | P3 2   | D1      |
//! | 2  | P1.03 | 35 | P3 3   | D2      |
//! | 3  | P1.04 | 36 | P3 4   | D3      |
//! | 4  | P1.05 | 37 | P3 5   | D4      |
//! | 5  | P1.06 | 38 | P3 6   | D5      |
//! | 6  | P1.07 | 39 | P3 7   | D6      |
//! | 7  | P1.08 | 40 | P3 8   | D7      |
//! | 8  | P1.10 | 42 | P4 1   | D8      |
//! | 9  | P1.11 | 43 | P4 2   | D9      |
//! | 10 | P1.12 | 44 | P4 3   | D10     |
//! | 11 | P1.13 | 45 | P4 4   | D11     |
//! | 12 | P1.14 | 46 | P4 5   | D12     |
//! | 13 | P1.15 | 47 | P4 6   | D13     |
//! | 14 | P0.26 | 26 | P4 9   | D14     |
//! | 15 | P0.27 | 27 | P4 10  | D15     |
//!
//! ### `GPIO` / Analog Inputs
//!
//! | #  | Pin        | Header | Arduino |
//! |----|------------|--------|---------|
//! | 16 | P0.03 AIN1 | P2 1   | A0      |
//! | 17 | P0.04 AIN2 | P2 2   | A1      |
//! | 18 | P0.28 AIN4 | P2 3   | A2      |
//! | 19 | P0.29 AIN5 | P2 4   | A3      |
//! | 20 | P0.30 AIN6 | P2 5   | A4      |
//! | 21 | P0.31 AIN7 | P2 6   | A5      |
//! | 22 | P0.02 AIN0 | P4 8   | AVDD    |
//!
//! ### Onboard Functions
//!
//! | Pin   | Header | Function |
//! |-------|--------|----------|
//! | P0.05 | P6 3   | UART RTS |
//! | P0.06 | P6 4   | UART TXD |
//! | P0.07 | P6 5   | UART CTS |
//! | P0.08 | P6 6   | UART RXT |
//! | P0.11 | P24 1  | Button 1 |
//! | P0.12 | P24 2  | Button 2 |
//! | P0.13 | P24 3  | LED 1    |
//! | P0.14 | P24 4  | LED 2    |
//! | P0.15 | P24 5  | LED 3    |
//! | P0.16 | P24 6  | LED 4    |
//! | P0.18 | P24 8  | Reset    |
//! | P0.19 | P24 9  | SPI CLK  |
//! | P0.20 | P24 10 | SPI MOSI |
//! | P0.21 | P24 11 | SPI MISO |
//! | P0.24 | P24 14 | Button 3 |
//! | P0.25 | P24 15 | Button 4 |

#![no_std]
// Disable this attribute when documenting, as a workaround for
// https://github.com/rust-lang/rust/issues/62184.
#![cfg_attr(not(doc), no_main)]
#![feature(const_in_array_repeat_expressions)]
#![deny(missing_docs)]

use kernel::common::dynamic_deferred_call::{DynamicDeferredCall, DynamicDeferredCallClientState};
use kernel::component::Component;
#[allow(unused_imports)]
use kernel::{capabilities, create_capability, debug, debug_gpio, debug_verbose, static_init};
use nrf52840::gpio::Pin;
use nrf52_components::{self, UartChannel, UartPins};

// The nRF52840DK LEDs (see back of board)
const LED1_PIN: Pin = Pin::P0_13;
const LED2_PIN: Pin = Pin::P0_14;
const LED3_PIN: Pin = Pin::P0_15;
const LED4_PIN: Pin = Pin::P0_16;

// The nRF52840DK buttons (see back of board)
const BUTTON1_PIN: Pin = Pin::P0_11;
const BUTTON2_PIN: Pin = Pin::P0_12;
const BUTTON3_PIN: Pin = Pin::P0_24;
const BUTTON4_PIN: Pin = Pin::P0_25;
const BUTTON_RST_PIN: Pin = Pin::P0_18;

const UART_RTS: Option<Pin> = Some(Pin::P0_05);
const UART_TXD: Pin = Pin::P0_06;
const UART_CTS: Option<Pin> = Some(Pin::P0_07);
const UART_RXD: Pin = Pin::P0_08;

const SPI_MOSI: Pin = Pin::P0_20;
const SPI_MISO: Pin = Pin::P0_21;
const SPI_CLK: Pin = Pin::P0_19;

/// Debug Writer
pub mod io;

// Whether to use UART debugging or Segger RTT (USB) debugging.
// - Set to false to use UART.
// - Set to true to use Segger RTT over USB.
const USB_DEBUGGING: bool = true;

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: kernel::procs::FaultResponse = kernel::procs::FaultResponse::Panic;

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 8;

static mut PROCESSES: [Option<&'static dyn kernel::procs::ProcessType>; NUM_PROCS] =
    [None; NUM_PROCS];

static mut STORAGE_LOCATIONS: [kernel::StorageLocation; 1] = [kernel::StorageLocation {
    address: 0xC0000,
    size: 0x40000,
}];

static mut CHIP: Option<&'static nrf52840::chip::Chip> = None;

/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x1000] = [0; 0x1000];

/// Supported drivers by the platform
pub struct Platform {
    button: &'static capsules::button::Button<'static, nrf52840::gpio::GPIOPin<'static>>,
    pconsole: &'static capsules::process_console::ProcessConsole<
        'static,
        components::process_console::Capability,
    >,
    console: &'static capsules::console::Console<'static>,
    gpio: &'static capsules::gpio::GPIO<'static, nrf52840::gpio::GPIOPin<'static>>,
    led: &'static capsules::led::LED<'static, nrf52840::gpio::GPIOPin<'static>>,
    rng: &'static capsules::rng::RngDriver<'static>,
    ipc: kernel::ipc::IPC,
    analog_comparator: &'static capsules::analog_comparator::AnalogComparator<
        'static,
        nrf52840::acomp::Comparator<'static>,
    >,
    alarm: &'static capsules::alarm::AlarmDriver<
        'static,
        capsules::virtual_alarm::VirtualMuxAlarm<'static, nrf52840::rtc::Rtc<'static>>,
    >,
    nvmc: &'static nrf52840::nvmc::SyscallDriver,
}

impl kernel::Platform for Platform {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::Driver>) -> R,
    {
        match driver_num {
            capsules::console::DRIVER_NUM => f(Some(self.console)),
            capsules::gpio::DRIVER_NUM => f(Some(self.gpio)),
            capsules::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules::led::DRIVER_NUM => f(Some(self.led)),
            capsules::button::DRIVER_NUM => f(Some(self.button)),
            capsules::rng::DRIVER_NUM => f(Some(self.rng)),
            capsules::analog_comparator::DRIVER_NUM => f(Some(self.analog_comparator)),
            nrf52840::nvmc::DRIVER_NUM => f(Some(self.nvmc)),
            kernel::ipc::DRIVER_NUM => f(Some(&self.ipc)),
            _ => f(None),
        }
    }

    fn filter_syscall(
        &self,
        process: &dyn kernel::procs::ProcessType,
        syscall: &kernel::syscall::Syscall,
    ) -> Result<(), kernel::ReturnCode> {
        use kernel::syscall::Syscall;
        match *syscall {
            Syscall::COMMAND {
                driver_number: nrf52840::nvmc::DRIVER_NUM,
                subdriver_number: cmd,
                arg0: ptr,
                arg1: len,
            } if (cmd == 2 || cmd == 3) && !process.fits_in_storage_location(ptr, len) => {
                Err(kernel::ReturnCode::EINVAL)
            }
            _ => Ok(()),
        }
    }
}

/// Entry point in the vector table called on hard reset.
#[no_mangle]
pub unsafe fn reset_handler() {
    // Loads relocations and clears BSS
    nrf52840::init();

    let uart_channel = if USB_DEBUGGING {
        // Initialize early so any panic beyond this point can use the RTT memory object.
        let mut rtt_memory_refs =
            components::segger_rtt::SeggerRttMemoryComponent::new().finalize(());

        // XXX: This is inherently unsafe as it aliases the mutable reference to rtt_memory. This
        // aliases reference is only used inside a panic handler, which should be OK, but maybe we
        // should use a const reference to rtt_memory and leverage interior mutability instead.
        self::io::set_rtt_memory(&mut *rtt_memory_refs.get_rtt_memory_ptr());

        UartChannel::Rtt(rtt_memory_refs)
    } else {
        UartChannel::Pins(UartPins::new(UART_RTS, UART_TXD, UART_CTS, UART_RXD))
    };

    let board_kernel = static_init!(
        kernel::Kernel,
        kernel::Kernel::new_with_storage(&PROCESSES, &STORAGE_LOCATIONS)
    );

    let gpio = components::gpio::GpioComponent::new(
        board_kernel,
        components::gpio_component_helper!(
            nrf52840::gpio::GPIOPin,
            0 => &nrf52840::gpio::PORT[Pin::P1_01],
            1 => &nrf52840::gpio::PORT[Pin::P1_02],
            2 => &nrf52840::gpio::PORT[Pin::P1_03],
            3 => &nrf52840::gpio::PORT[Pin::P1_04],
            4 => &nrf52840::gpio::PORT[Pin::P1_05],
            5 => &nrf52840::gpio::PORT[Pin::P1_06],
            6 => &nrf52840::gpio::PORT[Pin::P1_07],
            7 => &nrf52840::gpio::PORT[Pin::P1_08],
            8 => &nrf52840::gpio::PORT[Pin::P1_10],
            9 => &nrf52840::gpio::PORT[Pin::P1_11],
            10 => &nrf52840::gpio::PORT[Pin::P1_12],
            11 => &nrf52840::gpio::PORT[Pin::P1_13],
            12 => &nrf52840::gpio::PORT[Pin::P1_14],
            13 => &nrf52840::gpio::PORT[Pin::P1_15],
            14 => &nrf52840::gpio::PORT[Pin::P0_26],
            15 => &nrf52840::gpio::PORT[Pin::P0_27]
        ),
    )
    .finalize(components::gpio_component_buf!(nrf52840::gpio::GPIOPin));

    let button = components::button::ButtonComponent::new(
        board_kernel,
        components::button_component_helper!(
            nrf52840::gpio::GPIOPin,
            (
                &nrf52840::gpio::PORT[BUTTON1_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            ), //13
            (
                &nrf52840::gpio::PORT[BUTTON2_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            ), //14
            (
                &nrf52840::gpio::PORT[BUTTON3_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            ), //15
            (
                &nrf52840::gpio::PORT[BUTTON4_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            ) //16
        ),
    )
    .finalize(components::button_component_buf!(nrf52840::gpio::GPIOPin));

    let led = components::led::LedsComponent::new(components::led_component_helper!(
        nrf52840::gpio::GPIOPin,
        (
            &nrf52840::gpio::PORT[LED1_PIN],
            kernel::hil::gpio::ActivationMode::ActiveLow
        ),
        (
            &nrf52840::gpio::PORT[LED2_PIN],
            kernel::hil::gpio::ActivationMode::ActiveLow
        ),
        (
            &nrf52840::gpio::PORT[LED3_PIN],
            kernel::hil::gpio::ActivationMode::ActiveLow
        ),
        (
            &nrf52840::gpio::PORT[LED4_PIN],
            kernel::hil::gpio::ActivationMode::ActiveLow
        )
    ))
    .finalize(components::led_component_buf!(nrf52840::gpio::GPIOPin));

    let chip = static_init!(nrf52840::chip::Chip, nrf52840::chip::new());
    CHIP = Some(chip);

    nrf52_components::startup::NrfStartupComponent::new(
        false,
        BUTTON_RST_PIN,
        nrf52840::uicr::Regulator0Output::DEFAULT,
    )
    .finalize(());

    // Create capabilities that the board needs to call certain protected kernel
    // functions.
    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);
    let memory_allocation_capability = create_capability!(capabilities::MemoryAllocationCapability);
    let gpio_port = &nrf52840::gpio::PORT;
    // Configure kernel debug gpios as early as possible
    kernel::debug::assign_gpios(
        Some(&gpio_port[LED1_PIN]),
        Some(&gpio_port[LED2_PIN]),
        Some(&gpio_port[LED3_PIN]),
    );

    let rtc = &nrf52840::rtc::RTC;
    rtc.start();
    let mux_alarm = components::alarm::AlarmMuxComponent::new(rtc)
        .finalize(components::alarm_mux_component_helper!(nrf52840::rtc::Rtc));
    let alarm = components::alarm::AlarmDriverComponent::new(board_kernel, mux_alarm)
        .finalize(components::alarm_component_helper!(nrf52840::rtc::Rtc));

    let channel = nrf52_components::UartChannelComponent::new(uart_channel, mux_alarm).finalize(());

    let dynamic_deferred_call_clients =
        static_init!([DynamicDeferredCallClientState; 2], Default::default());
    let dynamic_deferred_caller = static_init!(
        DynamicDeferredCall,
        DynamicDeferredCall::new(dynamic_deferred_call_clients)
    );
    DynamicDeferredCall::set_global_instance(dynamic_deferred_caller);

    // Create a shared UART channel for the console and for kernel debug.
    let uart_mux =
        components::console::UartMuxComponent::new(channel, 115200, dynamic_deferred_caller)
            .finalize(());

    let pconsole =
        components::process_console::ProcessConsoleComponent::new(board_kernel, uart_mux)
            .finalize(());

    // Setup the console.
    let console = components::console::ConsoleComponent::new(board_kernel, uart_mux).finalize(());
    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new(uart_mux).finalize(());

    let rng = components::rng::RngComponent::new(board_kernel, &nrf52840::trng::TRNG).finalize(());

    nrf52840::spi::SPIM0.configure(
        nrf52840::pinmux::Pinmux::new(SPI_MOSI as u32),
        nrf52840::pinmux::Pinmux::new(SPI_MISO as u32),
        nrf52840::pinmux::Pinmux::new(SPI_CLK as u32),
    );

    // Initialize AC using AIN5 (P0.29) as VIN+ and VIN- as AIN0 (P0.02)
    // These are hardcoded pin assignments specified in the driver
    let analog_comparator = components::analog_comparator::AcComponent::new(
        &nrf52840::acomp::ACOMP,
        components::acomp_component_helper!(
            nrf52840::acomp::Channel,
            &nrf52840::acomp::CHANNEL_AC0
        ),
    )
    .finalize(components::acomp_component_buf!(
        nrf52840::acomp::Comparator
    ));

    let nvmc = static_init!(
        nrf52840::nvmc::SyscallDriver,
        nrf52840::nvmc::SyscallDriver::new(
            &nrf52840::nvmc::NVMC,
            board_kernel.create_grant(&memory_allocation_capability),
            dynamic_deferred_caller,
        )
    );
    nvmc.set_deferred_handle(
        dynamic_deferred_caller
            .register(nvmc)
            .expect("no deferred call slot available for nvmc"),
    );

    nrf52_components::NrfClockComponent::new().finalize(());

    let platform = Platform {
        button,
        pconsole,
        console,
        led,
        gpio,
        rng,
        alarm,
        analog_comparator,
        nvmc,
        ipc: kernel::ipc::IPC::new(board_kernel, &memory_allocation_capability),
    };

    platform.pconsole.start();
    debug!("Initialization complete. Entering main loop\r");
    debug!("{}", &nrf52840::ficr::FICR_INSTANCE);

    /// These symbols are defined in the linker script.
    extern "C" {
        /// Beginning of the ROM region containing app images.
        static _sapps: u8;
        /// End of the ROM region containing app images.
        static _eapps: u8;
        /// Beginning of the RAM region for app memory.
        static mut _sappmem: u8;
        /// End of the RAM region for app memory.
        static _eappmem: u8;
    }

    kernel::procs::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            &_sapps as *const u8,
            &_eapps as *const u8 as usize - &_sapps as *const u8 as usize,
        ),
        core::slice::from_raw_parts_mut(
            &mut _sappmem as *mut u8,
            &_eappmem as *const u8 as usize - &_sappmem as *const u8 as usize,
        ),
        &mut PROCESSES,
        FAULT_RESPONSE,
        &process_management_capability,
    )
    .unwrap_or_else(|err| {
        debug!("Error loading processes!");
        debug!("{:?}", err);
    });

    let scheduler = components::sched::round_robin::RoundRobinComponent::new(&PROCESSES)
        .finalize(components::rr_component_helper!(NUM_PROCS));
    board_kernel.kernel_loop(
        &platform,
        chip,
        Some(&platform.ipc),
        scheduler,
        &main_loop_capability,
    );
}
