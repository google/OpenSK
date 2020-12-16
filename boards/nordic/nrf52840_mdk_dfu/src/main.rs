//! Tock kernel for the Makerdiary nRF52840 MDK USB dongle.
//!
//! It is based on nRF52840 SoC (Cortex M4 core with a BLE transceiver) with
//! many exported I/O and peripherals.

#![no_std]
// Disable this attribute when documenting, as a workaround for
// https://github.com/rust-lang/rust/issues/62184.
#![cfg_attr(not(doc), no_main)]
#![feature(const_in_array_repeat_expressions)]
#![deny(missing_docs)]

use capsules::virtual_alarm::VirtualMuxAlarm;
use kernel::common::dynamic_deferred_call::{DynamicDeferredCall, DynamicDeferredCallClientState};
use kernel::component::Component;
#[allow(unused_imports)]
use kernel::{capabilities, create_capability, debug, debug_gpio, debug_verbose, static_init};
use kernel::hil::usb::UsbController;
use nrf52840::gpio::Pin;
use nrf52_components::{self, UartChannel, UartPins};

// The nRF52840 MDK USB Dongle LEDs
const LED1_R_PIN: Pin = Pin::P0_23;
const LED1_G_PIN: Pin = Pin::P0_22;
const LED1_B_PIN: Pin = Pin::P0_24;

// The nRF52840 Dongle button
const BUTTON_PIN: Pin = Pin::P0_18;
const BUTTON_RST_PIN: Pin = Pin::P0_02;

const UART_RTS: Option<Pin> = Some(Pin::P0_21);
const UART_TXD: Pin = Pin::P0_20;
const UART_CTS: Option<Pin> = Some(Pin::P0_03);
const UART_RXD: Pin = Pin::P0_19;

// Constants related to the configuration of the 15.4 network stack
const SRC_MAC: u16 = 0xf00f;
const PAN_ID: u16 = 0xABCD;

/// UART Writer
pub mod io;

const VENDOR_ID: u16 = 0x1915; // Nordic Semiconductor
const PRODUCT_ID: u16 = 0x521f; // nRF52840 Dongle (PCA10059)
static STRINGS: &'static [&'static str] = &[
    // Manufacturer
    "Nordic Semiconductor ASA",
    // Product
    "OpenSK",
    // Serial number
    "v1.0",
];

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

// Static reference to chip for panic dumps
static mut CHIP: Option<&'static nrf52840::chip::Chip> = None;

/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x1000] = [0; 0x1000];

/// Supported drivers by the platform
pub struct Platform {
    ble_radio: &'static capsules::ble_advertising_driver::BLE<
        'static,
        nrf52840::ble_radio::Radio<'static>,
        VirtualMuxAlarm<'static, nrf52840::rtc::Rtc<'static>>,
    >,
    ieee802154_radio: &'static capsules::ieee802154::RadioDriver<'static>,
    button: &'static capsules::button::Button<'static, nrf52840::gpio::GPIOPin<'static>>,
    pconsole: &'static capsules::process_console::ProcessConsole<
        'static,
        components::process_console::Capability,
    >,
    console: &'static capsules::console::Console<'static>,
    gpio: &'static capsules::gpio::GPIO<'static, nrf52840::gpio::GPIOPin<'static>>,
    led: &'static capsules::led::LED<'static, nrf52840::gpio::GPIOPin<'static>>,
    rng: &'static capsules::rng::RngDriver<'static>,
    temp: &'static capsules::temperature::TemperatureSensor<'static>,
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
    usb: &'static capsules::usb::usb_ctap::CtapUsbSyscallDriver<
        'static,
        'static,
        nrf52840::usbd::Usbd<'static>,
    >,
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
            capsules::ble_advertising_driver::DRIVER_NUM => f(Some(self.ble_radio)),
            capsules::ieee802154::DRIVER_NUM => f(Some(self.ieee802154_radio)),
            capsules::temperature::DRIVER_NUM => f(Some(self.temp)),
            capsules::analog_comparator::DRIVER_NUM => f(Some(self.analog_comparator)),
            nrf52840::nvmc::DRIVER_NUM => f(Some(self.nvmc)),
            capsules::usb::usb_ctap::DRIVER_NUM => f(Some(self.usb)),
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

    let board_kernel = static_init!(
        kernel::Kernel,
        kernel::Kernel::new_with_storage(&PROCESSES, &STORAGE_LOCATIONS)
    );
    // GPIOs
    let gpio = components::gpio::GpioComponent::new(
        board_kernel,
        components::gpio_component_helper!(
            nrf52840::gpio::GPIOPin,
            // left side of the USB plug. Right side is used for UART
            0 => &nrf52840::gpio::PORT[Pin::P0_04],
            1 => &nrf52840::gpio::PORT[Pin::P0_05],
            2 => &nrf52840::gpio::PORT[Pin::P0_06],
            3 => &nrf52840::gpio::PORT[Pin::P0_07],
            4 => &nrf52840::gpio::PORT[Pin::P0_08]
        ),
    ).finalize(components::gpio_component_buf!(nrf52840::gpio::GPIOPin));

    let button = components::button::ButtonComponent::new(
        board_kernel,
        components::button_component_helper!(
            nrf52840::gpio::GPIOPin,
            (
                &nrf52840::gpio::PORT[BUTTON_PIN],
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullUp
            )
        ),
    )
    .finalize(components::button_component_buf!(nrf52840::gpio::GPIOPin));

    let led = components::led::LedsComponent::new(components::led_component_helper!(
        nrf52840::gpio::GPIOPin,
        (
            &nrf52840::gpio::PORT[LED1_R_PIN],
            kernel::hil::gpio::ActivationMode::ActiveLow
        ),
        (
            &nrf52840::gpio::PORT[LED1_G_PIN],
            kernel::hil::gpio::ActivationMode::ActiveLow
        ),
        (
            &nrf52840::gpio::PORT[LED1_B_PIN],
            kernel::hil::gpio::ActivationMode::ActiveLow
        )
    ))
    .finalize(components::led_component_buf!(nrf52840::gpio::GPIOPin));

    let chip = static_init!(nrf52840::chip::Chip, nrf52840::chip::new());
    CHIP = Some(chip);

    nrf52_components::startup::NrfStartupComponent::new(
        false,
        BUTTON_RST_PIN,
        nrf52840::uicr::Regulator0Output::V3_0,
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
        Some(&gpio_port[LED1_R_PIN]),
        Some(&gpio_port[LED1_G_PIN]),
        Some(&gpio_port[LED1_B_PIN]),
    );

    let rtc = &nrf52840::rtc::RTC;
    rtc.start();
    let mux_alarm = components::alarm::AlarmMuxComponent::new(rtc)
        .finalize(components::alarm_mux_component_helper!(nrf52840::rtc::Rtc));
    let alarm = components::alarm::AlarmDriverComponent::new(board_kernel, mux_alarm)
        .finalize(components::alarm_component_helper!(nrf52840::rtc::Rtc));
    let uart_channel = UartChannel::Pins(UartPins::new(UART_RTS, UART_TXD, UART_CTS, UART_RXD));
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

    let ble_radio =
        nrf52_components::BLEComponent::new(board_kernel, &nrf52840::ble_radio::RADIO, mux_alarm)
            .finalize(());

    let (ieee802154_radio, _mux_mac) = components::ieee802154::Ieee802154Component::new(
        board_kernel,
        &nrf52840::ieee802154_radio::RADIO,
        &nrf52840::aes::AESECB,
        PAN_ID,
        SRC_MAC,
    )
    .finalize(components::ieee802154_component_helper!(
        nrf52840::ieee802154_radio::Radio,
        nrf52840::aes::AesECB<'static>
    ));

    let temp = components::temperature::TemperatureComponent::new(
        board_kernel,
        &nrf52840::temperature::TEMP,
    )
    .finalize(());

    let rng = components::rng::RngComponent::new(board_kernel, &nrf52840::trng::TRNG).finalize(());

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
        )
    );

    // Configure USB controller
    let usb:
        &'static capsules::usb::usb_ctap::CtapUsbSyscallDriver<
            'static,
            'static,
            nrf52840::usbd::Usbd<'static>,
    > = {
        let usb_ctap = static_init!(
            capsules::usb::usbc_ctap_hid::ClientCtapHID<
                'static,
                'static,
                nrf52840::usbd::Usbd<'static>,
            >,
            capsules::usb::usbc_ctap_hid::ClientCtapHID::new(
                &nrf52840::usbd::USBD,
                capsules::usb::usbc_client::MAX_CTRL_PACKET_SIZE_NRF52840,
                VENDOR_ID,
                PRODUCT_ID,
                STRINGS,
            )
        );
        nrf52840::usbd::USBD.set_client(usb_ctap);

        // Enable power events to be sent to USB controller
        nrf52840::power::POWER.set_usb_client(&nrf52840::usbd::USBD);
        nrf52840::power::POWER.enable_interrupts();

        // Configure the USB userspace driver
        let usb_driver = static_init!(
            capsules::usb::usb_ctap::CtapUsbSyscallDriver<
                'static,
                'static,
                nrf52840::usbd::Usbd<'static>,
            >,
            capsules::usb::usb_ctap::CtapUsbSyscallDriver::new(
                usb_ctap,
                board_kernel.create_grant(&memory_allocation_capability)
            )
        );
        usb_ctap.set_client(usb_driver);
        usb_driver as &'static _
    };

    nrf52_components::NrfClockComponent::new().finalize(());

    let platform = Platform {
        button,
        ble_radio,
        ieee802154_radio,
        pconsole,
        console,
        led,
        gpio,
        rng,
        temp,
        alarm,
        analog_comparator,
        nvmc,
        usb,
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
