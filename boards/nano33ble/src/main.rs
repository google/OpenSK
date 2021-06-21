//! Tock kernel for the Arduino Nano 33 BLE.
//!
//! It is based on nRF52840 SoC (Cortex M4 core with a BLE + IEEE 802.15.4 transceiver).

#![no_std]
// Disable this attribute when documenting, as a workaround for
// https://github.com/rust-lang/rust/issues/62184.
#![cfg_attr(not(doc), no_main)]
#![feature(const_in_array_repeat_expressions)]
#![deny(missing_docs)]

use kernel::capabilities;
use kernel::common::dynamic_deferred_call::{DynamicDeferredCall, DynamicDeferredCallClientState};
use kernel::component::Component;
use kernel::hil::usb::UsbController;
use kernel::hil::gpio::ActivationMode::ActiveLow;
use kernel::hil::gpio::Configure;
use kernel::hil::gpio::Output;
use kernel::hil::i2c::I2CMaster;
use kernel::mpu::MPU;
use kernel::Chip;
use nrf52_components::{self, UartChannel, UartPins};
#[allow(unused_imports)]
use kernel::{create_capability, debug, debug_gpio, debug_verbose, static_init};

use nrf52840::gpio::Pin;


// Three-color LED.
const LED_RED_PIN: Pin = Pin::P0_24;
const LED_GREEN_PIN: Pin = Pin::P0_16;
const LED_BLUE_PIN: Pin = Pin::P0_06;

const LED_KERNEL_PIN: Pin = Pin::P0_13;

const _BUTTON_RST_PIN: Pin = Pin::P0_18;

const GPIO_D2: Pin = Pin::P1_11;
const GPIO_D3: Pin = Pin::P1_12;
const GPIO_D4: Pin = Pin::P1_15;
const GPIO_D5: Pin = Pin::P1_13;
const GPIO_D6: Pin = Pin::P1_14;
const GPIO_D7: Pin = Pin::P0_23;
const GPIO_D8: Pin = Pin::P0_21;
const GPIO_D9: Pin = Pin::P0_27;
const GPIO_D10: Pin = Pin::P1_02;

const _UART_TX_PIN: Pin = Pin::P1_03;
const _UART_RX_PIN: Pin = Pin::P1_10;
const _UART_CTS_PIN: Option<Pin> = None;
const _UART_RTS_PIN: Option<Pin> = None;

/// I2C pins for all of the sensors.
const I2C_SDA_PIN: Pin = Pin::P0_14;
const I2C_SCL_PIN: Pin = Pin::P0_15;

/// GPIO tied to the VCC of the I2C pullup resistors.
const I2C_PULLUP_PIN: Pin = Pin::P1_00;

/// Interrupt pin for the APDS9960 sensor.
//const APDS9960_PIN: Pin = Pin::P0_19;

/// UART Writer for panic!()s.
pub mod io;

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: kernel::procs::FaultResponse = kernel::procs::FaultResponse::Panic;

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 8;

static mut PROCESSES: [Option<&'static dyn kernel::procs::ProcessType>; NUM_PROCS] = [None; NUM_PROCS];

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
    pconsole: &'static capsules::process_console::ProcessConsole<
        'static,
        components::process_console::Capability,
    >,
    console: &'static capsules::console::Console<'static>,
    //proximity: &'static capsules::proximity::ProximitySensor<'static>,
    gpio: &'static capsules::gpio::GPIO<'static, nrf52840::gpio::GPIOPin<'static>>,
    led: &'static capsules::led::LED<'static, nrf52840::gpio::GPIOPin<'static>>,
    button: &'static capsules::button::Button<'static, nrf52840::gpio::GPIOPin<'static>>,
    rng: &'static capsules::rng::RngDriver<'static>,
    ipc: kernel::ipc::IPC,
    alarm: &'static capsules::alarm::AlarmDriver<
        'static,
        capsules::virtual_alarm::VirtualMuxAlarm<'static, nrf52840::rtc::Rtc<'static>>,
    >,
    usb: &'static capsules::usb::usb_ctap::CtapUsbSyscallDriver<
        'static,
        'static,
        nrf52840::usbd::Usbd<'static>,
    >,
    nvmc: &'static nrf52840::nvmc::SyscallDriver
}

impl kernel::Platform for Platform {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::Driver>) -> R,
    {
        match driver_num {
            capsules::console::DRIVER_NUM => f(Some(self.console)),
            //capsules::proximity::DRIVER_NUM => f(Some(self.proximity)),
            capsules::gpio::DRIVER_NUM => f(Some(self.gpio)),
            capsules::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules::led::DRIVER_NUM => f(Some(self.led)),
            capsules::rng::DRIVER_NUM => f(Some(self.rng)),
            capsules::button::DRIVER_NUM => f(Some(self.button)),
            kernel::ipc::DRIVER_NUM => f(Some(&self.ipc)),
            nrf52840::nvmc::DRIVER_NUM => f(Some(self.nvmc)),
            capsules::usb::usb_ctap::DRIVER_NUM => f(Some(self.usb)),
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
        kernel::Kernel::new_with_storage(&PROCESSES, &STORAGE_LOCATIONS));

    //--------------------------------------------------------------------------
    // CAPABILITIES
    //--------------------------------------------------------------------------

    // Create capabilities that the board needs to call certain protected kernel
    // functions.
    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);
    let memory_allocation_capability = create_capability!(capabilities::MemoryAllocationCapability);

    //--------------------------------------------------------------------------
    // DEBUG GPIO
    //--------------------------------------------------------------------------

    // Configure kernel debug GPIOs as early as possible. These are used by the
    // `debug_gpio!(0, toggle)` macro. We configure these early so that the
    // macro is available during most of the setup code and kernel execution.
    kernel::debug::assign_gpios(Some(&nrf52840::gpio::PORT[LED_KERNEL_PIN]), None, None);

    //--------------------------------------------------------------------------
    // BUTTON
    //--------------------------------------------------------------------------


    // The button has been set by default on PIN D2. If you'd like to change it,
    // you can modify the PORT with the desired PIN and comment it below at the GPIO initialization

    let button = components::button::ButtonComponent::new(
        board_kernel,
        components::button_component_helper!(
            nrf52840::gpio::GPIOPin,
            (
                &nrf52840::gpio::PORT[GPIO_D2],
                kernel::hil::gpio::ActivationMode::ActiveHigh,
                kernel::hil::gpio::FloatingState::PullNone
            )
        ),
    )
    .finalize(components::button_component_buf!(nrf52840::gpio::GPIOPin));


    //--------------------------------------------------------------------------
    // GPIO
    //--------------------------------------------------------------------------


    let gpio = components::gpio::GpioComponent::new(
        board_kernel,
        components::gpio_component_helper!(
            nrf52840::gpio::GPIOPin,
            // PIN D2 has been hooked up to a button, as shown above
            //2 => &nrf52840::gpio::PORT[GPIO_D2],
            3 => &nrf52840::gpio::PORT[GPIO_D3],
            4 => &nrf52840::gpio::PORT[GPIO_D4],
            5 => &nrf52840::gpio::PORT[GPIO_D5],
            6 => &nrf52840::gpio::PORT[GPIO_D6],
            7 => &nrf52840::gpio::PORT[GPIO_D7],
            8 => &nrf52840::gpio::PORT[GPIO_D8],
            9 => &nrf52840::gpio::PORT[GPIO_D9],
            10 => &nrf52840::gpio::PORT[GPIO_D10]
        ),
    )
    .finalize(components::gpio_component_buf!(nrf52840::gpio::GPIOPin));

    //--------------------------------------------------------------------------
    // LEDs
    //--------------------------------------------------------------------------

    let led = components::led::LedsComponent::new(components::led_component_helper!(
        nrf52840::gpio::GPIOPin,
        (&nrf52840::gpio::PORT[LED_RED_PIN], ActiveLow),
        (&nrf52840::gpio::PORT[LED_GREEN_PIN], ActiveLow),
        (&nrf52840::gpio::PORT[LED_BLUE_PIN], ActiveLow)
    ))
    .finalize(components::led_component_buf!(nrf52840::gpio::GPIOPin));

    nrf52_components::startup::NrfStartupComponent::new(
        false,
        _BUTTON_RST_PIN,
        nrf52840::uicr::Regulator0Output::V3_0,
    )
    .finalize(());

    //--------------------------------------------------------------------------
    // Deferred Call (Dynamic) Setup
    //--------------------------------------------------------------------------

    let dynamic_deferred_call_clients =
        static_init!([DynamicDeferredCallClientState; 2], Default::default());
    let dynamic_deferred_caller = static_init!(
        DynamicDeferredCall,
        DynamicDeferredCall::new(dynamic_deferred_call_clients)
    );
    DynamicDeferredCall::set_global_instance(dynamic_deferred_caller);

    //--------------------------------------------------------------------------
    // ALARM & TIMER
    //--------------------------------------------------------------------------

    let rtc = &nrf52840::rtc::RTC;
    rtc.start();

    let mux_alarm = components::alarm::AlarmMuxComponent::new(rtc)
        .finalize(components::alarm_mux_component_helper!(nrf52840::rtc::Rtc));
    let alarm = components::alarm::AlarmDriverComponent::new(board_kernel, mux_alarm)
        .finalize(components::alarm_component_helper!(nrf52840::rtc::Rtc));

    //--------------------------------------------------------------------------
    // UART & CONSOLE & DEBUG
    //--------------------------------------------------------------------------

    // Setup the CDC-ACM over USB driver that we will use for UART.
    // We use the Arduino Vendor ID and Product ID since the device is the same.

    // Create the strings we include in the USB descriptor. We use the hardcoded
    // DEVICEADDR register on the nRF52 to set the serial number.
    let serial_number_buf = static_init!([u8; 17], [0; 17]);
    let serial_number_string: &'static str =
        nrf52840::ficr::FICR_INSTANCE.address_str(serial_number_buf);
    let strings = static_init!(
        [&str; 3],
        [
            "Arduino",              // Manufacturer
            "Nano 33 BLE - TockOS", // Product
            serial_number_string,   // Serial number
        ]
    );

    let uart_channel = UartChannel::Pins(UartPins::new(_UART_RTS_PIN, _UART_TX_PIN, _UART_CTS_PIN, _UART_RX_PIN));
    let channel = nrf52_components::UartChannelComponent::new(uart_channel, mux_alarm).finalize(());

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


    //--------------------------------------------------------------------------
    // RANDOM NUMBERS
    //--------------------------------------------------------------------------

    let rng = components::rng::RngComponent::new(board_kernel, &nrf52840::trng::TRNG).finalize(());

    //--------------------------------------------------------------------------
    // SENSORS
    //--------------------------------------------------------------------------

    let sensors_i2c_bus = static_init!(
        capsules::virtual_i2c::MuxI2C<'static>,
        capsules::virtual_i2c::MuxI2C::new(&nrf52840::i2c::TWIM0, None, dynamic_deferred_caller)
    );
    nrf52840::i2c::TWIM0.configure(
        nrf52840::pinmux::Pinmux::new(I2C_SCL_PIN as u32),
        nrf52840::pinmux::Pinmux::new(I2C_SDA_PIN as u32),
    );
    nrf52840::i2c::TWIM0.set_master_client(sensors_i2c_bus);

    &nrf52840::gpio::PORT[I2C_PULLUP_PIN].make_output();
    &nrf52840::gpio::PORT[I2C_PULLUP_PIN].set();

    // Disabled the gesture sensor since we do not need it in this context and the current tock repo 
    // that OpenSK runs on does not contain it

    /*
    let apds9960_i2c = static_init!(
        capsules::virtual_i2c::I2CDevice,
        capsules::virtual_i2c::I2CDevice::new(sensors_i2c_bus, 0x39 << 1)
    );

    let apds9960 = static_init!(
        capsules::apds9960::APDS9960<'static>,
        capsules::apds9960::APDS9960::new(
            apds9960_i2c,
            &nrf52840::gpio::PORT[APDS9960_PIN],
            &mut capsules::apds9960::BUFFER
        )
    );
    apds9960_i2c.set_client(apds9960);
    nrf52840::gpio::PORT[APDS9960_PIN].set_client(apds9960);
    */


    // Disabled the proximity sensor for the same reasons as stated above (apds9960)

    // let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

    /*
    let proximity = static_init!(
        capsules::proximity::ProximitySensor<'static>,
        capsules::proximity::ProximitySensor::new(apds9960, board_kernel.create_grant(&grant_cap))
    );
    */

   // kernel::hil::sensors::ProximityDriver::set_client(apds9960, proximity);

    let nvmc = static_init!(
        nrf52840::nvmc::SyscallDriver,
        nrf52840::nvmc::SyscallDriver::new(
            &nrf52840::nvmc::NVMC,
            board_kernel.create_grant(&memory_allocation_capability),
        )
    );

    //--------------------------------------------------------------------------
    // USB
    //------------------------------------------------------------------------

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
                0x2341,
                0x005a,
                strings,
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

    //--------------------------------------------------------------------------
    // FINAL SETUP AND BOARD BOOT
    //--------------------------------------------------------------------------

    // Start all of the clocks. Low power operation will require a better
    // approach than this.
    nrf52_components::NrfClockComponent::new().finalize(());

    let platform = Platform {
        button: button,
        pconsole: pconsole,
        console: console,
        //proximity: proximity,
        led: led,
        gpio: gpio,
        rng: rng,
        alarm: alarm,
        usb: usb,
        nvmc:nvmc,
        ipc: kernel::ipc::IPC::new(board_kernel, &memory_allocation_capability),
    };

    let chip = static_init!(nrf52840::chip::Chip, nrf52840::chip::new());
    CHIP = Some(chip);

    // Need to disable the MPU because the bootloader seems to set it up.
    chip.mpu().clear_mpu();

    // Configure the USB stack to enable a serial port over CDC-ACM.
    //cdc.enable();
    //cdc.attach();

    platform.pconsole.start();

    debug!("Initialization complete. Entering main loop.");

    //--------------------------------------------------------------------------
    // PROCESSES AND MAIN LOOP
    //--------------------------------------------------------------------------

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
