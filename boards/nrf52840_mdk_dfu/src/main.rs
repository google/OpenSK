//! Tock kernel for the Makerdiary nRF52840 MDK USB dongle.
//!
//! It is based on nRF52840 SoC (Cortex M4 core with a BLE transceiver) with
//! many exported I/O and peripherals.

#![no_std]
#![no_main]
#![deny(missing_docs)]

use kernel::component::Component;
#[allow(unused_imports)]
use kernel::{debug, debug_gpio, debug_verbose, static_init};
use nrf52840::gpio::Pin;
use nrf52dk_base::{SpiPins, UartChannel, UartPins};

// The nRF52840 MDK USB Dongle LEDs
const LED1_R_PIN: Pin = Pin::P0_23;
const LED1_G_PIN: Pin = Pin::P0_22;
const LED1_B_PIN: Pin = Pin::P0_24;

// The nRF52840 Dongle button
const BUTTON_PIN: Pin = Pin::P0_18;
const BUTTON_RST_PIN: Pin = Pin::P0_02;

const UART_RTS: Pin = Pin::P0_21;
const UART_TXD: Pin = Pin::P0_20;
const UART_CTS: Pin = Pin::P0_03;
const UART_RXD: Pin = Pin::P0_19;

const SPI_MOSI: Pin = Pin::P0_05;
const SPI_MISO: Pin = Pin::P0_06;
const SPI_CLK: Pin = Pin::P0_07;

/// UART Writer
pub mod io;

// State for loading and holding applications.
// How should the kernel respond when a process faults.
const FAULT_RESPONSE: kernel::procs::FaultResponse = kernel::procs::FaultResponse::Panic;

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 8;

// RAM to be shared by all application processes.
#[link_section = ".app_memory"]
static mut APP_MEMORY: [u8; 0x3C000] = [0; 0x3C000];

static mut PROCESSES: [Option<&'static dyn kernel::procs::ProcessType>; NUM_PROCS] =
    [None, None, None, None, None, None, None, None];

// Static reference to chip for panic dumps
static mut CHIP: Option<&'static nrf52840::chip::Chip> = None;

/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x1000] = [0; 0x1000];

/// Entry point in the vector table called on hard reset.
#[no_mangle]
pub unsafe fn reset_handler() {
    // Loads relocations and clears BSS
    nrf52840::init();

    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(&PROCESSES));
    // GPIOs
    let gpio = components::gpio::GpioComponent::new(board_kernel).finalize(
        components::gpio_component_helper!(
            &nrf52840::gpio::PORT[Pin::P0_04],
            &nrf52840::gpio::PORT[Pin::P0_05],
            &nrf52840::gpio::PORT[Pin::P0_06],
            &nrf52840::gpio::PORT[Pin::P0_07],
            &nrf52840::gpio::PORT[Pin::P0_08]
        ),
    );
    let button = components::button::ButtonComponent::new(board_kernel).finalize(
        components::button_component_helper!((
            &nrf52840::gpio::PORT[BUTTON_PIN],
            capsules::button::GpioMode::LowWhenPressed,
            kernel::hil::gpio::FloatingState::PullUp
        )),
    );

    let led = components::led::LedsComponent::new().finalize(components::led_component_helper!(
        (
            &nrf52840::gpio::PORT[LED1_R_PIN],
            capsules::led::ActivationMode::ActiveLow
        ),
        (
            &nrf52840::gpio::PORT[LED1_G_PIN],
            capsules::led::ActivationMode::ActiveLow
        ),
        (
            &nrf52840::gpio::PORT[LED1_B_PIN],
            capsules::led::ActivationMode::ActiveLow
        )
    ));
    let chip = static_init!(nrf52840::chip::Chip, nrf52840::chip::new());
    CHIP = Some(chip);

    nrf52dk_base::setup_board(
        board_kernel,
        BUTTON_RST_PIN,
        &nrf52840::gpio::PORT,
        gpio,
        LED1_R_PIN,
        LED1_G_PIN,
        LED1_B_PIN,
        led,
        UartChannel::Pins(UartPins::new(UART_RTS, UART_TXD, UART_CTS, UART_RXD)),
        &SpiPins::new(SPI_MOSI, SPI_MISO, SPI_CLK),
        &None,
        button,
        true,
        &mut APP_MEMORY,
        &mut PROCESSES,
        FAULT_RESPONSE,
        nrf52840::uicr::Regulator0Output::V3_0,
        false,
        &Some(&nrf52840::usbd::USBD),
        chip,
    );
}
