# Makefile for building the tock kernel for the nRF development kit

TARGET=thumbv7em-none-eabi
PLATFORM=nrf52840_dongle_opensk

include ../../Makefile.common

TOCKLOADER=tockloader

# Where in the nrf52 flash to load the kernel with `tockloader`
KERNEL_ADDRESS=0x00000

# Upload programs over uart with tockloader
ifdef PORT
  TOCKLOADER_GENERAL_FLAGS += --port $(PORT)
endif

TOCKLOADER_JTAG_FLAGS = --jlink --board nrf52dk

# Upload the kernel over JTAG
.PHONY: flash
flash: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin
	$(TOCKLOADER) $(TOCKLOADER_GENERAL_FLAGS) flash --address $(KERNEL_ADDRESS) $(TOCKLOADER_JTAG_FLAGS) $<

# Upload the kernel over serial/bootloader
.PHONY: program
program: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).hex
	$(error Cannot program nRF52840-Dongle over USB. Use \`make flash\` and JTAG)
