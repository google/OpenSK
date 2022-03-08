pub trait FirmwareProtection {
    /// Locks the firmware.
    ///
    /// Returns whether the operation was successful.
    fn lock(&mut self) -> bool;
}
