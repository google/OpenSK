#[derive(Debug)]
pub enum FingerprintCaptureError {
    NoTouch,
    ImageBad,
    ImagePartial,
    TooFast,
    Other,
}

#[derive(Debug)]
pub enum FingerprintCheckError {
    NoMatch,
    Timeout,
    Other,
}

pub trait Fingerprint {
    /// Get the maximum number of fingerprint enrollments the sensor can
    /// support.
    fn get_enrollment_count_maximum(&self) -> u8;

    /// Get the number of fingerprints currently enrolled.
    fn get_enrollment_count(&self) -> u8;

    /// Start an enrollment session for the fingerprint at the given index.
    ///
    /// `index` should be from 0 to `get_enrollment_count_maximum()-1`.
    fn prepare_enrollment(&self, index: u8);

    /// Capture a fingerprint image.
    ///
    /// `prepare_enrollment()` must be called first.
    ///
    /// Waits for a fingerprint image or returns if `timeout_ms` happens without
    /// a touch.
    ///
    /// ## Return
    ///
    /// `Ok(())` on success and `Err(())` on any failure.
    fn capture_sample(&self, timeout_ms: usize) -> Result<(), FingerprintCaptureError>;

    /// Store a fingerprint enrollment.
    ///
    /// ## Return
    ///
    /// `Ok(())` on success and `Err(())` on any failure.
    fn commit_enrollment(&self) -> Result<(), ()>;

    /// Cancel a fingerprint enrollment.
    fn cancel_enrollment(&self);

    /// Check all enrollments to see if they are enrolled.
    fn get_enrollments(&self, fingerlist: &mut [u8; 5]);

    /// Called before [`check_fingerprint()`].
    ///
    /// Useful for starting any operation that needs to happen before
    /// potentially repeated fingerprint checks, such as blinking LEDs.
    fn check_fingerprint_init(&mut self);

    /// Require the user to touch the sensor and verify the fingerprint is
    /// valid.
    ///
    /// Waits for a fingerprint image or returns if `timeout_ms` happens without
    /// a touch.
    ///
    /// Returns:
    /// - `Ok(index)`: If fingerprint is valid, returns the index of the matched
    ///   fingerprint.
    /// - `Err(e)`: Error if fingerprint is not valid.
    fn check_fingerprint(&self, timeout_ms: usize) -> Result<u8, FingerprintCheckError>;

    /// Called after checking fingerprints has finished.
    fn check_fingerprint_complete(&mut self);

    /// Delete the fingerprint enrolled at the given index.
    fn delete_enrollment(&self, index: u8);

    fn setloglevel(&self, level: u8);

}
