use crate::ctap::status_code::CtapResult;
use alloc::vec::Vec;
use sk_cbor as cbor;

#[derive(Debug, PartialEq, Eq)]
pub enum FingerprintKind {
    Touch = 1,
    Swipe = 2,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FingerprintCheckError {
    NoMatch,
    Timeout,
    Other,
}

/// Status code for enrolling fingerprints
///
/// See lastEnrollSampleStatus in section authenticatorBioEnrollment
#[derive(Debug, PartialEq, Eq)]
pub enum Ctap2EnrollFeedback {
    FpGood = 0x00,
    FpTooHigh = 0x01,
    FpTooLow = 0x02,
    FpTooLeft = 0x03,
    FpTooRight = 0x04,
    FpTooFast = 0x05,
    FpTooSlow = 0x06,
    FpPoorQuality = 0x07,
    FpTooSkewed = 0x08,
    FpTooShort = 0x09,
    FpMergeFailure = 0x0A,
    FpExists = 0x0B,
    // 0x0C is intentionally unused
    NoUserActivity = 0x0D,
    NoUserPresenceTransition = 0x0E,
}

impl From<Ctap2EnrollFeedback> for cbor::Value {
    fn from(feedback: Ctap2EnrollFeedback) -> Self {
        (feedback as u64).into()
    }
}

pub trait Fingerprint {
    /// Starts the fingerprint enrollment process.
    ///
    /// Returns the newly assigned template ID.
    fn prepare_enrollment(&mut self) -> CtapResult<Vec<u8>>;

    /// Captures a fingerprint image.
    ///
    /// Waits for the user to present a finger.
    /// If `timeout_ms` is provided, the function times out on user inaction.
    /// `prepare_enrollment` must be called first.
    /// A returned `Ctap2StatusCode` indicates an unexpected failure processing
    /// the command.
    /// The `Ctap2EnrollFeedback` contains expected errors from the fingerprint
    /// capture process.
    /// Also returns the expected number of remaining samples.
    fn capture_sample(
        &mut self,
        template_id: &[u8],
        timeout_ms: Option<usize>,
    ) -> CtapResult<(Ctap2EnrollFeedback, usize)>;

    /// Cancel a fingerprint enrollment.
    fn cancel_enrollment(&mut self) -> CtapResult<()>;

    /// Delete the fingerprint matching the given template ID.
    ///
    /// Does not delete stored information from persistent storage.
    /// This function signals to the sensor to remove the enrollment only.
    fn remove_enrollment(&mut self, template_id: &[u8]) -> CtapResult<()>;

    /// Initialize hardware to prepare a fingerprint check.
    ///
    /// Called before [`check_fingerprint`].
    /// Useful for starting any operation that needs to happen before
    /// potentially repeated fingerprint checks, such as blinking LEDs.
    fn check_fingerprint_init(&mut self);

    /// Collects a fingerprint from the user and verifies it.
    ///
    /// Waits for the user to present a finger, or the timeout to pass.
    /// Returns Ok if the fingerprint was valid, and an error otherwise.
    fn check_fingerprint(&mut self, timeout_ms: usize) -> Result<(), FingerprintCheckError>;

    /// Deinitilize hardware after a fingerprint check.
    ///
    /// Called after [`check_fingerprint`] is finished.
    fn check_fingerprint_complete(&mut self);

    /// The kind of fingerprint sensor.
    fn fingerprint_kind(&self) -> FingerprintKind;

    /// Maximum number of good samples required for enrollment.
    fn max_capture_samples_required_for_enroll(&self) -> usize;
}
