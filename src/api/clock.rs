pub trait Clock: Sized {
    type Timer;
    fn make_timer(&self, milliseconds: u32) -> Self::Timer;
    fn check_timer(&self, timer: Self::Timer) -> Option<Self::Timer>;
}