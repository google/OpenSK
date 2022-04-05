use embedded_time::TimeInt;
use embedded_time::fraction::Fraction;
use core::fmt;
use core::ops::{Add, Sub, Mul, Div, Rem};

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, fmt::Debug)]
pub struct U24(u32);
impl U24 {
    pub const unsafe fn new_unchecked(n: u32) -> Self {
        // SAFETY: this is guaranteed to be safe by the caller.
        Self(n)
    }

    pub const fn new(n: u32) -> Option<Self> {
        if n <= 0xffffff {
            Some(Self(n))
        } else {
            None
        }
    }

    pub const fn new_wrap(n: u32) -> Self {
        Self(n & 0xffffff)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for U24 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for U24 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let res = self.get().add(other.get());
        debug_assert!(res <= 0xffffff);
        Self::new_wrap(res)
    }
}

impl Sub for U24 {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        let res = self.get().sub(other.get());
        // Note: underflow detection in debug is already done by u32's sub
        Self::new_wrap(res)
    }
}

impl Mul for U24 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let res = self.get().mul(other.get());
        debug_assert!(res <= 0xffffff);
        Self::new_wrap(res)
    }
}

impl Div for U24 {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        // SAFETY: division by zero detection is already done by u32's div
        // and division cannot overflow
        unsafe { Self::new_unchecked(self.get().div(other.get())) }
    }
}

impl Rem for U24 {
    type Output = Self;
    fn rem(self, other: Self) -> Self {
        // SAFETY: rem cannot overflow
        unsafe { Self::new_unchecked(self.get().rem(other.get())) }
    }
}

impl num::One for U24 {
    fn one() -> Self {
        Self(1)
    }
}

impl num::Zero for U24 {
    fn zero() -> Self {
        Self(0)
    }

    fn is_zero(&self) -> bool {
        self.get() == 0
    }
}

impl num::Num for U24 {
    type FromStrRadixErr = core::num::ParseIntError;
    fn from_str_radix(str: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        u32::from_str_radix(str, radix)
            .and_then(|n|
                // If we are too big, we manually generate a ParseIntError
                Self::new(n).ok_or_else(||
                    u32::from_str_radix("100000000", 16).unwrap_err()
                )
            )
    }
}

impl num::Integer for U24 {
    fn div_floor(&self, other: &Self) -> Self {
        // SAFETY: div_floor cannot overflow
        unsafe { Self::new_unchecked(self.get().div_floor(&other.get())) }
    }
    fn mod_floor(&self, other: &Self) -> Self {
        // SAFETY: div_floor cannot overflow
        unsafe { Self::new_unchecked(self.get().mod_floor(&other.get())) }
    }
    fn gcd(&self, other: &Self) -> Self {
        // SAFETY: gcd cannot overflow
        unsafe { Self::new_unchecked(self.get().gcd(&other.get())) }
    }
    fn lcm(&self, other: &Self) -> Self {
        Self::new(self.get().lcm(&other.get())).unwrap()
    }
    fn divides(&self, other: &Self) -> bool {
        self.get().divides(&other.get())
    }
    fn is_multiple_of(&self, other: &Self) -> bool {
        self.get().is_multiple_of(&other.get())
    }
    fn is_even(&self) -> bool {
        self.get().is_even()
    }
    fn is_odd(&self) -> bool {
        self.get().is_odd()
    }
    fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (div, rem) = self.get().div_rem(&other.get());
        // SAFETY: div_floor cannot overflow
        unsafe { ( Self::new_unchecked(div), Self::new_unchecked(rem) ) }
    }
}

impl num::Bounded for U24 {
    fn min_value() -> Self {
        // SAFETY: 0 is within bounds
        unsafe { Self::new_unchecked(0) }
    }
    fn max_value() -> Self {
        // SAFETY: 0xffffff is within bounds
        unsafe { Self::new_unchecked(0xffffff) }
    }
}

impl num::traits::WrappingAdd for U24 {
    fn wrapping_add(&self, v: &Self) -> Self {
        Self::new_wrap(self.get().wrapping_add(v.get()))
    }
}

impl num::traits::WrappingSub for U24 {
    fn wrapping_sub(&self, v: &Self) -> Self {
        Self::new_wrap(self.get().wrapping_sub(v.get()))
    }
}

impl num::traits::CheckedAdd for U24 {
    fn checked_add(&self, v: &Self) -> Option<Self> {
        self.get()
            .checked_add(v.get())
            .and_then(|n| Self::new(n))
    }
}

impl num::traits::CheckedSub for U24 {
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        self.get()
            .checked_sub(v.get())
            // SAFETY: checked_sub cannot overflow
            .and_then(|n| Some(unsafe { Self::new_unchecked(n) }))
    }
}

impl num::traits::CheckedMul for U24 {
    fn checked_mul(&self, v: &Self) -> Option<Self> {
        self.get()
            .checked_mul(v.get())
            .and_then(|n| Self::new(n))
    }
}

impl num::traits::CheckedDiv for U24 {
    fn checked_div(&self, v: &Self) -> Option<Self> {
        self.get()
            .checked_div(v.get())
            // SAFETY: checked_div cannot overflow
            .and_then(|n| Some(unsafe { Self::new_unchecked(n) }))
    }
}

impl From<u32> for U24 {
    /// Use the 24 lowest bits from n, ignore the rest
    fn from(n: u32) -> Self {
        Self::new_wrap(n)
    }
}

impl Mul<Fraction> for U24 {
    type Output = Self;
    fn mul(self, other: Fraction) -> Self {
        Self::new(self.get() * other).unwrap()
    }
}

impl Div<Fraction> for U24 {
    type Output = Self;
    fn div(self, other: Fraction) -> Self {
        Self::new(self.get() / other).unwrap()
    }
}

impl TimeInt for U24 {}