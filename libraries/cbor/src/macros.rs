// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Convenience macros for working with CBOR values.

use crate::values::Value;
use alloc::vec;
use core::cmp::Ordering;
use core::iter::Peekable;

/// This macro generates code to extract multiple values from a `Vec<(Value, Value)>` at once
/// in an optimized manner, consuming the input vector.
///
/// It takes as input a `Vec` as well as a list of identifiers and keys, and generates code
/// that assigns the corresponding values to new variables using the given identifiers. Each of
/// these variables has type `Option<Value>`, to account for the case where keys aren't found.
///
/// **Important:** Keys passed to the `destructure_cbor_map!` macro **must be sorted** in increasing
/// order. If not, the algorithm can yield incorrect results, such a assigning `None` to a variable
/// even if the corresponding key existed in the map. **No runtime checks** are made for this in the
/// `destructure_cbor_map!` macro, in order to avoid overhead at runtime. However, assertions that
/// keys are sorted are added in `cfg(test)` mode, so that unit tests can verify ahead of time that
/// the keys are indeed sorted. This macro is therefore **not suitable for dynamic keys** that can
/// change at runtime.
///
/// Example usage:
///
/// ```rust
/// # extern crate alloc;
/// # use sk_cbor::destructure_cbor_map;
/// #
/// # fn main() {
/// #     let map = alloc::vec::Vec::new();
/// destructure_cbor_map! {
///     let {
///         1 => x,
///         "key" => y,
///     } = map;
/// }
/// # }
/// ```
#[macro_export]
macro_rules! destructure_cbor_map {
    ( let { $( $key:expr => $variable:ident, )+ } = $map:expr; ) => {
        // A pre-requisite for this algorithm to work is that the keys to extract from the map are
        // sorted - the behavior is unspecified if the keys are not sorted.
        // Therefore, in test mode we add assertions that the keys are indeed sorted.
        #[cfg(test)]
        $crate::assert_sorted_keys!($( $key, )+);

        use $crate::values::{IntoCborValue, Value};
        use $crate::macros::destructure_cbor_map_peek_value;

        // This algorithm first converts the map into a peekable iterator - whose items are sorted
        // in strictly increasing order of keys. Then, the repeated calls to the "peek value"
        // helper function will consume this iterator and yield values (or `None`) when reaching
        // the keys to extract.
        //
        // This is where the pre-requisite that keys to extract are sorted is important: the
        // algorithm does a single linear scan over the iterator and therefore keys to extract have
        // to come in the same order (i.e. sorted).
        let mut it = $map.into_iter().peekable();
        $(
        let $variable: Option<Value> = destructure_cbor_map_peek_value(&mut it, $key.into_cbor_value());
        )+
    };
}

/// This function is an internal detail of the `destructure_cbor_map!` macro, but has public
/// visibility so that users of the macro can use it.
///
/// Given a peekable iterator of key-value pairs sorted in strictly increasing key order and a
/// needle key, this function consumes all items whose key compares less than or equal to the
/// needle, and returns `Some(value)` if the needle was present as the key in the iterator and
/// `None` otherwise.
///
/// The logic is separated into its own function to reduce binary size, as otherwise the logic
/// would be inlined for every use case. As of June 2020, this saves ~40KB of binary size for the
/// CTAP2 application of OpenSK.
pub fn destructure_cbor_map_peek_value(
    it: &mut Peekable<vec::IntoIter<(Value, Value)>>,
    needle: Value,
) -> Option<Value> {
    loop {
        match it.peek() {
            None => return None,
            Some(item) => {
                let key: &Value = &item.0;
                match key.cmp(&needle) {
                    Ordering::Less => {
                        it.next();
                    }
                    Ordering::Equal => {
                        let value: Value = it.next().unwrap().1;
                        return Some(value);
                    }
                    Ordering::Greater => return None,
                }
            }
        }
    }
}

/// Assert that the keys in a vector of key-value pairs are in canonical order.
#[macro_export]
macro_rules! assert_sorted_keys {
    // Last key
    ( $key:expr, ) => {
    };

    ( $key1:expr, $key2:expr, $( $keys:expr, )* ) => {
        {
            use $crate::values::{IntoCborValue, Value};
            let k1: Value = $key1.into_cbor_value();
            let k2: Value = $key2.into_cbor_value();
            assert!(
                k1 < k2,
                "{:?} < {:?} failed. The destructure_cbor_map! macro requires keys in sorted order.",
                k1,
                k2,
            );
        }
        $crate::assert_sorted_keys!($key2, $( $keys, )*);
    };
}

/// Creates a CBOR Value of type Map with the specified key-value pairs.
///
/// Keys and values are expressions and converted into CBOR Keys and Values.
/// The syntax for these pairs is `key_expression => value_expression,`.
/// Keys do not have to be sorted.
///
/// # Panics
///
/// You may not call this function with identical keys in its argument.
///
/// Example usage:
///
/// ```rust
/// # extern crate alloc;
/// # use sk_cbor::cbor_map;
/// let map = cbor_map! {
///   0x01 => false,
///   "02" => -3,
/// };
/// ```
#[macro_export]
macro_rules! cbor_map {
    // trailing comma case
    ( $( $key:expr => $value:expr, )+ ) => {
        cbor_map! ( $($key => $value),+ )
    };

    ( $( $key:expr => $value:expr ),* ) => {
        {
            // The import is unused if the list is empty.
            #[allow(unused_imports)]
            use $crate::values::IntoCborValue;
            let mut _map = ::alloc::vec::Vec::new();
            $(
                _map.push(($key.into_cbor_value(), $value.into_cbor_value()));
            )*
            $crate::values::Value::map(_map)
        }
    };
}

/// Creates a CBOR Value of type Map with key-value pairs where values can be Options.
///
/// Keys and values are expressions and converted into CBOR Keys and Value Options.
/// The map entry is included iff the Value is not an Option or Option is Some.
/// The syntax for these pairs is `key_expression => value_expression,`.
/// Duplicate keys will lead to invalid CBOR, i.e. writing these values fails.
/// Keys do not have to be sorted.
///
/// Example usage:
///
/// ```rust
/// # extern crate alloc;
/// # use sk_cbor::cbor_map_options;
/// let missing_value: Option<bool> = None;
/// let map = cbor_map_options! {
///   0x01 => Some(false),
///   "02" => -3,
///   "not in map" => missing_value,
/// };
/// ```
#[macro_export]
macro_rules! cbor_map_options {
    // trailing comma case
    ( $( $key:expr => $value:expr, )+ ) => {
        cbor_map_options! ( $($key => $value),+ )
    };

    ( $( $key:expr => $value:expr ),* ) => {
        {
            // The import is unused if the list is empty.
            #[allow(unused_imports)]
            use $crate::values::{IntoCborValue, IntoCborValueOption};
            let mut _map = ::alloc::vec::Vec::<(_, $crate::values::Value)>::new();
            $(
            {
                let opt: Option<$crate::values::Value> = $value.into_cbor_value_option();
                if let Some(val) = opt {
                    _map.push(($key.into_cbor_value(), val));
                }
            }
            )*
            $crate::values::Value::map(_map)
        }
    };
}

/// Creates a CBOR Value of type Map from a Vec<(Value, Value)>.
#[macro_export]
macro_rules! cbor_map_collection {
    ( $tree:expr ) => {{
        $crate::values::Value::map($tree)
    }};
}

/// Creates a CBOR Value of type Array with the given elements.
///
/// Elements are expressions and converted into CBOR Values. Elements are comma-separated.
///
/// Example usage:
///
/// ```rust
/// # extern crate alloc;
/// # use sk_cbor::cbor_array;
/// let array = cbor_array![1, "2"];
/// ```
#[macro_export]
macro_rules! cbor_array {
    // trailing comma case
    ( $( $value:expr, )+ ) => {
        cbor_array! ( $($value),+ )
    };

    ( $( $value:expr ),* ) => {
        {
            // The import is unused if the list is empty.
            #[allow(unused_imports)]
            use $crate::values::IntoCborValue;
            $crate::values::Value::array(vec![ $( $value.into_cbor_value(), )* ])
        }
    };
}

/// Creates a CBOR Value of type Array from a Vec<Value>.
#[macro_export]
macro_rules! cbor_array_vec {
    ( $vec:expr ) => {{
        use $crate::values::IntoCborValue;
        $crate::values::Value::array($vec.into_iter().map(|x| x.into_cbor_value()).collect())
    }};
}

/// Creates a CBOR Value of type Simple with value true.
#[macro_export]
macro_rules! cbor_true {
    ( ) => {
        $crate::values::Value::bool_value(true)
    };
}

/// Creates a CBOR Value of type Simple with value false.
#[macro_export]
macro_rules! cbor_false {
    ( ) => {
        $crate::values::Value::bool_value(false)
    };
}

/// Creates a CBOR Value of type Simple with value null.
#[macro_export]
macro_rules! cbor_null {
    ( ) => {
        $crate::values::Value::null_value()
    };
}

/// Creates a CBOR Value of type Simple with the undefined value.
#[macro_export]
macro_rules! cbor_undefined {
    ( ) => {
        $crate::values::Value::undefined()
    };
}

/// Creates a CBOR Value of type Simple with the given bool value.
#[macro_export]
macro_rules! cbor_bool {
    ( $x:expr ) => {
        $crate::values::Value::bool_value($x)
    };
}

/// Creates a CBOR Value of type Unsigned with the given numeric value.
#[macro_export]
macro_rules! cbor_unsigned {
    ( $x:expr ) => {
        $crate::values::Value::unsigned($x as u64)
    };
}

/// Creates a CBOR Value of type Unsigned or Negative with the given numeric value.
#[macro_export]
macro_rules! cbor_int {
    ( $x:expr ) => {
        $crate::values::Value::integer($x as i64)
    };
}

/// Creates a CBOR Value of type Text String with the given string.
#[macro_export]
macro_rules! cbor_text {
    ( $x:expr ) => {
        $crate::values::Value::text_string($x.into())
    };
}

/// Creates a CBOR Value of type Byte String with the given slice or vector.
#[macro_export]
macro_rules! cbor_bytes {
    ( $x:expr ) => {
        $crate::values::Value::byte_string($x)
    };
}

/// Creates a CBOR Value of type Tag with the given tag and object.
#[macro_export]
macro_rules! cbor_tagged {
    ( $t:expr, $x: expr ) => {
        $crate::values::Value::tag($t, $x)
    };
}

/// Creates a CBOR Value of type Byte String with the given byte string literal.
///
/// Example usage:
///
/// ```rust
/// # extern crate alloc;
/// # use sk_cbor::cbor_bytes_lit;
/// let byte_array = cbor_bytes_lit!(b"foo");
/// ```
#[macro_export]
macro_rules! cbor_bytes_lit {
    ( $x:expr ) => {
        $crate::cbor_bytes!(($x as &[u8]).to_vec())
    };
}

#[cfg(test)]
mod test {
    use super::super::values::Value;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_cbor_simple_values() {
        assert_eq!(cbor_true!(), Value::bool_value(true));
        assert_eq!(cbor_false!(), Value::bool_value(false));
        assert_eq!(cbor_null!(), Value::null_value());
        assert_eq!(cbor_undefined!(), Value::undefined());
    }

    #[test]
    fn test_cbor_bool() {
        assert_eq!(cbor_bool!(true), Value::bool_value(true));
        assert_eq!(cbor_bool!(false), Value::bool_value(false));
    }

    #[test]
    fn test_cbor_int_unsigned() {
        assert_eq!(cbor_int!(0), Value::from(0));
        assert_eq!(cbor_int!(1), Value::from(1));
        assert_eq!(cbor_int!(123456), Value::from(123456));
        assert_eq!(
            cbor_int!(core::i64::MAX),
            Value::from(core::i64::MAX as u64)
        );
    }

    #[test]
    fn test_cbor_int_negative() {
        assert_eq!(cbor_int!(-1), Value::from(-1));
        assert_eq!(cbor_int!(-123456), Value::from(-123456));
        assert_eq!(cbor_int!(core::i64::MIN), Value::from(core::i64::MIN));
    }

    #[test]
    fn test_cbor_int_literals() {
        let a = cbor_array![
            core::i64::MIN,
            core::i32::MIN,
            -123456,
            -1,
            0,
            1,
            123456,
            core::i32::MAX,
            core::i64::MAX,
            core::u64::MAX,
        ];
        let b = Value::array(vec![
            Value::from(core::i64::MIN),
            Value::from(core::i32::MIN as i64),
            Value::from(-123456),
            Value::from(-1),
            Value::from(0),
            Value::from(1),
            Value::from(123456),
            Value::from(core::i32::MAX as u64),
            Value::from(core::i64::MAX as u64),
            Value::from(core::u64::MAX),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_array() {
        let a = cbor_array![
            -123,
            456,
            true,
            cbor_null!(),
            "foo",
            b"bar",
            cbor_array![],
            cbor_array![0, 1],
            cbor_map! {},
            cbor_map! {2 => 3},
        ];
        let b = Value::array(vec![
            Value::from(-123),
            Value::from(456),
            Value::bool_value(true),
            Value::null_value(),
            Value::from(String::from("foo")),
            Value::from(b"bar".to_vec()),
            Value::array(Vec::new()),
            Value::array(vec![Value::from(0), Value::from(1)]),
            Value::map(Vec::new()),
            Value::map([(Value::from(2), Value::from(3))].iter().cloned().collect()),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_array_vec_empty() {
        let a = cbor_array_vec!(Vec::<bool>::new());
        let b = Value::array(Vec::new());
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_array_vec_int() {
        let a = cbor_array_vec!(vec![1, 2, 3, 4]);
        let b = Value::array(vec![
            Value::from(1),
            Value::from(2),
            Value::from(3),
            Value::from(4),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_array_vec_text() {
        let a = cbor_array_vec!(vec!["a", "b", "c"]);
        let b = Value::array(vec![
            Value::from(String::from("a")),
            Value::from(String::from("b")),
            Value::from(String::from("c")),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_array_vec_bytes() {
        let a = cbor_array_vec!(vec![b"a", b"b", b"c"]);
        let b = Value::array(vec![
            Value::from(b"a".to_vec()),
            Value::from(b"b".to_vec()),
            Value::from(b"c".to_vec()),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_map() {
        let a = cbor_map! {
            4 => 56,
            5 => "foo",
            6 => b"bar",
            7 => cbor_array![],
            8 => cbor_array![0, 1],
            9 => cbor_map!{},
            10 => cbor_map!{2 => 3},
            -1 => -23,
            b"bar" => cbor_null!(),
            "foo" => true,
        };
        let b = Value::map(
            [
                (Value::from(4), Value::from(56)),
                (Value::from(5), Value::from(String::from("foo"))),
                (Value::from(6), Value::from(b"bar".to_vec())),
                (Value::from(7), Value::array(Vec::new())),
                (
                    Value::from(8),
                    Value::array(vec![Value::from(0), Value::from(1)]),
                ),
                (Value::from(9), Value::map(Vec::new())),
                (
                    Value::from(10),
                    Value::map([(Value::from(2), Value::from(3))].iter().cloned().collect()),
                ),
                (Value::from(-1), Value::from(-23)),
                (Value::from(b"bar".to_vec()), Value::null_value()),
                (Value::from(String::from("foo")), Value::bool_value(true)),
            ]
            .iter()
            .cloned()
            .collect(),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_map_options() {
        let a = cbor_map_options! {
            4 => Some(56),
            5 => "foo",
            6 => Some(b"bar" as &[u8]),
            7 => cbor_array![],
            8 => Some(cbor_array![0, 1]),
            9 => cbor_map!{},
            10 => Some(cbor_map!{2 => 3}),
            11 => None::<String>,
            12 => None::<&str>,
            13 => None::<Vec<u8>>,
            14 => None::<&[u8]>,
            15 => None::<bool>,
            16 => None::<i32>,
            17 => None::<i64>,
            18 => None::<u64>,
            -1 => -23,
            b"bar" => Some(cbor_null!()),
            "foo" => true,
        };
        let b = Value::map(
            [
                (Value::from(4), Value::from(56)),
                (Value::from(5), Value::from(String::from("foo"))),
                (Value::from(6), Value::from(b"bar".to_vec())),
                (Value::from(7), Value::array(Vec::new())),
                (
                    Value::from(8),
                    Value::array(vec![Value::from(0), Value::from(1)]),
                ),
                (Value::from(9), Value::map(Vec::new())),
                (
                    Value::from(10),
                    Value::map([(Value::from(2), Value::from(3))].iter().cloned().collect()),
                ),
                (Value::from(-1), Value::from(-23)),
                (Value::from(b"bar".to_vec()), Value::null_value()),
                (Value::from(String::from("foo")), Value::bool_value(true)),
            ]
            .iter()
            .cloned()
            .collect(),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_map_collection_empty() {
        let a = cbor_map_collection!(Vec::<(_, _)>::new());
        let b = Value::map(Vec::new());
        assert_eq!(a, b);
    }

    #[test]
    fn test_cbor_map_collection_foo() {
        let a = cbor_map_collection!(vec![(Value::from(2), Value::from(3))]);
        let b = Value::map(vec![(Value::from(2), Value::from(3))]);
        assert_eq!(a, b);
    }

    fn extract_map(cbor_value: Value) -> Vec<(Value, Value)> {
        cbor_value.extract_map().unwrap()
    }

    #[test]
    fn test_destructure_cbor_map_simple() {
        let map = cbor_map! {
            1 => 10,
            2 => 20,
        };

        destructure_cbor_map! {
            let {
                1 => x1,
                2 => x2,
            } = extract_map(map);
        }

        assert_eq!(x1, Some(cbor_unsigned!(10)));
        assert_eq!(x2, Some(cbor_unsigned!(20)));
    }

    #[test]
    #[should_panic]
    fn test_destructure_cbor_map_unsorted() {
        let map = cbor_map! {
            1 => 10,
            2 => 20,
        };

        destructure_cbor_map! {
            // The keys are not sorted here, which violates the precondition of
            // destructure_cbor_map. An assertion should catch that and make the test panic.
            let {
                2 => _x2,
                1 => _x1,
            } = extract_map(map);
        }
    }

    #[test]
    fn test_destructure_cbor_map_partial() {
        let map = cbor_map! {
            1 => 10,
            2 => 20,
            3 => 30,
            4 => 40,
            5 => 50,
            6 => 60,
            7 => 70,
            8 => 80,
            9 => 90,
        };

        destructure_cbor_map! {
            let {
                3 => x3,
                7 => x7,
            } = extract_map(map);
        }

        assert_eq!(x3, Some(cbor_unsigned!(30)));
        assert_eq!(x7, Some(cbor_unsigned!(70)));
    }

    #[test]
    fn test_destructure_cbor_map_missing() {
        let map = cbor_map! {
            1 => 10,
            3 => 30,
            4 => 40,
        };

        destructure_cbor_map! {
            let {
                0 => x0,
                1 => x1,
                2 => x2,
                3 => x3,
                4 => x4,
                5 => x5,
            } = extract_map(map);
        }

        assert_eq!(x0, None);
        assert_eq!(x1, Some(cbor_unsigned!(10)));
        assert_eq!(x2, None);
        assert_eq!(x3, Some(cbor_unsigned!(30)));
        assert_eq!(x4, Some(cbor_unsigned!(40)));
        assert_eq!(x5, None);
    }

    #[test]
    fn test_destructure_unsorted_cbor_map() {
        let map = cbor_map! {
            2 => 20,
            1 => 10,
        };

        destructure_cbor_map! {
            let {
                1 => x1,
                2 => x2,
            } = extract_map(map);
        }

        assert_eq!(x1, Some(cbor_unsigned!(10)));
        assert_eq!(x2, Some(cbor_unsigned!(20)));
    }
}
