use std::borrow::Cow;

pub(crate) struct Key(String);

/// The value part of attribute [KeyValue] pairs.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    /// bool values
    Bool(bool),
    /// i64 values
    I64(i64),
    /// f64 values
    F64(f64),
    /// String values
    String(Cow<'static, str>),
    // Array of homogeneous values
    //Array(Array),
}
