use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Empty,
    Truncated,
    BadMagic,
    BadVersion,
    BadChecksum,
    BadLength,
    BadField,
    UnknownKind,
    Unsupported,
    Limit,
    Utf8,
    Invariant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub kind: ErrorKind,
    pub offset: usize,
    pub message: &'static str,
}

impl DecodeError {
    pub const fn new(kind: ErrorKind, offset: usize, message: &'static str) -> Self {
        Self {
            kind,
            offset,
            message,
        }
    }

    pub const fn at(kind: ErrorKind, offset: usize) -> Self {
        Self {
            kind,
            offset,
            message: "",
        }
    }

    pub fn with_message(mut self, message: &'static str) -> Self {
        self.message = message;
        self
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "{:?} at {}", self.kind, self.offset)
        } else {
            write!(f, "{:?} at {}: {}", self.kind, self.offset, self.message)
        }
    }
}

impl std::error::Error for DecodeError {}

pub type Result<T> = std::result::Result<T, DecodeError>;

pub fn limit_len(len: usize, max: usize, offset: usize) -> Result<()> {
    if len > max {
        Err(DecodeError::new(
            ErrorKind::Limit,
            offset,
            "length exceeds decoder limit",
        ))
    } else {
        Ok(())
    }
}

pub fn require(cond: bool, kind: ErrorKind, offset: usize, message: &'static str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(DecodeError::new(kind, offset, message))
    }
}
