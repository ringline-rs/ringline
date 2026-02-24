use bytes::Bytes;

/// Request body.
#[derive(Debug, Clone, Default)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// Body from bytes.
    Bytes(Bytes),
}

impl Body {
    /// Returns true if the body is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Body::Empty => true,
            Body::Bytes(b) => b.is_empty(),
        }
    }

    /// Returns the body as a byte slice, or empty slice if no body.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Body::Empty => &[],
            Body::Bytes(b) => b,
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        if v.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(Bytes::from(v))
        }
    }
}

impl From<&[u8]> for Body {
    fn from(s: &[u8]) -> Self {
        if s.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(Bytes::copy_from_slice(s))
        }
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        if b.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(b)
        }
    }
}

impl From<&str> for Body {
    fn from(s: &str) -> Self {
        Body::from(s.as_bytes())
    }
}
