use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
};

#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    Unsigned(u64),
    Boolean(bool),
    Text(String),
    Bytes(Vec<u8>),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Mac([u8; 6]),
    Hex(u64),
}

impl Display for FieldValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(value) => write!(f, "{value}"),
            Self::Boolean(value) => write!(f, "{value}"),
            Self::Text(value) => f.write_str(value),
            Self::Bytes(value) => {
                for byte in value {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Ipv4(value) => Display::fmt(&Ipv4Addr::from(*value), f),
            Self::Ipv6(value) => Display::fmt(&Ipv6Addr::from(*value), f),
            Self::Mac(value) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                value[0], value[1], value[2], value[3], value[4], value[5]
            ),
            Self::Hex(value) => write!(f, "0x{value:04x}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: Cow<'static, str>,
    pub value: FieldValue,
    pub offset: Option<usize>,
    pub length: Option<usize>,
}

impl Field {
    pub fn new(name: impl Into<Cow<'static, str>>, value: impl Into<FieldValue>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            offset: None,
            length: None,
        }
    }

    pub fn hex(name: &'static str, value: u64) -> Self {
        Self {
            name: Cow::Borrowed(name),
            value: FieldValue::Hex(value),
            offset: None,
            length: None,
        }
    }

    pub fn at(mut self, offset: usize, length: usize) -> Self {
        self.offset = Some(offset);
        self.length = Some(length);
        self
    }
}

impl From<u8> for FieldValue {
    fn from(value: u8) -> Self {
        Self::Unsigned(u64::from(value))
    }
}

impl From<u16> for FieldValue {
    fn from(value: u16) -> Self {
        Self::Unsigned(u64::from(value))
    }
}

impl From<u32> for FieldValue {
    fn from(value: u32) -> Self {
        Self::Unsigned(u64::from(value))
    }
}

impl From<u64> for FieldValue {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<Vec<u8>> for FieldValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<[u8; 4]> for FieldValue {
    fn from(value: [u8; 4]) -> Self {
        Self::Ipv4(value)
    }
}

impl From<[u8; 6]> for FieldValue {
    fn from(value: [u8; 6]) -> Self {
        Self::Mac(value)
    }
}

impl From<[u8; 16]> for FieldValue {
    fn from(value: [u8; 16]) -> Self {
        Self::Ipv6(value)
    }
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Layer {
    pub name: Cow<'static, str>,
    pub fields: Vec<Field>,
}

impl Layer {
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Self::with_capacity(name, 0)
    }

    pub fn with_capacity(name: impl Into<Cow<'static, str>>, field_capacity: usize) -> Self {
        Self {
            name: name.into(),
            fields: Vec::with_capacity(field_capacity),
        }
    }

    pub fn field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }
}

impl Display for Layer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.name)?;
        for field in &self.fields {
            writeln!(f, "  {}: {}", field.name, field.value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_inline_network_addresses_and_hex_values() {
        assert_eq!(
            FieldValue::from([0, 1, 2, 0xaa, 0xbb, 0xff]).to_string(),
            "00:01:02:aa:bb:ff"
        );
        assert_eq!(Field::hex("Type", 0x0800).value.to_string(), "0x0800");
    }
}
