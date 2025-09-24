// SPDX-License-Identifier: MIT

use std::ffi::CString;

use netlink_packet_core::{
    emit_u32, parse_string, parse_u32, DecodeError, DefaultNla, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

const ALTIFNAMSIZ: usize = 128;
const ETHTOOL_A_HEADER_DEV_INDEX: u16 = 1;
const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;
const ETHTOOL_A_HEADER_FLAGS: u16 = 3;

const ETHTOOL_FLAG_COMPACT_BITSETS: u32 = 1;
const ETHTOOL_FLAG_OMIT_REPLY: u32 = 2;
const ETHTOOL_FLAG_STATS: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolHeaderFlag {
    CompactBitsets,
    OmitReply,
    Stats,
    Unknown(u32),
}

impl From<u32> for EthtoolHeaderFlag {
    fn from(value: u32) -> Self {
        match value {
            ETHTOOL_FLAG_COMPACT_BITSETS => Self::CompactBitsets,
            ETHTOOL_FLAG_OMIT_REPLY => Self::OmitReply,
            ETHTOOL_FLAG_STATS => Self::Stats,
            v => Self::Unknown(v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolHeader {
    DevIndex(u32),
    DevName(String),
    Flags(Vec<EthtoolHeaderFlag>),
    Other(DefaultNla),
}

impl Nla for EthtoolHeader {
    fn value_len(&self) -> usize {
        match self {
            Self::DevIndex(_) | Self::Flags(_) => 4,
            Self::DevName(s) => {
                if s.len() + 1 > ALTIFNAMSIZ {
                    ALTIFNAMSIZ
                } else {
                    s.len() + 1
                }
            }
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::DevIndex(_) => ETHTOOL_A_HEADER_DEV_INDEX,
            Self::DevName(_) => ETHTOOL_A_HEADER_DEV_NAME,
            Self::Flags(_) => ETHTOOL_A_HEADER_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::DevIndex(value) => emit_u32(buffer, *value).unwrap(),
            Self::Flags(flags) => {
                emit_u32(buffer, flags_to_u32(flags)).unwrap()
            }
            Self::DevName(s) => {
                str_to_zero_ended_u8_array(s, buffer, ALTIFNAMSIZ)
            }
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolHeader
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            ETHTOOL_A_HEADER_DEV_INDEX => Self::DevIndex(
                parse_u32(payload)
                    .context("invalid ETHTOOL_A_HEADER_DEV_INDEX value")?,
            ),
            ETHTOOL_A_HEADER_FLAGS => {
                let flags = parse_u32(payload)
                    .context("invalid ETHTOOL_A_HEADER_FLAGS value")?;
                Self::Flags(u32_to_flags(flags))
            }
            ETHTOOL_A_HEADER_DEV_NAME => Self::DevName(
                parse_string(payload)
                    .context("invalid ETHTOOL_A_HEADER_DEV_NAME value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

fn u32_to_flags(flag: u32) -> Vec<EthtoolHeaderFlag> {
    let mut flags = Vec::new();
    for bit in 0..u32::BITS {
        let mask = 1 << bit;
        if flag & mask == 0 {
            continue;
        }
        let entry = match mask {
            ETHTOOL_FLAG_COMPACT_BITSETS => EthtoolHeaderFlag::CompactBitsets,
            ETHTOOL_FLAG_OMIT_REPLY => EthtoolHeaderFlag::OmitReply,
            ETHTOOL_FLAG_STATS => EthtoolHeaderFlag::Stats,
            other => EthtoolHeaderFlag::Unknown(other),
        };
        flags.push(entry);
    }

    flags
}

fn flags_to_u32(flags: &[EthtoolHeaderFlag]) -> u32 {
    let mut value = 0u32;
    for flag in flags {
        match flag {
            EthtoolHeaderFlag::CompactBitsets => {
                value |= ETHTOOL_FLAG_COMPACT_BITSETS
            }
            EthtoolHeaderFlag::OmitReply => value |= ETHTOOL_FLAG_OMIT_REPLY,
            EthtoolHeaderFlag::Stats => value |= ETHTOOL_FLAG_STATS,
            EthtoolHeaderFlag::Unknown(i) => value |= *i,
        }
    }
    value
}

fn str_to_zero_ended_u8_array(
    src_str: &str,
    buffer: &mut [u8],
    max_size: usize,
) {
    if let Ok(src_cstring) = CString::new(src_str.as_bytes()) {
        let src_null_ended_str = src_cstring.into_bytes_with_nul();
        if src_null_ended_str.len() > max_size {
            buffer[..max_size].clone_from_slice(&src_null_ended_str[..max_size])
        } else {
            buffer[..src_null_ended_str.len()]
                .clone_from_slice(&src_null_ended_str)
        }
    }
}
