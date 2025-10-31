// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, Parseable,
};

use crate::{
    cable_test::attr::source::EthtoolCableTestSource, EthtoolCablePair,
};

// Cable result attribute types
const ETHTOOL_A_CABLE_RESULT_PAIR: u16 = 1;
const ETHTOOL_A_CABLE_RESULT_CODE: u16 = 2;
const ETHTOOL_A_CABLE_RESULT_SRC: u16 = 3;

// Cable test result code values
const ETHTOOL_A_CABLE_RESULT_CODE_OK: u8 = 1;
const ETHTOOL_A_CABLE_RESULT_CODE_OPEN: u8 = 2;
const ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT: u8 = 3;
const ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT: u8 = 4;
const ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH: u8 = 5;
const ETHTOOL_A_CABLE_RESULT_CODE_NOISE: u8 = 6;
const ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE: u8 = 7;

/// Result attribute for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestResultAttr {
    Pair(EthtoolCablePair),
    Code(EthtoolCableTestResultCode),
    Source(EthtoolCableTestSource),
    Other(DefaultNla),
}

/// Result code for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolCableTestResultCode {
    Ok,
    Open,
    SameShort,
    CrossShort,
    ImpedanceMismatch,
    Noise,
    ResolutionNotPossible,
    Other(u8),
}

impl From<u8> for EthtoolCableTestResultCode {
    fn from(value: u8) -> Self {
        match value {
            ETHTOOL_A_CABLE_RESULT_CODE_OK => Self::Ok,
            ETHTOOL_A_CABLE_RESULT_CODE_OPEN => Self::Open,
            ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT => Self::SameShort,
            ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT => Self::CrossShort,
            ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH => {
                Self::ImpedanceMismatch
            }
            ETHTOOL_A_CABLE_RESULT_CODE_NOISE => Self::Noise,
            ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE => {
                Self::ResolutionNotPossible
            }
            _ => Self::Other(value),
        }
    }
}

impl From<EthtoolCableTestResultCode> for u8 {
    fn from(value: EthtoolCableTestResultCode) -> Self {
        match value {
            EthtoolCableTestResultCode::Ok => ETHTOOL_A_CABLE_RESULT_CODE_OK,
            EthtoolCableTestResultCode::Open => {
                ETHTOOL_A_CABLE_RESULT_CODE_OPEN
            }
            EthtoolCableTestResultCode::SameShort => {
                ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT
            }
            EthtoolCableTestResultCode::CrossShort => {
                ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT
            }
            EthtoolCableTestResultCode::ImpedanceMismatch => {
                ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH
            }
            EthtoolCableTestResultCode::Noise => {
                ETHTOOL_A_CABLE_RESULT_CODE_NOISE
            }
            EthtoolCableTestResultCode::ResolutionNotPossible => {
                ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE
            }
            EthtoolCableTestResultCode::Other(v) => v,
        }
    }
}

impl Nla for EthtoolCableTestResultAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Pair(_) | Self::Code(_) => std::mem::size_of::<u8>(),
            Self::Source(_) => std::mem::size_of::<u32>(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Pair(_) => ETHTOOL_A_CABLE_RESULT_PAIR,
            Self::Code(_) => ETHTOOL_A_CABLE_RESULT_CODE,
            Self::Source(_) => ETHTOOL_A_CABLE_RESULT_SRC,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Pair(pair) => buffer[0] = (*pair).into(),
            Self::Code(code) => buffer[0] = (*code).into(),
            Self::Source(src) => {
                let word: u32 = (*src).into();
                buffer[..4].copy_from_slice(&word.to_ne_bytes())
            }
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestResultAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        match buf.kind() {
            ETHTOOL_A_CABLE_RESULT_PAIR => parse_u8(buf.value())
                .map(|v| Self::Pair(v.into()))
                .context("failed to parse ETHTOOL_A_CABLE_RESULT_PAIR"),
            ETHTOOL_A_CABLE_RESULT_CODE => parse_u8(buf.value())
                .map(|v| Self::Code(v.into()))
                .context("failed to parse ETHTOOL_A_CABLE_RESULT_CODE"),
            ETHTOOL_A_CABLE_RESULT_SRC => parse_u32(buf.value())
                .map(|v| Self::Source(v.into()))
                .context("failed to parse ETHTOOL_A_CABLE_RESULT_SRC"),
            _ => DefaultNla::parse(buf)
                .map(Self::Other)
                .context("failed to parse unknown NLA for cable test result"),
        }
    }
}
