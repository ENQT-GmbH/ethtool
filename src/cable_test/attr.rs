// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::{EthtoolAttr, EthtoolHeader};

// Cable test notification attribute types
const ETHTOOL_A_CABLE_TEST_NTF_HEADER: u16 = 1;
const ETHTOOL_A_CABLE_TEST_NTF_STATUS: u16 = 2;
const ETHTOOL_A_CABLE_TEST_NTF_NEST: u16 = 3;

// Cable nest attribute types
const ETHTOOL_A_CABLE_NEST_RESULT: u16 = 1;
const ETHTOOL_A_CABLE_NEST_FAULT_LENGTH: u16 = 2;

// Cable result attribute types
const ETHTOOL_A_CABLE_RESULT_PAIR: u16 = 1;
const ETHTOOL_A_CABLE_RESULT_CODE: u16 = 2;
const ETHTOOL_A_CABLE_RESULT_SRC: u16 = 3;

// Cable fault length attribute types
const ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR: u16 = 1;
const ETHTOOL_A_CABLE_FAULT_LENGTH_CM: u16 = 2;
const ETHTOOL_A_CABLE_FAULT_LENGTH_SRC: u16 = 3;

// Cable test status values
const ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED: u8 = 1;
const ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED: u8 = 2;

// Cable test result code values
const ETHTOOL_A_CABLE_RESULT_CODE_OK: u8 = 1;
const ETHTOOL_A_CABLE_RESULT_CODE_OPEN: u8 = 2;
const ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT: u8 = 3;
const ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT: u8 = 4;
const ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH: u8 = 5;
const ETHTOOL_A_CABLE_RESULT_CODE_NOISE: u8 = 6;
const ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE: u8 = 7;

// Cable test pairs
const ETHTOOL_A_CABLE_PAIR_A: u8 = 0;
const ETHTOOL_A_CABLE_PAIR_B: u8 = 1;
const ETHTOOL_A_CABLE_PAIR_C: u8 = 2;
const ETHTOOL_A_CABLE_PAIR_D: u8 = 3;

// Cable test information source
const ETHTOOL_A_CABLE_INF_SRC_TDR: u32 = 1;
const ETHTOOL_A_CABLE_INF_SRC_ALCD: u32 = 2;

/// Result code for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
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

/// Cable pair identifier for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolCableTestPair {
    A,
    B,
    C,
    D,
    Other(u8),
}

impl From<u8> for EthtoolCableTestPair {
    fn from(value: u8) -> Self {
        match value {
            ETHTOOL_A_CABLE_PAIR_A => Self::A,
            ETHTOOL_A_CABLE_PAIR_B => Self::B,
            ETHTOOL_A_CABLE_PAIR_C => Self::C,
            ETHTOOL_A_CABLE_PAIR_D => Self::D,
            _ => Self::Other(value),
        }
    }
}

/// Source of cable test information.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestSource {
    Tdr,
    Alcd,
    Other(u32),
}

impl From<u32> for EthtoolCableTestSource {
    fn from(value: u32) -> Self {
        match value {
            ETHTOOL_A_CABLE_INF_SRC_TDR => Self::Tdr,
            ETHTOOL_A_CABLE_INF_SRC_ALCD => Self::Alcd,
            _ => Self::Other(value),
        }
    }
}

/// Status of an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestStatus {
    Started,
    Completed,
    Other(u8),
}

impl From<u8> for EthtoolCableTestStatus {
    fn from(value: u8) -> Self {
        match value {
            ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED => Self::Started,
            ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED => Self::Completed,
            _ => Self::Other(value),
        }
    }
}

/// Result attribute for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestResult {
    Pair(EthtoolCableTestPair),
    Code(EthtoolCableTestResultCode),
    Source(EthtoolCableTestSource),
    Other(DefaultNla),
}

/// Fault length attribute for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestFaultLength {
    Pair(EthtoolCableTestPair),
    Cm(u32),
    Source(EthtoolCableTestSource),
    Other(DefaultNla),
}

/// Nested attribute for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestNest {
    Result(Vec<EthtoolCableTestResult>),
    FaultLength(Vec<EthtoolCableTestFaultLength>),
    Other(DefaultNla),
}

/// Top-level attribute for an ethtool cable test notification.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestAttr {
    Header(Vec<EthtoolHeader>),
    Status(EthtoolCableTestStatus),
    Nest(Vec<EthtoolCableTestNest>),
    Other(DefaultNla),
}

impl Nla for EthtoolCableTestResult {
    fn value_len(&self) -> usize {
        match self {
            Self::Pair(_) | Self::Code(_) => 1,
            Self::Source(_) => 4,
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
            Self::Pair(pair) => {
                buffer[0] = match pair {
                    EthtoolCableTestPair::A => ETHTOOL_A_CABLE_PAIR_A,
                    EthtoolCableTestPair::B => ETHTOOL_A_CABLE_PAIR_B,
                    EthtoolCableTestPair::C => ETHTOOL_A_CABLE_PAIR_C,
                    EthtoolCableTestPair::D => ETHTOOL_A_CABLE_PAIR_D,
                    EthtoolCableTestPair::Other(v) => *v,
                }
            }
            Self::Code(code) => {
                buffer[0] = match code {
                    EthtoolCableTestResultCode::Ok => {
                        ETHTOOL_A_CABLE_RESULT_CODE_OK
                    }
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
                    EthtoolCableTestResultCode::Other(v) => *v,
                }
            }
            Self::Source(src) => {
                let v = match src {
                    EthtoolCableTestSource::Tdr => ETHTOOL_A_CABLE_INF_SRC_TDR,
                    EthtoolCableTestSource::Alcd => {
                        ETHTOOL_A_CABLE_INF_SRC_ALCD
                    }
                    EthtoolCableTestSource::Other(v) => *v,
                };
                buffer[..4].copy_from_slice(&v.to_ne_bytes());
            }
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl Nla for EthtoolCableTestFaultLength {
    fn value_len(&self) -> usize {
        match self {
            Self::Pair(_) => 1,
            Self::Cm(_) => 4,
            Self::Source(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Pair(_) => ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
            Self::Cm(_) => ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
            Self::Source(_) => ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Pair(pair) => {
                buffer[0] = match pair {
                    EthtoolCableTestPair::A => ETHTOOL_A_CABLE_PAIR_A,
                    EthtoolCableTestPair::B => ETHTOOL_A_CABLE_PAIR_B,
                    EthtoolCableTestPair::C => ETHTOOL_A_CABLE_PAIR_C,
                    EthtoolCableTestPair::D => ETHTOOL_A_CABLE_PAIR_D,
                    EthtoolCableTestPair::Other(v) => *v,
                }
            }
            Self::Cm(cm) => buffer[..4].copy_from_slice(&cm.to_ne_bytes()),
            Self::Source(src) => {
                let v = match src {
                    EthtoolCableTestSource::Tdr => ETHTOOL_A_CABLE_INF_SRC_TDR,
                    EthtoolCableTestSource::Alcd => {
                        ETHTOOL_A_CABLE_INF_SRC_ALCD
                    }
                    EthtoolCableTestSource::Other(v) => *v,
                };
                buffer[..4].copy_from_slice(&v.to_ne_bytes());
            }
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl Nla for EthtoolCableTestNest {
    fn value_len(&self) -> usize {
        match self {
            Self::Result(attr) => attr.as_slice().buffer_len(),
            Self::FaultLength(attr) => attr.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            EthtoolCableTestNest::Result(_) => {
                ETHTOOL_A_CABLE_NEST_RESULT | NLA_F_NESTED
            }
            EthtoolCableTestNest::FaultLength(_) => {
                ETHTOOL_A_CABLE_NEST_FAULT_LENGTH | NLA_F_NESTED
            }
            EthtoolCableTestNest::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            EthtoolCableTestNest::Result(attrs) => {
                attrs.as_slice().emit(buffer)
            }
            EthtoolCableTestNest::FaultLength(attrs) => {
                attrs.as_slice().emit(buffer)
            }
            EthtoolCableTestNest::Other(attr) => attr.emit(buffer),
        }
    }
}

impl Nla for EthtoolCableTestAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Header(hdrs) => hdrs.as_slice().buffer_len(),
            Self::Status(_) => 1,
            Self::Nest(attr) => attr.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Header(_) => ETHTOOL_A_CABLE_TEST_NTF_HEADER | NLA_F_NESTED,
            Self::Status(_) => ETHTOOL_A_CABLE_TEST_NTF_STATUS,
            Self::Nest(_) => ETHTOOL_A_CABLE_TEST_NTF_NEST | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Header(header) => header.as_slice().emit(buffer),
            Self::Status(status) => {
                buffer[0] = match status {
                    EthtoolCableTestStatus::Started => {
                        ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED
                    }
                    EthtoolCableTestStatus::Completed => {
                        ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED
                    }
                    EthtoolCableTestStatus::Other(v) => *v,
                }
            }
            Self::Nest(nest) => nest.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestResult
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
                .context("invalid NLA (unknown kind)"),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestFaultLength
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        match buf.kind() {
            ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR => parse_u8(payload)
                .map(|v| Self::Pair(v.into()))
                .context("failed to parse ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR"),
            ETHTOOL_A_CABLE_FAULT_LENGTH_CM => parse_u32(payload)
                .map(Self::Cm)
                .context("failed to parse ETHTOOL_A_CABLE_FAULT_LENGTH_CM"),
            ETHTOOL_A_CABLE_FAULT_LENGTH_SRC => parse_u32(payload)
                .map(|v| Self::Source(v.into()))
                .context("failed to parse ETHTOOL_A_CABLE_FAULT_LENGTH_SRC"),
            _ => DefaultNla::parse(buf)
                .map(Self::Other)
                .context("invalid NLA (unknown kind)"),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestNest
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let value = match buf.kind() {
            ETHTOOL_A_CABLE_NEST_RESULT => {
                let mut results = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context(
                        "failed to get nla for ETHTOOL_A_CABLE_NEST_RESULT",
                    )?;
                    let result = EthtoolCableTestResult::parse(&nla).context(
                        "failed to parse nla for ETHTOOL_A_CABLE_NEST_RESULT",
                    )?;
                    results.push(result);
                }

                Self::Result(results)
            }
            ETHTOOL_A_CABLE_NEST_FAULT_LENGTH => {
                let mut results = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context("failed to get nla for ETHTOOL_A_CABLE_NEST_FAULT_LENGTH")?;
                    let result = EthtoolCableTestFaultLength::parse(&nla)
                        .context("failed to parse nla for ETHTOOL_A_CABLE_NEST_FAULT_LENGTH")?;
                    results.push(result);
                }

                Self::FaultLength(results)
            }
            _ => DefaultNla::parse(buf)
                .map(Self::Other)
                .context("invalid NLA (unknown kind)")?,
        };

        Ok(value)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let result = match buf.kind() {
            ETHTOOL_A_CABLE_TEST_NTF_HEADER => {
                let nlas = NlasIterator::new(buf.value())
                    .map(|nla| {
                        let nla = nla.context("failed to get nla from ETHTOOL_A_CABLE_TEST_NTF_HEADER")?;
                        EthtoolHeader::parse(&nla).context("failed to parse ETHTOOL_A_CABLE_TEST_NTF_HEADER")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Self::Header(nlas)
            }
            ETHTOOL_A_CABLE_TEST_NTF_STATUS => {
                let value = parse_u8(buf.value()).context(
                    "failed to parse ETHTOOL_A_CABLE_TEST_NTF_STATUS",
                )?;
                Self::Status(value.into())
            }
            ETHTOOL_A_CABLE_TEST_NTF_NEST => {
                let nlas = NlasIterator::new(buf.value())
                    .map(|nla| {
                        let nla = nla.context("failed to get nla from ETHTOOL_A_CABLE_TEST_NTF_NEST")?;
                        EthtoolCableTestNest::parse(&nla).context("failed to parse ETHTOOL_A_CABLE_TEST_NTF_NEST")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Self::Nest(nlas)
            }
            _ => {
                let other = DefaultNla::parse(buf)
                    .context("invalid NLA (unknown kind)")?;
                Self::Other(other)
            }
        };

        Ok(result)
    }
}

pub(crate) fn parse_cable_test_nlas(
    buffer: &[u8],
) -> Result<Vec<EthtoolAttr>, DecodeError> {
    NlasIterator::new(buffer)
        .map(|nla_res| {
            let nla = nla_res.context(
                "failed to get ethtool cable test message attribute",
            )?;
            let parsed = EthtoolCableTestAttr::parse(&nla).context(
                "failed to parse ethtool cable test message attribute",
            )?;
            Ok(EthtoolAttr::CableTest(parsed))
        })
        .collect()
}
