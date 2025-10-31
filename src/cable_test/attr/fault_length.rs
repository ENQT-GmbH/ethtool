// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, parse_u32, parse_u8, DecodeError, DefaultNla, Emitable,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

use crate::{
    cable_test::attr::source::EthtoolCableTestSource, EthtoolCablePair,
};

// Cable fault length attribute types
const ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR: u16 = 1;
const ETHTOOL_A_CABLE_FAULT_LENGTH_CM: u16 = 2;
const ETHTOOL_A_CABLE_FAULT_LENGTH_SRC: u16 = 3;

/// Fault length attribute for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestFaultLengthAttr {
    Pair(EthtoolCablePair),
    Cm(u32),
    Source(EthtoolCableTestSource),
    Other(DefaultNla),
}

impl Nla for EthtoolCableTestFaultLengthAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Pair(_) => std::mem::size_of::<u8>(),
            Self::Cm(_) | Self::Source(_) => std::mem::size_of::<u32>(),
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
            Self::Pair(pair) => buffer[0] = (*pair).into(),
            Self::Cm(cm) => emit_u32(buffer, *cm).unwrap(),
            Self::Source(src) => emit_u32(buffer, (*src).into()).unwrap(),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestFaultLengthAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        match buf.kind() {
            ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR => parse_u8(buf.value())
                .map(|v| Self::Pair(v.into()))
                .context("failed to parse ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR"),
            ETHTOOL_A_CABLE_FAULT_LENGTH_CM => parse_u32(buf.value())
                .map(Self::Cm)
                .context("failed to parse ETHTOOL_A_CABLE_FAULT_LENGTH_CM"),
            ETHTOOL_A_CABLE_FAULT_LENGTH_SRC => parse_u32(buf.value())
                .map(|v| Self::Source(v.into()))
                .context("failed to parse ETHTOOL_A_CABLE_FAULT_LENGTH_SRC"),
            _ => DefaultNla::parse(buf).map(Self::Other).context(
                "failed to parse unknown NLA for cable test fault length",
            ),
        }
    }
}
