// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::cable_test::attr::{
    fault_length::EthtoolCableTestFaultLengthAttr,
    result::EthtoolCableTestResultAttr,
};

// Cable nest attribute types
const ETHTOOL_A_CABLE_NEST_RESULT: u16 = 1;
const ETHTOOL_A_CABLE_NEST_FAULT_LENGTH: u16 = 2;

/// Nested attribute for an ethtool cable test.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestNestAttr {
    Result(Vec<EthtoolCableTestResultAttr>),
    FaultLength(Vec<EthtoolCableTestFaultLengthAttr>),
    Other(DefaultNla),
}

impl Nla for EthtoolCableTestNestAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Result(attr) => attr.as_slice().buffer_len(),
            Self::FaultLength(attr) => attr.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Result(_) => ETHTOOL_A_CABLE_NEST_RESULT | NLA_F_NESTED,
            Self::FaultLength(_) => {
                ETHTOOL_A_CABLE_NEST_FAULT_LENGTH | NLA_F_NESTED
            }
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Result(result) => result.as_slice().emit(buffer),
            Self::FaultLength(fault) => fault.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestNestAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        match buf.kind() {
            ETHTOOL_A_CABLE_NEST_RESULT => {
                let nlas = NlasIterator::new(buf.value())
                    .map(|nla| {
                        EthtoolCableTestResultAttr::parse(&nla?).context(
                            "failed to parse ETHTOOL_A_CABLE_NEST_RESULT",
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Result(nlas))
            }
            ETHTOOL_A_CABLE_NEST_FAULT_LENGTH => {
                let nlas = NlasIterator::new(buf.value())
                    .map(|nla| {
                        EthtoolCableTestFaultLengthAttr::parse(&nla?).context(
                            "failed to parse ETHTOOL_A_CABLE_NEST_FAULT_LENGTH",
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::FaultLength(nlas))
            }
            _ => {
                let other = DefaultNla::parse(buf).context(
                    "failed to parse unknown NLA for cable test nest",
                )?;
                Ok(Self::Other(other))
            }
        }
    }
}
