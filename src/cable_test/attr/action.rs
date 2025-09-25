// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::EthtoolHeader;

const ETHTOOL_A_CABLE_TEST_TDR_HEADER: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolCableTestActionAttr {
    Header(Vec<EthtoolHeader>),
    Other(DefaultNla),
}

impl Nla for EthtoolCableTestActionAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Header(header) => header.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Header(_) => ETHTOOL_A_CABLE_TEST_TDR_HEADER | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Header(header) => header.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolCableTestActionAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        match buf.kind() {
            ETHTOOL_A_CABLE_TEST_TDR_HEADER => {
                let nlas = NlasIterator::new(buf.value())
                    .map(|nla| {
                        EthtoolHeader::parse(&nla?).context(
                            "failed to parse ETHTOOL_A_CABLE_TEST_TDR_HEADER",
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Header(nlas))
            }
            _ => {
                let other = DefaultNla::parse(buf)
                    .context("failed to parse unknown NLA for TDR action")?;
                Ok(Self::Other(other))
            }
        }
    }
}
