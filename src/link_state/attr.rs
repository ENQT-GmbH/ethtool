// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, parse_u32, parse_u8, DecodeError, DefaultNla, Emitable,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::{
    link_state::state::{EthtoolExtState, EthtoolExtSubstateValue},
    EthtoolAttr, EthtoolHeader,
};

const ETHTOOL_A_LINKSTATE_HEADER: u16 = 1;
const ETHTOOL_A_LINKSTATE_LINK: u16 = 2;
const ETHTOOL_A_LINKSTATE_SQI: u16 = 3;
const ETHTOOL_A_LINKSTATE_SQI_MAX: u16 = 4;
const ETHTOOL_A_LINKSTATE_EXT_STATE: u16 = 5;
const ETHTOOL_A_LINKSTATE_EXT_SUBSTATE: u16 = 6;
const ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT: u16 = 7;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolLinkStateAttr {
    Header(Vec<EthtoolHeader>),
    Link(bool),
    Sqi(u32),
    SqiMax(u32),
    ExtState(EthtoolExtState),
    ExtSubstate(EthtoolExtSubstateValue),
    ExtDownCounter(u32),
    Other(DefaultNla),
}

impl Nla for EthtoolLinkStateAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Header(headers) => headers.as_slice().buffer_len(),
            Self::Link(_) | Self::ExtState(_) | Self::ExtSubstate(_) => {
                std::mem::size_of::<u8>()
            }
            Self::Sqi(_) | Self::SqiMax(_) | Self::ExtDownCounter(_) => {
                std::mem::size_of::<u32>()
            }
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Header(_) => ETHTOOL_A_LINKSTATE_HEADER | NLA_F_NESTED,
            Self::Link(_) => ETHTOOL_A_LINKSTATE_LINK,
            Self::Sqi(_) => ETHTOOL_A_LINKSTATE_SQI,
            Self::SqiMax(_) => ETHTOOL_A_LINKSTATE_SQI_MAX,
            Self::ExtState(_) => ETHTOOL_A_LINKSTATE_EXT_STATE,
            Self::ExtSubstate(_) => ETHTOOL_A_LINKSTATE_EXT_SUBSTATE,
            Self::ExtDownCounter(_) => ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Header(header) => header.as_slice().emit(buffer),
            Self::Link(link) => buffer[0] = *link as u8,
            Self::Sqi(sqi) => emit_u32(buffer, *sqi).unwrap(),
            Self::SqiMax(sqi_max) => emit_u32(buffer, *sqi_max).unwrap(),
            Self::ExtState(state) => buffer[0] = (*state).into(),
            Self::ExtSubstate(substate) => buffer[0] = *substate,
            Self::ExtDownCounter(counter) => {
                emit_u32(buffer, *counter).unwrap()
            }
            Self::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolLinkStateAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        match buf.kind() {
            ETHTOOL_A_LINKSTATE_HEADER => {
                let nlas = NlasIterator::new(buf.value())
                    .map(|nla| {
                        EthtoolHeader::parse(&nla?).context(
                            "failed to parse ETHTOOL_A_LINKSTATE_HEADER",
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Header(nlas))
            }
            ETHTOOL_A_LINKSTATE_LINK => {
                let value = parse_u8(buf.value())
                    .context("failed to parse ETHTOOL_A_LINKSTATE_LINK")?;
                Ok(Self::Link(value == 1))
            }
            ETHTOOL_A_LINKSTATE_SQI => {
                let value = parse_u32(buf.value())
                    .context("failed to parse ETHTOOL_A_LINKSTATE_SQI")?;
                Ok(Self::Sqi(value))
            }
            ETHTOOL_A_LINKSTATE_SQI_MAX => {
                let value = parse_u32(buf.value())
                    .context("failed to parse ETHTOOL_A_LINKSTATE_SQI_MAX")?;
                Ok(Self::SqiMax(value))
            }
            ETHTOOL_A_LINKSTATE_EXT_STATE => {
                let value = parse_u8(buf.value())
                    .context("failed to parse ETHTOOL_A_LINKSTATE_EXT_STATE")?;
                Ok(Self::ExtState(value.into()))
            }
            ETHTOOL_A_LINKSTATE_EXT_SUBSTATE => {
                let value = parse_u8(buf.value()).context(
                    "failed to parse ETHTOOL_A_LINKSTATE_EXT_SUBSTATE",
                )?;
                Ok(Self::ExtSubstate(value))
            }
            ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT => {
                let value = parse_u32(buf.value()).context(
                    "failed to parse ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT",
                )?;
                Ok(Self::ExtDownCounter(value))
            }
            _ => {
                let other = DefaultNla::parse(buf)
                    .context("failed to parse unknown NLA for link state")?;
                Ok(Self::Other(other))
            }
        }
    }
}

pub(crate) fn parse_link_state_nlas(
    buffer: &[u8],
) -> Result<Vec<EthtoolAttr>, DecodeError> {
    NlasIterator::new(buffer)
        .map(|nla| {
            let nla = nla.context(
                "failed to get ethtool link state message attribute",
            )?;
            let parsed = EthtoolLinkStateAttr::parse(&nla)
                .context("failed to parse ethtool link state NLA")?;
            Ok(EthtoolAttr::LinkState(parsed))
        })
        .collect()
}
