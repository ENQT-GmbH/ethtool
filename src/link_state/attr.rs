// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::{EthtoolAttr, EthtoolHeader};

const ETHTOOL_A_LINKSTATE_HEADER: u16 = 1;
const ETHTOOL_A_LINKSTATE_LINK: u16 = 2;
const ETHTOOL_A_LINKSTATE_SQI: u16 = 3;
const ETHTOOL_A_LINKSTATE_SQI_MAX: u16 = 4;
const ETHTOOL_A_LINKSTATE_EXT_STATE: u16 = 5;
const ETHTOOL_A_LINKSTATE_EXT_SUBSTATE: u16 = 6;
const ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT: u16 = 7;

const ETHTOOL_LINK_EXT_STATE_AUTONEG: u8 = 0x00;
const ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE: u8 = 0x01;
const ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH: u8 = 0x02;
const ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY: u8 = 0x03;
const ETHTOOL_LINK_EXT_STATE_NO_CABLE: u8 = 0x04;
const ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE: u8 = 0x05;
const ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE: u8 = 0x06;
const ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE: u8 = 0x07;
const ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED: u8 = 0x08;
const ETHTOOL_LINK_EXT_STATE_OVERHEAT: u8 = 0x09;
const ETHTOOL_LINK_EXT_STATE_MODULE: u8 = 0x0A;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolLinkExtState {
    Autoneg,
    LinkTraining,
    LinkLogicalMismatch,
    BadSignalIntegrity,
    NoCable,
    CableIssue,
    EepromIssue,
    CalibrationFailure,
    PowerBudgetExceeded,
    Overheat,
    Module,
    Other(u8),
}

impl From<u8> for EthtoolLinkExtState {
    fn from(value: u8) -> Self {
        match value {
            ETHTOOL_LINK_EXT_STATE_AUTONEG => Self::Autoneg,
            ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE => Self::LinkTraining,
            ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH => {
                Self::LinkLogicalMismatch
            }
            ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY => {
                Self::BadSignalIntegrity
            }
            ETHTOOL_LINK_EXT_STATE_NO_CABLE => Self::NoCable,
            ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE => Self::CableIssue,
            ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE => Self::EepromIssue,
            ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE => {
                Self::CalibrationFailure
            }
            ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED => {
                Self::PowerBudgetExceeded
            }
            ETHTOOL_LINK_EXT_STATE_OVERHEAT => Self::Overheat,
            ETHTOOL_LINK_EXT_STATE_MODULE => Self::Module,
            _ => Self::Other(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolLinkStateAttr {
    Header(Vec<EthtoolHeader>),
    Link(bool),
    Sqi(u32),
    SqiMax(u32),
    LinkExtState(EthtoolLinkExtState),
    LinkExtSubstate(u8),
    LinkExtDownCounter(u32),
    Other(DefaultNla),
}

impl Nla for EthtoolLinkStateAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Header(headers) => headers.as_slice().buffer_len(),
            Self::Link(_)
            | Self::LinkExtState(_)
            | Self::LinkExtSubstate(_) => 1,
            Self::Sqi(_) | Self::SqiMax(_) | Self::LinkExtDownCounter(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Header(_) => ETHTOOL_A_LINKSTATE_HEADER | NLA_F_NESTED,
            Self::Link(_) => ETHTOOL_A_LINKSTATE_LINK,
            Self::Sqi(_) => ETHTOOL_A_LINKSTATE_SQI,
            Self::SqiMax(_) => ETHTOOL_A_LINKSTATE_SQI_MAX,
            Self::LinkExtState(_) => ETHTOOL_A_LINKSTATE_EXT_STATE,
            Self::LinkExtSubstate(_) => ETHTOOL_A_LINKSTATE_EXT_SUBSTATE,
            Self::LinkExtDownCounter(_) => ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Header(ref nlas) => nlas.as_slice().emit(buffer),
            Self::Other(ref attr) => attr.emit(buffer),
            _ => unimplemented!("changing link_state is not supported"),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolLinkStateAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let attr = match buf.kind() {
            ETHTOOL_A_LINKSTATE_HEADER => {
                let mut headers = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(
                        "failed to extract link_state header attribute",
                    )?;
                    let parsed = EthtoolHeader::parse(nla)
                        .context("failed to parse link_state header")?;
                    headers.push(parsed);
                }
                Self::Header(headers)
            }

            ETHTOOL_A_LINKSTATE_LINK => {
                let value = parse_u8(payload)
                    .context("invalid ETHTOOL_A_LINKSTATE_LINK value")?;
                Self::Link(value == 1)
            }

            ETHTOOL_A_LINKSTATE_SQI => {
                let value = parse_u32(payload)
                    .context("invalid ETHTOOL_A_LINKSTATE_SQI value")?;
                Self::Sqi(value)
            }

            ETHTOOL_A_LINKSTATE_SQI_MAX => {
                let value = parse_u32(payload)
                    .context("invalid ETHTOOL_A_LINKSTATE_SQI_MAX value")?;
                Self::SqiMax(value)
            }

            ETHTOOL_A_LINKSTATE_EXT_STATE => {
                let value = parse_u8(payload)
                    .context("invalid ETHTOOL_A_LINKSTATE_EXT_STATE value")?;
                Self::LinkExtState(value.into())
            }

            ETHTOOL_A_LINKSTATE_EXT_SUBSTATE => {
                let value = parse_u8(payload).context(
                    "invalid ETHTOOL_A_LINKSTATE_EXT_SUBSTATE value",
                )?;
                Self::LinkExtSubstate(value)
            }

            ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT => {
                let value = parse_u32(payload).context(
                    "invalid ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT value",
                )?;
                Self::LinkExtDownCounter(value)
            }

            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        };

        Ok(attr)
    }
}

pub(crate) fn parse_link_state_nlas(
    buffer: &[u8],
) -> Result<Vec<EthtoolAttr>, DecodeError> {
    let mut nlas = Vec::new();
    for nla in NlasIterator::new(buffer) {
        let nla = &nla.context(
            "failed to extract ethtool link_state message attribute",
        )?;
        let parsed = EthtoolLinkStateAttr::parse(nla).context(format!(
            "failed to parse ethtool link_state message attribute {nla:?}"
        ))?;
        nlas.push(EthtoolAttr::LinkState(parsed));
    }
    Ok(nlas)
}
