// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::{
    bitset_util::{parse_bitset_nlas, EthtoolBitset},
    EthtoolAttr, EthtoolHeader, EthtoolLinkModeBit,
};

const ETHTOOL_A_LINKMODES_HEADER: u16 = 1;
const ETHTOOL_A_LINKMODES_AUTONEG: u16 = 2;
const ETHTOOL_A_LINKMODES_OURS: u16 = 3;
const ETHTOOL_A_LINKMODES_PEER: u16 = 4;
const ETHTOOL_A_LINKMODES_SPEED: u16 = 5;
const ETHTOOL_A_LINKMODES_DUPLEX: u16 = 6;
const ETHTOOL_A_LINKMODES_SUBORDINATE_CFG: u16 = 7;
const ETHTOOL_A_LINKMODES_SUBORDINATE_STATE: u16 = 8;
const ETHTOOL_A_LINKMODES_LANES: u16 = 9;
const ETHTOOL_A_LINKMODES_RATE_MATCHING: u16 = 10;

const DUPLEX_HALF: u8 = 0x00;
const DUPLEX_FULL: u8 = 0x01;
const DUPLEX_UNKNOWN: u8 = 0xff;

const RATE_MATCH_NONE: u8 = 0;
const RATE_MATCH_PAUSE: u8 = 1;
const RATE_MATCH_CRS: u8 = 2;
const RATE_MATCH_OPEN_LOOP: u8 = 3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolLinkModeRateMatching {
    RateMatchNone,
    RateMatchPause,
    RateMatchCrs,
    RateMatchOpenLoop,
    Other(u8),
}

impl From<u8> for EthtoolLinkModeRateMatching {
    fn from(value: u8) -> Self {
        match value {
            RATE_MATCH_NONE => Self::RateMatchNone,
            RATE_MATCH_PAUSE => Self::RateMatchPause,
            RATE_MATCH_CRS => Self::RateMatchCrs,
            RATE_MATCH_OPEN_LOOP => Self::RateMatchOpenLoop,
            _ => Self::Other(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthtoolLinkModeOursCompact {
    bit: EthtoolLinkModeBit,
    advertised: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EthtoolLinkModeOursVerbose {
    bit: EthtoolLinkModeBit,
    name: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolLinkModeOurs {
    Verbose(Vec<EthtoolLinkModeOursVerbose>),
    Compact(Vec<EthtoolLinkModeOursCompact>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolLinkModeDuplex {
    Half,
    Full,
    Unknown,
    Other(u8),
}

impl From<u8> for EthtoolLinkModeDuplex {
    fn from(d: u8) -> Self {
        match d {
            DUPLEX_HALF => Self::Half,
            DUPLEX_FULL => Self::Full,
            DUPLEX_UNKNOWN => Self::Unknown,
            _ => Self::Other(d),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolLinkModeSpeed {
    Valid(u32),
    Unknown,
}

impl From<u32> for EthtoolLinkModeSpeed {
    fn from(value: u32) -> Self {
        if value == 0 || value == u32::MAX {
            Self::Unknown
        } else {
            Self::Valid(value)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolLinkModeAttr {
    Header(Vec<EthtoolHeader>),
    Autoneg(bool),
    Ours(EthtoolLinkModeOurs),
    Peer(Vec<EthtoolLinkModeBit>),
    Speed(EthtoolLinkModeSpeed),
    Duplex(EthtoolLinkModeDuplex),
    ControllerSubordinateCfg(u8),
    ControllerSubordinateState(u8),
    Lanes(u32),
    RateMatching(EthtoolLinkModeRateMatching),
    Other(DefaultNla),
}

impl Nla for EthtoolLinkModeAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Header(hdrs) => hdrs.as_slice().buffer_len(),
            Self::Autoneg(_)
            | Self::Duplex(_)
            | Self::ControllerSubordinateCfg(_)
            | Self::ControllerSubordinateState(_)
            | Self::RateMatching(_) => std::mem::size_of::<u8>(),
            Self::Ours(_) => {
                todo!("Does not support changing ethtool link mode yet")
            }
            Self::Peer(_) => {
                todo!("Does not support changing ethtool link mode yet")
            }
            Self::Speed(_) | Self::Lanes(_) => std::mem::size_of::<u32>(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Header(_) => ETHTOOL_A_LINKMODES_HEADER | NLA_F_NESTED,
            Self::Autoneg(_) => ETHTOOL_A_LINKMODES_AUTONEG,
            Self::Ours(_) => ETHTOOL_A_LINKMODES_OURS,
            Self::Peer(_) => ETHTOOL_A_LINKMODES_PEER,
            Self::Speed(_) => ETHTOOL_A_LINKMODES_SPEED,
            Self::Duplex(_) => ETHTOOL_A_LINKMODES_DUPLEX,
            Self::ControllerSubordinateCfg(_) => {
                ETHTOOL_A_LINKMODES_SUBORDINATE_CFG
            }
            Self::ControllerSubordinateState(_) => {
                ETHTOOL_A_LINKMODES_SUBORDINATE_STATE
            }
            Self::Lanes(_) => ETHTOOL_A_LINKMODES_LANES,
            Self::RateMatching(_) => ETHTOOL_A_LINKMODES_RATE_MATCHING,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Header(ref nlas) => nlas.as_slice().emit(buffer),
            Self::Other(ref attr) => attr.emit(buffer),
            _ => todo!("Does not support changing ethtool link mode yet"),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for EthtoolLinkModeAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            ETHTOOL_A_LINKMODES_HEADER => {
                let mut nlas = Vec::new();
                let error_msg = "failed to parse link_mode header attributes";
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(error_msg)?;
                    let parsed =
                        EthtoolHeader::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::Header(nlas)
            }
            ETHTOOL_A_LINKMODES_AUTONEG => Self::Autoneg(
                parse_u8(payload)
                    .context("Invalid ETHTOOL_A_LINKMODES_AUTONEG value")?
                    == 1,
            ),
            ETHTOOL_A_LINKMODES_OURS => {
                let entries = match parse_bitset_nlas(payload)? {
                    EthtoolBitset::Verbose(bits) => {
                        let modes = bits
                            .into_iter()
                            .map(|bit| EthtoolLinkModeOursVerbose {
                                bit: bit.index.into(),
                                name: bit.name,
                            })
                            .collect();

                        EthtoolLinkModeOurs::Verbose(modes)
                    }
                    EthtoolBitset::Compact(bits) => {
                        let modes = bits
                            .into_iter()
                            .map(|bit| EthtoolLinkModeOursCompact {
                                bit: bit.index.into(),
                                advertised: bit.value,
                            })
                            .collect();

                        EthtoolLinkModeOurs::Compact(modes)
                    }
                };

                Self::Ours(entries)
            }
            ETHTOOL_A_LINKMODES_PEER => {
                let entries = parse_bitset_nlas(payload)?
                    .get_entries()
                    .into_iter()
                    .filter(|(_, value)| *value)
                    .map(|(index, _)| EthtoolLinkModeBit::from(index))
                    .collect();

                Self::Peer(entries)
            }
            ETHTOOL_A_LINKMODES_SPEED => Self::Speed(
                parse_u32(payload)
                    .context("Invalid ETHTOOL_A_LINKMODES_SPEED value")?
                    .into(),
            ),
            ETHTOOL_A_LINKMODES_DUPLEX => Self::Duplex(
                parse_u8(payload)
                    .context("Invalid ETHTOOL_A_LINKMODES_DUPLEX value")?
                    .into(),
            ),
            ETHTOOL_A_LINKMODES_SUBORDINATE_CFG => {
                Self::ControllerSubordinateCfg(parse_u8(payload).context(
                    "Invalid ETHTOOL_A_LINKMODES_SUBORDINATE_CFG value",
                )?)
            }
            ETHTOOL_A_LINKMODES_SUBORDINATE_STATE => {
                Self::ControllerSubordinateState(parse_u8(payload).context(
                    "Invalid ETHTOOL_A_LINKMODES_SUBORDINATE_STATE value",
                )?)
            }
            ETHTOOL_A_LINKMODES_LANES => Self::Lanes(
                parse_u32(payload)
                    .context("Invalid ETHTOOL_A_LINKMODES_LANES value")?,
            ),
            ETHTOOL_A_LINKMODES_RATE_MATCHING => Self::RateMatching(
                parse_u8(payload)
                    .context("Invalid ETHTOOL_A_LINKMODES_RATE_MATCHING value")?
                    .into(),
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

pub(crate) fn parse_link_mode_nlas(
    buffer: &[u8],
) -> Result<Vec<EthtoolAttr>, DecodeError> {
    let mut nlas = Vec::new();
    for nla in NlasIterator::new(buffer) {
        let error_msg = format!(
            "Failed to parse ethtool link_mode message attribute {nla:?}"
        );
        let nla = &nla.context(error_msg.clone())?;
        let parsed = EthtoolLinkModeAttr::parse(nla).context(error_msg)?;
        nlas.push(EthtoolAttr::LinkMode(parsed));
    }
    Ok(nlas)
}
