// SPDX-License-Identifier: MIT

use log::warn;
use netlink_packet_core::{
    parse_string, parse_u32, DecodeError, ErrorContext, NlasIterator,
};

const ETHTOOL_A_BITSET_SIZE: u16 = 2;
const ETHTOOL_A_BITSET_BITS: u16 = 3;
const ETHTOOL_A_BITSET_VALUE: u16 = 4;
const ETHTOOL_A_BITSET_MASK: u16 = 5;

const ETHTOOL_A_BITSET_BITS_BIT: u16 = 1;

const ETHTOOL_A_BITSET_BIT_INDEX: u16 = 1;
const ETHTOOL_A_BITSET_BIT_NAME: u16 = 2;
const ETHTOOL_A_BITSET_BIT_VALUE: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct EthtoolVerboseBitSet {
    pub index: u32,
    pub value: bool,
    pub name: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct EthtoolCompactBitSet {
    pub index: u32,
    pub value: bool,
    pub mask: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EthtoolBitSet {
    Verbose(EthtoolVerboseBitSet),
    Compact(EthtoolCompactBitSet),
}

impl EthtoolBitSet {
    pub fn index(&self) -> u32 {
        match self {
            Self::Verbose(v) => v.index,
            Self::Compact(c) => c.index,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Verbose(v) => Some(&v.name),
            _ => None,
        }
    }

    pub fn value(&self) -> bool {
        match self {
            Self::Verbose(v) => v.value,
            Self::Compact(c) => c.value,
        }
    }

    pub fn mask(&self) -> Option<bool> {
        match self {
            Self::Compact(c) => Some(c.mask),
            _ => None,
        }
    }
}

pub(crate) fn parse_bitset_bits_nlas(
    raw: &[u8],
) -> Result<Vec<EthtoolBitSet>, DecodeError> {
    let is_compact = NlasIterator::new(raw)
        .filter_map(|nla| nla.ok())
        .find_map(|nla| match nla.kind() {
            ETHTOOL_A_BITSET_BITS => Some(false),
            ETHTOOL_A_BITSET_VALUE | ETHTOOL_A_BITSET_MASK => Some(true),
            _ => None,
        })
        .ok_or("could not determine if bitset is compact")?;

    if is_compact {
        const BITS_PER_BYTE: usize = 8;
        let mut size = None;
        let mut values = Vec::new();
        let mut masks = Vec::new();

        for nla in NlasIterator::new(raw) {
            let nla = nla.context("failed to get NLA for compact bitset")?;
            match nla.kind() {
                ETHTOOL_A_BITSET_SIZE => {
                    size = Some(parse_u32(nla.value())? as usize);
                }
                ETHTOOL_A_BITSET_VALUE => {
                    let size =
                        size.ok_or("compact bitset value: size not set")?;
                    let bytes = nla.value();
                    values = (0..size)
                        .map(|i| {
                            let byte = bytes
                                .get(i / BITS_PER_BYTE)
                                .copied()
                                .unwrap_or(0);
                            ((byte >> (i % BITS_PER_BYTE)) & 1) != 0
                        })
                        .collect();
                }
                ETHTOOL_A_BITSET_MASK => {
                    let size =
                        size.ok_or("compact bitset mask: size not set")?;
                    let bytes = nla.value();
                    masks = (0..size)
                        .map(|i| {
                            let byte = bytes
                                .get(i / BITS_PER_BYTE)
                                .copied()
                                .unwrap_or(0);
                            ((byte >> (i % BITS_PER_BYTE)) & 1) != 0
                        })
                        .collect();
                }
                _ => {}
            }
        }

        let size = size.ok_or("compact bitset: size not set")?;
        if values.len() != size {
            return Err("compact bitset: values length mismatch".into());
        }
        if masks.len() != size {
            return Err("compact bitset: masks length mismatch".into());
        }

        Ok((0..size)
            .map(|i| {
                EthtoolBitSet::Compact(EthtoolCompactBitSet {
                    index: i as u32,
                    value: values[i],
                    mask: masks[i],
                })
            })
            .collect())
    } else {
        for nla in NlasIterator::new(raw) {
            let nla = nla.context("failed to get NLA for verbose bitset")?;
            if nla.kind() == ETHTOOL_A_BITSET_BITS {
                let bitset = parse_verbose_bitset_bits_nla(nla.value())?
                    .into_iter()
                    .map(EthtoolBitSet::Verbose)
                    .collect();
                return Ok(bitset);
            }
        }

        Err("verbose bitset: ETHTOOL_A_BITSET_BITS NLA not found".into())
    }
}

pub(crate) fn parse_bitset_bits_string_nlas(
    raw: &[u8],
) -> Result<Vec<String>, DecodeError> {
    let error_msg = "failed to parse mode bit sets";
    for nla in NlasIterator::new(raw) {
        let nla = &nla.context(error_msg)?;
        if nla.kind() == ETHTOOL_A_BITSET_BITS {
            let bits = parse_verbose_bitset_bits_nla(nla.value())?;

            return Ok(bits
                .into_iter()
                .filter_map(|b| if b.value { Some(b.name) } else { None })
                .collect::<Vec<String>>());
        }
    }
    Err("No ETHTOOL_A_BITSET_BITS NLA found".into())
}

fn parse_verbose_bitset_bits_nla(
    raw: &[u8],
) -> Result<Vec<EthtoolVerboseBitSet>, DecodeError> {
    let mut bit_sets = Vec::new();
    let error_msg = "Failed to parse ETHTOOL_A_BITSET_BITS attributes";
    for bit_nla in NlasIterator::new(raw) {
        let bit_nla = &bit_nla.context(error_msg)?;
        match bit_nla.kind() {
            ETHTOOL_A_BITSET_BITS_BIT => {
                let error_msg =
                    "Failed to parse ETHTOOL_A_BITSET_BITS_BIT attributes";
                let mut bit_set = EthtoolVerboseBitSet::default();
                let nlas = NlasIterator::new(bit_nla.value());
                for nla in nlas {
                    let nla = &nla.context(error_msg)?;
                    let payload = nla.value();
                    match nla.kind() {
                        ETHTOOL_A_BITSET_BIT_INDEX => {
                            bit_set.index =
                                parse_u32(payload).context(format!(
                                    "Invalid ETHTOOL_A_BITSET_BIT_INDEX \
                                    value {payload:?}"
                                ))?;
                        }
                        ETHTOOL_A_BITSET_BIT_VALUE => {
                            bit_set.value = true;
                        }
                        ETHTOOL_A_BITSET_BIT_NAME => {
                            bit_set.name = parse_string(payload).context(
                                "Invald ETHTOOL_A_BITSET_BIT_NAME value",
                            )?;
                        }
                        _ => {
                            warn!(
                                "Unknown ETHTOOL_A_BITSET_BITS_BIT {} {:?}",
                                nla.kind(),
                                nla.value(),
                            );
                        }
                    }
                }
                bit_sets.push(bit_set);
            }
            _ => {
                warn!(
                    "Unknown ETHTOOL_A_BITSET_BITS kind {}, {:?}",
                    bit_nla.kind(),
                    bit_nla.value()
                );
            }
        };
    }
    Ok(bit_sets)
}
