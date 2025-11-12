// SPDX-License-Identifier: MIT

use log::warn;
use netlink_packet_core::{
    parse_string, parse_u32, DecodeError, ErrorContext, NlasIterator,
};

const ETHTOOL_A_BITSET_NOMASK: u16 = 1;
const ETHTOOL_A_BITSET_SIZE: u16 = 2;
const ETHTOOL_A_BITSET_BITS: u16 = 3;
const ETHTOOL_A_BITSET_VALUE: u16 = 4;
const ETHTOOL_A_BITSET_MASK: u16 = 5;

const ETHTOOL_A_BITSET_BITS_BIT: u16 = 1;

const ETHTOOL_A_BITSET_BIT_INDEX: u16 = 1;
const ETHTOOL_A_BITSET_BIT_NAME: u16 = 2;
const ETHTOOL_A_BITSET_BIT_VALUE: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct EthtoolVerboseBitsetBit {
    pub index: u32,
    pub value: bool,
    pub name: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct EthtoolCompactBitsetBit {
    pub index: u32,
    pub value: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum EthtoolBitset {
    Verbose(Vec<EthtoolVerboseBitsetBit>),
    Compact(Vec<EthtoolCompactBitsetBit>),
}

impl EthtoolBitset {
    /// Returns a vector of tuples containing the index and value of each bit
    /// entry.
    pub(crate) fn get_entries(&self) -> Vec<(u32, bool)> {
        match self {
            EthtoolBitset::Verbose(bits) => {
                bits.iter().map(|bit| (bit.index, bit.value)).collect()
            }
            EthtoolBitset::Compact(bits) => {
                bits.iter().map(|bit| (bit.index, bit.value)).collect()
            }
        }
    }
}

pub(crate) fn parse_bitset_nlas(
    raw: &[u8],
) -> Result<EthtoolBitset, DecodeError> {
    let mut is_no_mask = false;
    let mut is_compact = None;
    let mut size = None;

    // Bitset format is determined by the presence of either:
    // - ETHTOOL_A_BITSET_VALUE (compact format)
    // - ETHTOOL_A_BITSET_BITS (verbose format)
    //
    // Note: ETHTOOL_A_BITSET_MASK and ETHTOOL_A_BITSET_NOMASK are mutually
    // exclusive, though both may be absent.
    for nla in NlasIterator::new(raw).filter_map(|nla| nla.ok()) {
        match nla.kind() {
            ETHTOOL_A_BITSET_VALUE => {
                is_compact = Some(true);
            }
            ETHTOOL_A_BITSET_BITS => {
                is_compact = Some(false);
            }
            ETHTOOL_A_BITSET_NOMASK => {
                is_no_mask = true;
            }
            ETHTOOL_A_BITSET_SIZE => {
                size = Some(parse_u32(nla.value())? as usize);
            }
            _ => {}
        }
    }

    let is_compact =
        is_compact.ok_or("could not determine if bitset is compact")?;

    if is_compact {
        let size =
            size.ok_or("could not determine the size of compact bitset")?;
        let mut values = Vec::with_capacity(size);
        let mut masks = Vec::with_capacity(size);

        for nla in NlasIterator::new(raw) {
            let nla = nla.context("failed to get NLA for compact bitset")?;
            match nla.kind() {
                ETHTOOL_A_BITSET_VALUE => {
                    values = parse_sized_bitset(nla.value(), size);
                }
                ETHTOOL_A_BITSET_MASK => {
                    masks = parse_sized_bitset(nla.value(), size);
                }
                _ => {}
            }
        }

        if values.len() != size {
            return Err("compact bitset value length mismatch".into());
        }

        if !is_no_mask && masks.len() != size {
            return Err("compact bitset mask length mismatch".into());
        }

        // Create compact bitset based on whether mask is used.
        // - If no mask is used: include all bits that are set to true.
        // - If mask is used: only include bits where mask is true, preserving
        //   their values.
        let bits = if is_no_mask {
            values
                .iter()
                .enumerate()
                .filter_map(|(i, &v)| {
                    v.then_some(EthtoolCompactBitsetBit {
                        index: i as u32,
                        value: true,
                    })
                })
                .collect()
        } else {
            masks
                .iter()
                .zip(values.iter())
                .enumerate()
                .filter_map(|(i, (&m, &v))| {
                    m.then_some(EthtoolCompactBitsetBit {
                        index: i as u32,
                        value: v,
                    })
                })
                .collect()
        };

        Ok(EthtoolBitset::Compact(bits))
    } else {
        for nla in NlasIterator::new(raw) {
            let nla = nla.context("failed to parse NLA for verbose bitset")?;
            if nla.kind() == ETHTOOL_A_BITSET_BITS {
                let bits =
                    parse_verbose_bitset_bits_nla(nla.value(), is_no_mask)?;
                return Ok(EthtoolBitset::Verbose(bits));
            }
        }

        Err("required ETHTOOL_A_BITSET_BITS NLA not found".into())
    }
}

pub(crate) fn parse_bitset_string_nlas(
    raw: &[u8],
) -> Result<Vec<String>, DecodeError> {
    let EthtoolBitset::Verbose(bitset) = parse_bitset_nlas(raw)? else {
        return Err("bitset is not in verbose bitset format".into());
    };

    Ok(bitset.into_iter().map(|bit| bit.name).collect())
}

fn parse_verbose_bitset_bits_nla(
    raw: &[u8],
    is_no_mask: bool,
) -> Result<Vec<EthtoolVerboseBitsetBit>, DecodeError> {
    let mut bit_sets = Vec::new();
    let error_msg = "Failed to parse ETHTOOL_A_BITSET_BITS attributes";
    for bit_nla in NlasIterator::new(raw) {
        let bit_nla = &bit_nla.context(error_msg)?;
        match bit_nla.kind() {
            ETHTOOL_A_BITSET_BITS_BIT => {
                let error_msg =
                    "Failed to parse ETHTOOL_A_BITSET_BITS_BIT attributes";
                let mut bit_set = EthtoolVerboseBitsetBit::default();
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
                            // When ETHTOOL_A_BITSET_NOMASK the bitset is
                            // interpreted as a simple bitmap.
                            // ETHTOOL_A_BITSET_BIT_VALUE is not used in that
                            // case
                            if is_no_mask {
                                bit_set.value = true;
                            }

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

fn parse_sized_bitset(bytes: &[u8], size: usize) -> Vec<bool> {
    const BITS_PER_BYTE: usize = 8;

    let mut result = Vec::with_capacity(size);
    for byte in bytes {
        for bit in 0..BITS_PER_BYTE {
            result.push((byte >> bit) & 1 != 0);
            if result.len() == size {
                return result;
            }
        }
    }

    result.resize(size, false);
    result
}
