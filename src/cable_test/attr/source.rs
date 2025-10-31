// SPDX-License-Identifier: MIT

// Cable test information source
const ETHTOOL_A_CABLE_INF_SRC_TDR: u32 = 1;
const ETHTOOL_A_CABLE_INF_SRC_ALCD: u32 = 2;

/// Source of cable test information.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

impl From<EthtoolCableTestSource> for u32 {
    fn from(value: EthtoolCableTestSource) -> Self {
        match value {
            EthtoolCableTestSource::Tdr => ETHTOOL_A_CABLE_INF_SRC_TDR,
            EthtoolCableTestSource::Alcd => ETHTOOL_A_CABLE_INF_SRC_ALCD,
            EthtoolCableTestSource::Other(v) => v,
        }
    }
}
