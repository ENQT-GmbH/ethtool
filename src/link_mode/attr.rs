// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::{bitset_util::parse_bitset_bits_nlas, EthtoolAttr, EthtoolHeader};

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

const ETHTOOL_LINK_MODE_10BASET_HALF_BIT: u32 = 0;
const ETHTOOL_LINK_MODE_10BASET_FULL_BIT: u32 = 1;
const ETHTOOL_LINK_MODE_100BASET_HALF_BIT: u32 = 2;
const ETHTOOL_LINK_MODE_100BASET_FULL_BIT: u32 = 3;
const ETHTOOL_LINK_MODE_1000BASET_HALF_BIT: u32 = 4;
const ETHTOOL_LINK_MODE_1000BASET_FULL_BIT: u32 = 5;
const ETHTOOL_LINK_MODE_AUTONEG_BIT: u32 = 6;
const ETHTOOL_LINK_MODE_TP_BIT: u32 = 7;
const ETHTOOL_LINK_MODE_AUI_BIT: u32 = 8;
const ETHTOOL_LINK_MODE_MII_BIT: u32 = 9;
const ETHTOOL_LINK_MODE_FIBRE_BIT: u32 = 10;
const ETHTOOL_LINK_MODE_BNC_BIT: u32 = 11;
const ETHTOOL_LINK_MODE_10000BASET_FULL_BIT: u32 = 12;
const ETHTOOL_LINK_MODE_PAUSE_BIT: u32 = 13;
const ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT: u32 = 14;
const ETHTOOL_LINK_MODE_2500BASEX_FULL_BIT: u32 = 15;
const ETHTOOL_LINK_MODE_BACKPLANE_BIT: u32 = 16;
const ETHTOOL_LINK_MODE_1000BASEKX_FULL_BIT: u32 = 17;
const ETHTOOL_LINK_MODE_10000BASEKX4_FULL_BIT: u32 = 18;
const ETHTOOL_LINK_MODE_10000BASEKR_FULL_BIT: u32 = 19;
const ETHTOOL_LINK_MODE_10000BASER_FEC_BIT: u32 = 20;
const ETHTOOL_LINK_MODE_20000BASEMLD2_FULL_BIT: u32 = 21;
const ETHTOOL_LINK_MODE_20000BASEKR2_FULL_BIT: u32 = 22;
const ETHTOOL_LINK_MODE_40000BASEKR4_FULL_BIT: u32 = 23;
const ETHTOOL_LINK_MODE_40000BASECR4_FULL_BIT: u32 = 24;
const ETHTOOL_LINK_MODE_40000BASESR4_FULL_BIT: u32 = 25;
const ETHTOOL_LINK_MODE_40000BASELR4_FULL_BIT: u32 = 26;
const ETHTOOL_LINK_MODE_56000BASEKR4_FULL_BIT: u32 = 27;
const ETHTOOL_LINK_MODE_56000BASECR4_FULL_BIT: u32 = 28;
const ETHTOOL_LINK_MODE_56000BASESR4_FULL_BIT: u32 = 29;
const ETHTOOL_LINK_MODE_56000BASELR4_FULL_BIT: u32 = 30;
const ETHTOOL_LINK_MODE_25000BASECR_FULL_BIT: u32 = 31;
const ETHTOOL_LINK_MODE_25000BASEKR_FULL_BIT: u32 = 32;
const ETHTOOL_LINK_MODE_25000BASESR_FULL_BIT: u32 = 33;
const ETHTOOL_LINK_MODE_50000BASECR2_FULL_BIT: u32 = 34;
const ETHTOOL_LINK_MODE_50000BASEKR2_FULL_BIT: u32 = 35;
const ETHTOOL_LINK_MODE_100000BASEKR4_FULL_BIT: u32 = 36;
const ETHTOOL_LINK_MODE_100000BASESR4_FULL_BIT: u32 = 37;
const ETHTOOL_LINK_MODE_100000BASECR4_FULL_BIT: u32 = 38;
const ETHTOOL_LINK_MODE_100000BASELR4_ER4_FULL_BIT: u32 = 39;
const ETHTOOL_LINK_MODE_50000BASESR2_FULL_BIT: u32 = 40;
const ETHTOOL_LINK_MODE_1000BASEX_FULL_BIT: u32 = 41;
const ETHTOOL_LINK_MODE_10000BASECR_FULL_BIT: u32 = 42;
const ETHTOOL_LINK_MODE_10000BASESR_FULL_BIT: u32 = 43;
const ETHTOOL_LINK_MODE_10000BASELR_FULL_BIT: u32 = 44;
const ETHTOOL_LINK_MODE_10000BASELRM_FULL_BIT: u32 = 45;
const ETHTOOL_LINK_MODE_10000BASEER_FULL_BIT: u32 = 46;
const ETHTOOL_LINK_MODE_2500BASET_FULL_BIT: u32 = 47;
const ETHTOOL_LINK_MODE_5000BASET_FULL_BIT: u32 = 48;
const ETHTOOL_LINK_MODE_FEC_NONE_BIT: u32 = 49;
const ETHTOOL_LINK_MODE_FEC_RS_BIT: u32 = 50;
const ETHTOOL_LINK_MODE_FEC_BASER_BIT: u32 = 51;
const ETHTOOL_LINK_MODE_50000BASEKR_FULL_BIT: u32 = 52;
const ETHTOOL_LINK_MODE_50000BASESR_FULL_BIT: u32 = 53;
const ETHTOOL_LINK_MODE_50000BASECR_FULL_BIT: u32 = 54;
const ETHTOOL_LINK_MODE_50000BASELR_ER_FR_FULL_BIT: u32 = 55;
const ETHTOOL_LINK_MODE_50000BASEDR_FULL_BIT: u32 = 56;
const ETHTOOL_LINK_MODE_100000BASEKR2_FULL_BIT: u32 = 57;
const ETHTOOL_LINK_MODE_100000BASESR2_FULL_BIT: u32 = 58;
const ETHTOOL_LINK_MODE_100000BASECR2_FULL_BIT: u32 = 59;
const ETHTOOL_LINK_MODE_100000BASELR2_ER2_FR2_FULL_BIT: u32 = 60;
const ETHTOOL_LINK_MODE_100000BASEDR2_FULL_BIT: u32 = 61;
const ETHTOOL_LINK_MODE_200000BASEKR4_FULL_BIT: u32 = 62;
const ETHTOOL_LINK_MODE_200000BASESR4_FULL_BIT: u32 = 63;
const ETHTOOL_LINK_MODE_200000BASELR4_ER4_FR4_FULL_BIT: u32 = 64;
const ETHTOOL_LINK_MODE_200000BASEDR4_FULL_BIT: u32 = 65;
const ETHTOOL_LINK_MODE_200000BASECR4_FULL_BIT: u32 = 66;
const ETHTOOL_LINK_MODE_100BASET1_FULL_BIT: u32 = 67;
const ETHTOOL_LINK_MODE_1000BASET1_FULL_BIT: u32 = 68;
const ETHTOOL_LINK_MODE_400000BASEKR8_FULL_BIT: u32 = 69;
const ETHTOOL_LINK_MODE_400000BASESR8_FULL_BIT: u32 = 70;
const ETHTOOL_LINK_MODE_400000BASELR8_ER8_FR8_FULL_BIT: u32 = 71;
const ETHTOOL_LINK_MODE_400000BASEDR8_FULL_BIT: u32 = 72;
const ETHTOOL_LINK_MODE_400000BASECR8_FULL_BIT: u32 = 73;
const ETHTOOL_LINK_MODE_FEC_LLRS_BIT: u32 = 74;
const ETHTOOL_LINK_MODE_100000BASEKR_FULL_BIT: u32 = 75;
const ETHTOOL_LINK_MODE_100000BASESR_FULL_BIT: u32 = 76;
const ETHTOOL_LINK_MODE_100000BASELR_ER_FR_FULL_BIT: u32 = 77;
const ETHTOOL_LINK_MODE_100000BASECR_FULL_BIT: u32 = 78;
const ETHTOOL_LINK_MODE_100000BASEDR_FULL_BIT: u32 = 79;
const ETHTOOL_LINK_MODE_200000BASEKR2_FULL_BIT: u32 = 80;
const ETHTOOL_LINK_MODE_200000BASESR2_FULL_BIT: u32 = 81;
const ETHTOOL_LINK_MODE_200000BASELR2_ER2_FR2_FULL_BIT: u32 = 82;
const ETHTOOL_LINK_MODE_200000BASEDR2_FULL_BIT: u32 = 83;
const ETHTOOL_LINK_MODE_200000BASECR2_FULL_BIT: u32 = 84;
const ETHTOOL_LINK_MODE_400000BASEKR4_FULL_BIT: u32 = 85;
const ETHTOOL_LINK_MODE_400000BASESR4_FULL_BIT: u32 = 86;
const ETHTOOL_LINK_MODE_400000BASELR4_ER4_FR4_FULL_BIT: u32 = 87;
const ETHTOOL_LINK_MODE_400000BASEDR4_FULL_BIT: u32 = 88;
const ETHTOOL_LINK_MODE_400000BASECR4_FULL_BIT: u32 = 89;
const ETHTOOL_LINK_MODE_100BASEFX_HALF_BIT: u32 = 90;
const ETHTOOL_LINK_MODE_100BASEFX_FULL_BIT: u32 = 91;
const ETHTOOL_LINK_MODE_10BASET1L_FULL_BIT: u32 = 92;
const ETHTOOL_LINK_MODE_800000BASECR8_FULL_BIT: u32 = 93;
const ETHTOOL_LINK_MODE_800000BASEKR8_FULL_BIT: u32 = 94;
const ETHTOOL_LINK_MODE_800000BASEDR8_FULL_BIT: u32 = 95;
const ETHTOOL_LINK_MODE_800000BASEDR8_2_FULL_BIT: u32 = 96;
const ETHTOOL_LINK_MODE_800000BASESR8_FULL_BIT: u32 = 97;
const ETHTOOL_LINK_MODE_800000BASEVR8_FULL_BIT: u32 = 98;
const ETHTOOL_LINK_MODE_10BASET1S_FULL_BIT: u32 = 99;
const ETHTOOL_LINK_MODE_10BASET1S_HALF_BIT: u32 = 100;
const ETHTOOL_LINK_MODE_10BASET1S_P2MP_HALF_BIT: u32 = 101;
const ETHTOOL_LINK_MODE_10BASET1BRR_FULL_BIT: u32 = 102;
const ETHTOOL_LINK_MODE_200000BASECR_FULL_BIT: u32 = 103;
const ETHTOOL_LINK_MODE_200000BASEKR_FULL_BIT: u32 = 104;
const ETHTOOL_LINK_MODE_200000BASEDR_FULL_BIT: u32 = 105;
const ETHTOOL_LINK_MODE_200000BASEDR_2_FULL_BIT: u32 = 106;
const ETHTOOL_LINK_MODE_200000BASESR_FULL_BIT: u32 = 107;
const ETHTOOL_LINK_MODE_200000BASEVR_FULL_BIT: u32 = 108;
const ETHTOOL_LINK_MODE_400000BASECR2_FULL_BIT: u32 = 109;
const ETHTOOL_LINK_MODE_400000BASEKR2_FULL_BIT: u32 = 110;
const ETHTOOL_LINK_MODE_400000BASEDR2_FULL_BIT: u32 = 111;
const ETHTOOL_LINK_MODE_400000BASEDR2_2_FULL_BIT: u32 = 112;
const ETHTOOL_LINK_MODE_400000BASESR2_FULL_BIT: u32 = 113;
const ETHTOOL_LINK_MODE_400000BASEVR2_FULL_BIT: u32 = 114;
const ETHTOOL_LINK_MODE_800000BASECR4_FULL_BIT: u32 = 115;
const ETHTOOL_LINK_MODE_800000BASEKR4_FULL_BIT: u32 = 116;
const ETHTOOL_LINK_MODE_800000BASEDR4_FULL_BIT: u32 = 117;
const ETHTOOL_LINK_MODE_800000BASEDR4_2_FULL_BIT: u32 = 118;
const ETHTOOL_LINK_MODE_800000BASESR4_FULL_BIT: u32 = 119;
const ETHTOOL_LINK_MODE_800000BASEVR4_FULL_BIT: u32 = 120;

const RATE_MATCH_NONE: u8 = 0;
const RATE_MATCH_PAUSE: u8 = 1;
const RATE_MATCH_CRS: u8 = 2;
const RATE_MATCH_OPEN_LOOP: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthtoolLinkModeBit {
    Bit10BaseTHalf,
    Bit10BaseTFull,
    Bit100BaseTHalf,
    Bit100BaseTFull,
    Bit1000BaseTHalf,
    Bit1000BaseTFull,
    BitAutoneg,
    BitTp,
    BitAui,
    BitMii,
    BitFibre,
    BitBnc,
    Bit10000BaseTFull,
    BitPause,
    BitAsymPause,
    Bit2500BaseXFull,
    BitBackplane,
    Bit1000BaseKXFull,
    Bit10000BaseKX4Full,
    Bit10000BaseKRFull,
    Bit10000BaseRFec,
    Bit20000BaseMLD2Full,
    Bit20000BaseKR2Full,
    Bit40000BaseKR4Full,
    Bit40000BaseCR4Full,
    Bit40000BaseSR4Full,
    Bit40000BaseLR4Full,
    Bit56000BaseKR4Full,
    Bit56000BaseCR4Full,
    Bit56000BaseSR4Full,
    Bit56000BaseLR4Full,
    Bit25000BaseCRFull,
    Bit25000BaseKRFull,
    Bit25000BaseSRFull,
    Bit50000BaseCR2Full,
    Bit50000BaseKR2Full,
    Bit100000BaseKR4Full,
    Bit100000BaseSR4Full,
    Bit100000BaseCR4Full,
    Bit100000BaseLR4Er4Full,
    Bit50000BaseSR2Full,
    Bit1000BaseXFull,
    Bit10000BaseCRFull,
    Bit10000BaseSRFull,
    Bit10000BaseLRFull,
    Bit10000BaseLRmFull,
    Bit10000BaseERFull,
    Bit2500BaseTFull,
    Bit5000BaseTFull,
    BitFecNone,
    BitFecRs,
    BitFecBaseR,
    Bit50000BaseKRFull,
    Bit50000BaseSRFull,
    Bit50000BaseCRFull,
    Bit50000BaseLRErFrFull,
    Bit50000BaseDRFull,
    Bit100000BaseKR2Full,
    Bit100000BaseSR2Full,
    Bit100000BaseCR2Full,
    Bit100000BaseLR2Er2Fr2Full,
    Bit100000BaseDR2Full,
    Bit200000BaseKR4Full,
    Bit200000BaseSR4Full,
    Bit200000BaseLR4Er4Fr4Full,
    Bit200000BaseDR4Full,
    Bit200000BaseCR4Full,
    Bit100BaseT1Full,
    Bit1000BaseT1Full,
    Bit400000BaseKR8Full,
    Bit400000BaseSR8Full,
    Bit400000BaseLR8Er8Fr8Full,
    Bit400000BaseDR8Full,
    Bit400000BaseCR8Full,
    BitFecLlrs,
    Bit100000BaseKRFull,
    Bit100000BaseSRFull,
    Bit100000BaseLRErFrFull,
    Bit100000BaseCRFull,
    Bit100000BaseDRFull,
    Bit200000BaseKR2Full,
    Bit200000BaseSR2Full,
    Bit200000BaseLR2Er2Fr2Full,
    Bit200000BaseDR2Full,
    Bit200000BaseCR2Full,
    Bit400000BaseKR4Full,
    Bit400000BaseSR4Full,
    Bit400000BaseLR4Er4Fr4Full,
    Bit400000BaseDR4Full,
    Bit400000BaseCR4Full,
    Bit100BaseFXHalf,
    Bit100BaseFXFull,
    Bit10BaseT1LFull,
    Bit800000BaseCR8Full,
    Bit800000BaseKR8Full,
    Bit800000BaseDR8Full,
    Bit800000BaseDR8V2Full,
    Bit800000BaseSR8Full,
    Bit800000BaseVR8Full,
    Bit10BaseT1SFull,
    Bit10BaseT1SHalf,
    Bit10BaseT1SP2MpHalf,
    Bit10BaseT1BrrFull,
    Bit200000BaseCRFull,
    Bit200000BaseKRFull,
    Bit200000BaseDRFull,
    Bit200000BaseDRV2Full,
    Bit200000BaseSRFull,
    Bit200000BaseVRFull,
    Bit400000BaseCR2Full,
    Bit400000BaseKR2Full,
    Bit400000BaseDR2Full,
    Bit400000BaseDR2V2Full,
    Bit400000BaseSR2Full,
    Bit400000BaseVR2Full,
    Bit800000BaseCR4Full,
    Bit800000BaseKR4Full,
    Bit800000BaseDR4Full,
    Bit800000BaseDR4V2Full,
    Bit800000BaseSR4Full,
    Bit800000BaseVR4Full,
    Other(u32),
}

impl From<u32> for EthtoolLinkModeBit {
    fn from(value: u32) -> Self {
        match value {
            ETHTOOL_LINK_MODE_10BASET_HALF_BIT => Self::Bit10BaseTHalf,
            ETHTOOL_LINK_MODE_10BASET_FULL_BIT => Self::Bit10BaseTFull,
            ETHTOOL_LINK_MODE_100BASET_HALF_BIT => Self::Bit100BaseTHalf,
            ETHTOOL_LINK_MODE_100BASET_FULL_BIT => Self::Bit100BaseTFull,
            ETHTOOL_LINK_MODE_1000BASET_HALF_BIT => Self::Bit1000BaseTHalf,
            ETHTOOL_LINK_MODE_1000BASET_FULL_BIT => Self::Bit1000BaseTFull,
            ETHTOOL_LINK_MODE_AUTONEG_BIT => Self::BitAutoneg,
            ETHTOOL_LINK_MODE_TP_BIT => Self::BitTp,
            ETHTOOL_LINK_MODE_AUI_BIT => Self::BitAui,
            ETHTOOL_LINK_MODE_MII_BIT => Self::BitMii,
            ETHTOOL_LINK_MODE_FIBRE_BIT => Self::BitFibre,
            ETHTOOL_LINK_MODE_BNC_BIT => Self::BitBnc,
            ETHTOOL_LINK_MODE_10000BASET_FULL_BIT => Self::Bit10000BaseTFull,
            ETHTOOL_LINK_MODE_PAUSE_BIT => Self::BitPause,
            ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT => Self::BitAsymPause,
            ETHTOOL_LINK_MODE_2500BASEX_FULL_BIT => Self::Bit2500BaseXFull,
            ETHTOOL_LINK_MODE_BACKPLANE_BIT => Self::BitBackplane,
            ETHTOOL_LINK_MODE_1000BASEKX_FULL_BIT => Self::Bit1000BaseKXFull,
            ETHTOOL_LINK_MODE_10000BASEKX4_FULL_BIT => {
                Self::Bit10000BaseKX4Full
            }
            ETHTOOL_LINK_MODE_10000BASEKR_FULL_BIT => Self::Bit10000BaseKRFull,
            ETHTOOL_LINK_MODE_10000BASER_FEC_BIT => Self::Bit10000BaseRFec,
            ETHTOOL_LINK_MODE_20000BASEMLD2_FULL_BIT => {
                Self::Bit20000BaseMLD2Full
            }
            ETHTOOL_LINK_MODE_20000BASEKR2_FULL_BIT => {
                Self::Bit20000BaseKR2Full
            }
            ETHTOOL_LINK_MODE_40000BASEKR4_FULL_BIT => {
                Self::Bit40000BaseKR4Full
            }
            ETHTOOL_LINK_MODE_40000BASECR4_FULL_BIT => {
                Self::Bit40000BaseCR4Full
            }
            ETHTOOL_LINK_MODE_40000BASESR4_FULL_BIT => {
                Self::Bit40000BaseSR4Full
            }
            ETHTOOL_LINK_MODE_40000BASELR4_FULL_BIT => {
                Self::Bit40000BaseLR4Full
            }
            ETHTOOL_LINK_MODE_56000BASEKR4_FULL_BIT => {
                Self::Bit56000BaseKR4Full
            }
            ETHTOOL_LINK_MODE_56000BASECR4_FULL_BIT => {
                Self::Bit56000BaseCR4Full
            }
            ETHTOOL_LINK_MODE_56000BASESR4_FULL_BIT => {
                Self::Bit56000BaseSR4Full
            }
            ETHTOOL_LINK_MODE_56000BASELR4_FULL_BIT => {
                Self::Bit56000BaseLR4Full
            }
            ETHTOOL_LINK_MODE_25000BASECR_FULL_BIT => Self::Bit25000BaseCRFull,
            ETHTOOL_LINK_MODE_25000BASEKR_FULL_BIT => Self::Bit25000BaseKRFull,
            ETHTOOL_LINK_MODE_25000BASESR_FULL_BIT => Self::Bit25000BaseSRFull,
            ETHTOOL_LINK_MODE_50000BASECR2_FULL_BIT => {
                Self::Bit50000BaseCR2Full
            }
            ETHTOOL_LINK_MODE_50000BASEKR2_FULL_BIT => {
                Self::Bit50000BaseKR2Full
            }
            ETHTOOL_LINK_MODE_100000BASEKR4_FULL_BIT => {
                Self::Bit100000BaseKR4Full
            }
            ETHTOOL_LINK_MODE_100000BASESR4_FULL_BIT => {
                Self::Bit100000BaseSR4Full
            }
            ETHTOOL_LINK_MODE_100000BASECR4_FULL_BIT => {
                Self::Bit100000BaseCR4Full
            }
            ETHTOOL_LINK_MODE_100000BASELR4_ER4_FULL_BIT => {
                Self::Bit100000BaseLR4Er4Full
            }
            ETHTOOL_LINK_MODE_50000BASESR2_FULL_BIT => {
                Self::Bit50000BaseSR2Full
            }
            ETHTOOL_LINK_MODE_1000BASEX_FULL_BIT => Self::Bit1000BaseXFull,
            ETHTOOL_LINK_MODE_10000BASECR_FULL_BIT => Self::Bit10000BaseCRFull,
            ETHTOOL_LINK_MODE_10000BASESR_FULL_BIT => Self::Bit10000BaseSRFull,
            ETHTOOL_LINK_MODE_10000BASELR_FULL_BIT => Self::Bit10000BaseLRFull,
            ETHTOOL_LINK_MODE_10000BASELRM_FULL_BIT => {
                Self::Bit10000BaseLRmFull
            }
            ETHTOOL_LINK_MODE_10000BASEER_FULL_BIT => Self::Bit10000BaseERFull,
            ETHTOOL_LINK_MODE_2500BASET_FULL_BIT => Self::Bit2500BaseTFull,
            ETHTOOL_LINK_MODE_5000BASET_FULL_BIT => Self::Bit5000BaseTFull,
            ETHTOOL_LINK_MODE_FEC_NONE_BIT => Self::BitFecNone,
            ETHTOOL_LINK_MODE_FEC_RS_BIT => Self::BitFecRs,
            ETHTOOL_LINK_MODE_FEC_BASER_BIT => Self::BitFecBaseR,
            ETHTOOL_LINK_MODE_50000BASEKR_FULL_BIT => Self::Bit50000BaseKRFull,
            ETHTOOL_LINK_MODE_50000BASESR_FULL_BIT => Self::Bit50000BaseSRFull,
            ETHTOOL_LINK_MODE_50000BASECR_FULL_BIT => Self::Bit50000BaseCRFull,
            ETHTOOL_LINK_MODE_50000BASELR_ER_FR_FULL_BIT => {
                Self::Bit50000BaseLRErFrFull
            }
            ETHTOOL_LINK_MODE_50000BASEDR_FULL_BIT => Self::Bit50000BaseDRFull,
            ETHTOOL_LINK_MODE_100000BASEKR2_FULL_BIT => {
                Self::Bit100000BaseKR2Full
            }
            ETHTOOL_LINK_MODE_100000BASESR2_FULL_BIT => {
                Self::Bit100000BaseSR2Full
            }
            ETHTOOL_LINK_MODE_100000BASECR2_FULL_BIT => {
                Self::Bit100000BaseCR2Full
            }
            ETHTOOL_LINK_MODE_100000BASELR2_ER2_FR2_FULL_BIT => {
                Self::Bit100000BaseLR2Er2Fr2Full
            }
            ETHTOOL_LINK_MODE_100000BASEDR2_FULL_BIT => {
                Self::Bit100000BaseDR2Full
            }
            ETHTOOL_LINK_MODE_200000BASEKR4_FULL_BIT => {
                Self::Bit200000BaseKR4Full
            }
            ETHTOOL_LINK_MODE_200000BASESR4_FULL_BIT => {
                Self::Bit200000BaseSR4Full
            }
            ETHTOOL_LINK_MODE_200000BASELR4_ER4_FR4_FULL_BIT => {
                Self::Bit200000BaseLR4Er4Fr4Full
            }
            ETHTOOL_LINK_MODE_200000BASEDR4_FULL_BIT => {
                Self::Bit200000BaseDR4Full
            }
            ETHTOOL_LINK_MODE_200000BASECR4_FULL_BIT => {
                Self::Bit200000BaseCR4Full
            }
            ETHTOOL_LINK_MODE_100BASET1_FULL_BIT => Self::Bit100BaseT1Full,
            ETHTOOL_LINK_MODE_1000BASET1_FULL_BIT => Self::Bit1000BaseT1Full,
            ETHTOOL_LINK_MODE_400000BASEKR8_FULL_BIT => {
                Self::Bit400000BaseKR8Full
            }
            ETHTOOL_LINK_MODE_400000BASESR8_FULL_BIT => {
                Self::Bit400000BaseSR8Full
            }
            ETHTOOL_LINK_MODE_400000BASELR8_ER8_FR8_FULL_BIT => {
                Self::Bit400000BaseLR8Er8Fr8Full
            }
            ETHTOOL_LINK_MODE_400000BASEDR8_FULL_BIT => {
                Self::Bit400000BaseDR8Full
            }
            ETHTOOL_LINK_MODE_400000BASECR8_FULL_BIT => {
                Self::Bit400000BaseCR8Full
            }
            ETHTOOL_LINK_MODE_FEC_LLRS_BIT => Self::BitFecLlrs,
            ETHTOOL_LINK_MODE_100000BASEKR_FULL_BIT => {
                Self::Bit100000BaseKRFull
            }
            ETHTOOL_LINK_MODE_100000BASESR_FULL_BIT => {
                Self::Bit100000BaseSRFull
            }
            ETHTOOL_LINK_MODE_100000BASELR_ER_FR_FULL_BIT => {
                Self::Bit100000BaseLRErFrFull
            }
            ETHTOOL_LINK_MODE_100000BASECR_FULL_BIT => {
                Self::Bit100000BaseCRFull
            }
            ETHTOOL_LINK_MODE_100000BASEDR_FULL_BIT => {
                Self::Bit100000BaseDRFull
            }
            ETHTOOL_LINK_MODE_200000BASEKR2_FULL_BIT => {
                Self::Bit200000BaseKR2Full
            }
            ETHTOOL_LINK_MODE_200000BASESR2_FULL_BIT => {
                Self::Bit200000BaseSR2Full
            }
            ETHTOOL_LINK_MODE_200000BASELR2_ER2_FR2_FULL_BIT => {
                Self::Bit200000BaseLR2Er2Fr2Full
            }
            ETHTOOL_LINK_MODE_200000BASEDR2_FULL_BIT => {
                Self::Bit200000BaseDR2Full
            }
            ETHTOOL_LINK_MODE_200000BASECR2_FULL_BIT => {
                Self::Bit200000BaseCR2Full
            }
            ETHTOOL_LINK_MODE_400000BASEKR4_FULL_BIT => {
                Self::Bit400000BaseKR4Full
            }
            ETHTOOL_LINK_MODE_400000BASESR4_FULL_BIT => {
                Self::Bit400000BaseSR4Full
            }
            ETHTOOL_LINK_MODE_400000BASELR4_ER4_FR4_FULL_BIT => {
                Self::Bit400000BaseLR4Er4Fr4Full
            }
            ETHTOOL_LINK_MODE_400000BASEDR4_FULL_BIT => {
                Self::Bit400000BaseDR4Full
            }
            ETHTOOL_LINK_MODE_400000BASECR4_FULL_BIT => {
                Self::Bit400000BaseCR4Full
            }
            ETHTOOL_LINK_MODE_100BASEFX_HALF_BIT => Self::Bit100BaseFXHalf,
            ETHTOOL_LINK_MODE_100BASEFX_FULL_BIT => Self::Bit100BaseFXFull,
            ETHTOOL_LINK_MODE_10BASET1L_FULL_BIT => Self::Bit10BaseT1LFull,
            ETHTOOL_LINK_MODE_800000BASECR8_FULL_BIT => {
                Self::Bit800000BaseCR8Full
            }
            ETHTOOL_LINK_MODE_800000BASEKR8_FULL_BIT => {
                Self::Bit800000BaseKR8Full
            }
            ETHTOOL_LINK_MODE_800000BASEDR8_FULL_BIT => {
                Self::Bit800000BaseDR8Full
            }
            ETHTOOL_LINK_MODE_800000BASEDR8_2_FULL_BIT => {
                Self::Bit800000BaseDR8V2Full
            }
            ETHTOOL_LINK_MODE_800000BASESR8_FULL_BIT => {
                Self::Bit800000BaseSR8Full
            }
            ETHTOOL_LINK_MODE_800000BASEVR8_FULL_BIT => {
                Self::Bit800000BaseVR8Full
            }
            ETHTOOL_LINK_MODE_10BASET1S_FULL_BIT => Self::Bit10BaseT1SFull,
            ETHTOOL_LINK_MODE_10BASET1S_HALF_BIT => Self::Bit10BaseT1SHalf,
            ETHTOOL_LINK_MODE_10BASET1S_P2MP_HALF_BIT => {
                Self::Bit10BaseT1SP2MpHalf
            }
            ETHTOOL_LINK_MODE_10BASET1BRR_FULL_BIT => Self::Bit10BaseT1BrrFull,
            ETHTOOL_LINK_MODE_200000BASECR_FULL_BIT => {
                Self::Bit200000BaseCRFull
            }
            ETHTOOL_LINK_MODE_200000BASEKR_FULL_BIT => {
                Self::Bit200000BaseKRFull
            }
            ETHTOOL_LINK_MODE_200000BASEDR_FULL_BIT => {
                Self::Bit200000BaseDRFull
            }
            ETHTOOL_LINK_MODE_200000BASEDR_2_FULL_BIT => {
                Self::Bit200000BaseDRV2Full
            }
            ETHTOOL_LINK_MODE_200000BASESR_FULL_BIT => {
                Self::Bit200000BaseSRFull
            }
            ETHTOOL_LINK_MODE_200000BASEVR_FULL_BIT => {
                Self::Bit200000BaseVRFull
            }
            ETHTOOL_LINK_MODE_400000BASECR2_FULL_BIT => {
                Self::Bit400000BaseCR2Full
            }
            ETHTOOL_LINK_MODE_400000BASEKR2_FULL_BIT => {
                Self::Bit400000BaseKR2Full
            }
            ETHTOOL_LINK_MODE_400000BASEDR2_FULL_BIT => {
                Self::Bit400000BaseDR2Full
            }
            ETHTOOL_LINK_MODE_400000BASEDR2_2_FULL_BIT => {
                Self::Bit400000BaseDR2V2Full
            }
            ETHTOOL_LINK_MODE_400000BASESR2_FULL_BIT => {
                Self::Bit400000BaseSR2Full
            }
            ETHTOOL_LINK_MODE_400000BASEVR2_FULL_BIT => {
                Self::Bit400000BaseVR2Full
            }
            ETHTOOL_LINK_MODE_800000BASECR4_FULL_BIT => {
                Self::Bit800000BaseCR4Full
            }
            ETHTOOL_LINK_MODE_800000BASEKR4_FULL_BIT => {
                Self::Bit800000BaseKR4Full
            }
            ETHTOOL_LINK_MODE_800000BASEDR4_FULL_BIT => {
                Self::Bit800000BaseDR4Full
            }
            ETHTOOL_LINK_MODE_800000BASEDR4_2_FULL_BIT => {
                Self::Bit800000BaseDR4V2Full
            }
            ETHTOOL_LINK_MODE_800000BASESR4_FULL_BIT => {
                Self::Bit800000BaseSR4Full
            }
            ETHTOOL_LINK_MODE_800000BASEVR4_FULL_BIT => {
                Self::Bit800000BaseVR4Full
            }
            _ => Self::Other(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
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
pub struct EthtoolLinkModeOurs {
    bit: EthtoolLinkModeBit,
    value: bool,
    advertised: bool,
    name: Option<String>,
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
    Ours(Vec<EthtoolLinkModeOurs>),
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
            | Self::RateMatching(_) => 1,
            Self::Ours(_) => {
                todo!("Does not support changing ethtool link mode yet")
            }
            Self::Peer(_) => {
                todo!("Does not support changing ethtool link mode yet")
            }
            Self::Speed(_) | Self::Lanes(_) => 4,
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
                let entries = parse_bitset_bits_nlas(payload)?
                    .into_iter()
                    .filter(|bit| bit.mask().map_or(true, |mask| mask))
                    .map(|bit| EthtoolLinkModeOurs {
                        bit: bit.index().into(),
                        value: bit.value(),
                        advertised: bit.mask().unwrap_or(true),
                        name: bit.name().map(str::to_string),
                    })
                    .collect();
                Self::Ours(entries)
            }
            ETHTOOL_A_LINKMODES_PEER => {
                let entries = parse_bitset_bits_nlas(payload)?
                    .into_iter()
                    .map(|bit| bit.index().into())
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
