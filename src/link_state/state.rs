// SPDX-License-Identifier: MIT

const ETHTOOL_LINK_EXT_STATE_AUTONEG: u8 = 0;
const ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE: u8 = 1;
const ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH: u8 = 2;
const ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY: u8 = 3;
const ETHTOOL_LINK_EXT_STATE_NO_CABLE: u8 = 4;
const ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE: u8 = 5;
const ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE: u8 = 6;
const ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE: u8 = 7;
const ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED: u8 = 8;
const ETHTOOL_LINK_EXT_STATE_OVERHEAT: u8 = 9;
const ETHTOOL_LINK_EXT_STATE_MODULE: u8 = 10;

const ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED: u8 = 1;
const ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED: u8 = 2;
const ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED: u8 = 3;
const ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE: u8 = 4;
const ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE: u8 = 5;
const ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD: u8 = 6;

const ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED: u8 = 1;
const ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT: u8 = 2;
const ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY: u8 = 3;
const ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT: u8 = 4;

const ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK: u8 = 1;
const ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK: u8 = 2;
const ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS: u8 = 3;
const ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED: u8 = 4;
const ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED: u8 = 5;

const ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS: u8 = 1;
const ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE: u8 = 2;
const ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST: u8 = 3;
const ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS: u8 = 4;

const ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE: u8 = 1;
const ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE: u8 = 2;

const ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY: u8 = 1;

pub type EthtoolExtSubstateValue = u8;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtState {
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtSubstateAutoneg {
    None,
    NoPartnerDetected,
    AckNotReceived,
    NextPageExchangeFailed,
    NoPartnerDetectedForceMode,
    FecMismatchDuringOverride,
    NoHcd,
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtSubstateLinkTraining {
    None,
    KrFrameLockNotAcquired,
    KrLinkInhibitTimeout,
    KrLinkPartnerDidNotSetReceiverReady,
    RemoteFault,
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtSubstateLinkLogicalMismatch {
    None,
    PcsDidNotAcquireBlockLock,
    PcsDidNotAcquireAmLock,
    PcsDidNotGetAlignStatus,
    FcFecIsNotLocked,
    RsFecIsNotLocked,
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtSubstateBadSignalIntegrity {
    None,
    LargeNumberOfPhysicalErrors,
    UnsupportedRate,
    SerdesReferenceClockLost,
    SerdesAlos,
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtSubstateCableIssue {
    None,
    UnsupportedCable,
    CableTestFailure,
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtSubstateModule {
    None,
    CmisNotReady,
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EthtoolExtSubstate {
    Autoneg(EthtoolExtSubstateAutoneg),
    LinkTraining(EthtoolExtSubstateLinkTraining),
    LinkLogicalMismatch(EthtoolExtSubstateLinkLogicalMismatch),
    BadSignalIntegrity(EthtoolExtSubstateBadSignalIntegrity),
    CableIssue(EthtoolExtSubstateCableIssue),
    Module(EthtoolExtSubstateModule),
    Other(u8),
}

impl From<u8> for EthtoolExtState {
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

impl From<EthtoolExtState> for u8 {
    fn from(value: EthtoolExtState) -> Self {
        match value {
            EthtoolExtState::Autoneg => ETHTOOL_LINK_EXT_STATE_AUTONEG,
            EthtoolExtState::LinkTraining => {
                ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE
            }
            EthtoolExtState::LinkLogicalMismatch => {
                ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH
            }
            EthtoolExtState::BadSignalIntegrity => {
                ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY
            }
            EthtoolExtState::NoCable => ETHTOOL_LINK_EXT_STATE_NO_CABLE,
            EthtoolExtState::CableIssue => ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE,
            EthtoolExtState::EepromIssue => ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE,
            EthtoolExtState::CalibrationFailure => {
                ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE
            }
            EthtoolExtState::PowerBudgetExceeded => {
                ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED
            }
            EthtoolExtState::Overheat => ETHTOOL_LINK_EXT_STATE_OVERHEAT,
            EthtoolExtState::Module => ETHTOOL_LINK_EXT_STATE_MODULE,
            EthtoolExtState::Other(v) => v,
        }
    }
}

impl From<u8> for EthtoolExtSubstateAutoneg {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED => {
                Self::NoPartnerDetected
            }
            ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED => {
                Self::AckNotReceived
            }
            ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED => {
                Self::NextPageExchangeFailed
            }
            ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE => {
                Self::NoPartnerDetectedForceMode
            }
            ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE => {
                Self::FecMismatchDuringOverride
            }
            ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD => Self::NoHcd,
            _ => Self::Other(value),
        }
    }
}

impl From<u8> for EthtoolExtSubstateLinkTraining {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED => {
                Self::KrFrameLockNotAcquired
            }
            ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT => {
                Self::KrLinkInhibitTimeout
            }
            ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY => {
                Self::KrLinkPartnerDidNotSetReceiverReady
            }
            ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT => Self::RemoteFault,
            _ => Self::Other(value),
        }
    }
}

impl From<u8> for EthtoolExtSubstateLinkLogicalMismatch {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK => {
                Self::PcsDidNotAcquireBlockLock
            }
            ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK => {
                Self::PcsDidNotAcquireAmLock
            }
            ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS => {
                Self::PcsDidNotGetAlignStatus
            }
            ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED => {
                Self::FcFecIsNotLocked
            }
            ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED => {
                Self::RsFecIsNotLocked
            }
            _ => Self::Other(value),
        }
    }
}

impl From<u8> for EthtoolExtSubstateBadSignalIntegrity {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS => {
                Self::LargeNumberOfPhysicalErrors
            }
            ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE => {
                Self::UnsupportedRate
            }
            ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST => {
                Self::SerdesReferenceClockLost
            }
            ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS => Self::SerdesAlos,
            _ => Self::Other(value),
        }
    }
}

impl From<u8> for EthtoolExtSubstateCableIssue {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE => {
                Self::UnsupportedCable
            }
            ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE => {
                Self::CableTestFailure
            }
            _ => Self::Other(value),
        }
    }
}

impl From<u8> for EthtoolExtSubstateModule {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY => {
                Self::CmisNotReady
            }
            _ => Self::Other(value),
        }
    }
}

impl EthtoolExtSubstate {
    pub fn from_state_pair(
        state: EthtoolExtState,
        substate: EthtoolExtSubstateValue,
    ) -> EthtoolExtSubstate {
        match state {
            EthtoolExtState::Autoneg => {
                EthtoolExtSubstate::Autoneg(substate.into())
            }
            EthtoolExtState::LinkTraining => {
                EthtoolExtSubstate::LinkTraining(substate.into())
            }
            EthtoolExtState::LinkLogicalMismatch => {
                EthtoolExtSubstate::LinkLogicalMismatch(substate.into())
            }
            EthtoolExtState::BadSignalIntegrity => {
                EthtoolExtSubstate::BadSignalIntegrity(substate.into())
            }
            EthtoolExtState::CableIssue => {
                EthtoolExtSubstate::CableIssue(substate.into())
            }
            EthtoolExtState::Module => {
                EthtoolExtSubstate::Module(substate.into())
            }
            _ => EthtoolExtSubstate::Other(substate),
        }
    }
}
