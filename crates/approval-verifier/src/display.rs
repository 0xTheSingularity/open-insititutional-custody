//! The trusted approval display (RFC 0001 §4.3, RFC 0002 §8, A34/C15).
//!
//! An [`ApprovalDisplay`] is produced only by
//! [`IndependentVerifier::render`](crate::IndependentVerifier::render) from
//! verified objects: every value is either decoded from the candidate's
//! native bytes by the pinned adapter, recomputed (hashes, addresses, amount
//! formatting), or read from a registry/policy object whose identity the
//! approval binds. Nothing is copied from a console-supplied description.
//!
//! ## Amount formatting rule
//!
//! [`format_amount`] renders `base_units / 10^decimals` exactly, using only
//! integer/string arithmetic (no floating point):
//!
//! * the integer part has no leading zeros (a lone `0` when below one unit)
//!   and no thousands separators;
//! * the fractional part is written to full precision and then trailing
//!   zeros are trimmed;
//! * if the fractional part is entirely zero the decimal point is omitted.
//!
//! Examples: `(1_500_000, 6) -> "1.5"`, `(1_000_000, 6) -> "1"`,
//! `(1_000_000, 18) -> "0.000000000001"`, `(1_000_000, 9) -> "0.001"`,
//! `(0, 6) -> "0"`, `(42, 0) -> "42"`.
//!
//! ## Card rendering
//!
//! `Display` renders a fixed-width card of exactly [`CARD_WIDTH`] columns per
//! line, ASCII only. Every value is passed through [`sanitize_display_text`]
//! so control characters, ANSI escapes, bidi overrides, and other non-ASCII
//! code points are shown as visible `\u{..}` escapes and can never disguise
//! or reorder what the approver reads. Long values wrap onto continuation
//! lines; nothing is truncated.

use oic_adapter_evm::address::eip55;
use oic_adapter_solana::address::to_base58;
use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Width in columns of every line of the rendered card.
pub const CARD_WIDTH: usize = 80;
const LABEL_WIDTH: usize = 22;
const INNER_WIDTH: usize = CARD_WIDTH - 4;
const VALUE_WIDTH: usize = INNER_WIDTH - LABEL_WIDTH;

/// Chain state the evidence bundle is anchored to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStateDisplay {
    pub height: u64,
    /// `0x`-prefixed lowercase hex of the block/bank hash.
    pub hash: String,
    pub commitment: String,
}

/// Summary of the bounded template an approver authorizes in
/// `BoundedDirectTransfer` mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateSummary {
    pub chain_wallet_id: ChainWalletId,
    pub network_id: NetworkId,
    pub asset_id: AssetId,
    pub amount_base_units: String,
    pub destination_id: DestinationId,
    pub destination_version: u32,
    pub destination_address_display: String,
    pub max_native_fee_base_units: String,
    pub maximum_successful_payments: u8,
    /// Fields the builder may fill after approval.
    pub fillable: Vec<FillableField>,
}

/// What the independent approval client shows before an approver signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDisplay {
    pub network_id: NetworkId,
    pub chain_profile_id: ChainProfileId,
    /// Recomputed from the key descriptor by the adapter's `derive_address`.
    pub wallet_address_display: String,
    /// Always `"direct_transfer"` in V0.
    pub operation_kind: String,
    /// `native`, `erc20 contract=0x…` (EIP-55), or `spl mint=… program=…` (base58).
    pub asset_identity: String,
    pub asset_symbol_from_registry: String,
    pub decimals: u8,
    pub amount_base_units: String,
    /// See the module-level amount formatting rule.
    pub amount_display: String,
    /// Formatted from the decoded recipient bytes.
    pub recipient_address_display: String,
    pub destination_id: DestinationId,
    pub destination_version: u32,
    pub destination_display_name: String,
    /// Decoded recipient bytes equal the registry destination's address on
    /// the profile's network.
    pub destination_matches_registry: bool,
    pub max_native_fee_base_units: String,
    pub purpose: OperationPurpose,
    pub intent_id: IntentId,
    pub external_reference: String,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub policy_id: PolicyId,
    pub policy_epoch: Epoch,
    pub preview_hash: Hash32,
    pub intent_hash: Hash32,
    pub evidence_state: EvidenceStateDisplay,
    pub evidence_age_seconds: u64,
    pub approval_mode: ApprovalMode,
    pub template: Option<TemplateSummary>,
    pub warnings: Vec<String>,
}

/// Exact decimal rendering of `base_units / 10^decimals`; see the module docs.
pub fn format_amount(base_units: u128, decimals: u8) -> String {
    let digits = base_units.to_string();
    let d = usize::from(decimals);
    if d == 0 {
        return digits;
    }
    let padded = if digits.len() <= d { format!("{}{}", "0".repeat(d + 1 - digits.len()), digits) } else { digits };
    let (int_part, frac_part) = padded.split_at(padded.len() - d);
    let frac = frac_part.trim_end_matches('0');
    if frac.is_empty() {
        int_part.to_string()
    } else {
        format!("{int_part}.{frac}")
    }
}

/// Human form of a chain-native address for a pinned adapter: EIP-55 for
/// `evm` (20 bytes), base58 for `solana` (32 bytes).
pub fn format_native_address(adapter_id: &AdapterId, bytes: &[u8]) -> OicResult<String> {
    match adapter_id.as_str() {
        oic_adapter_evm::ADAPTER_ID => {
            let a: [u8; 20] = bytes.try_into().map_err(|_| OicError::unverifiable(format!("EVM address must be 20 bytes, got {}", bytes.len())))?;
            Ok(eip55(&a))
        }
        oic_adapter_solana::ADAPTER_ID => {
            let a: [u8; 32] = bytes.try_into().map_err(|_| OicError::unverifiable(format!("Solana address must be 32 bytes, got {}", bytes.len())))?;
            Ok(to_base58(&a))
        }
        other => Err(OicError::unsupported(format!("no address formatter for adapter `{other}`"))),
    }
}

/// `native`, `erc20 contract=<EIP-55>`, or `spl mint=<base58> program=<base58>`.
pub fn format_asset_identity(asset: &AssetKind) -> OicResult<String> {
    match asset {
        AssetKind::Native => Ok("native".to_string()),
        AssetKind::Erc20 { contract } => {
            Ok(format!("erc20 contract={}", format_native_address(&AdapterId::unchecked(oic_adapter_evm::ADAPTER_ID), contract.as_slice())?))
        }
        AssetKind::SplToken { mint, token_program } => {
            let sol = AdapterId::unchecked(oic_adapter_solana::ADAPTER_ID);
            Ok(format!("spl mint={} program={}", format_native_address(&sol, mint.as_slice())?, format_native_address(&sol, token_program.as_slice())?))
        }
    }
}

/// Make text safe for a terminal or hardware screen: printable ASCII except
/// `\` passes through; `\` becomes `\\`; everything else (controls, escapes,
/// bidi overrides, any non-ASCII) becomes a visible `\u{XXXX}` escape.
pub fn sanitize_display_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(ch),
            other => out.push_str(&format!("\\u{{{:04x}}}", other as u32)),
        }
    }
    out
}

pub(crate) fn purpose_text(p: OperationPurpose) -> &'static str {
    match p {
        OperationPurpose::Settlement => "settlement",
        OperationPurpose::Treasury => "treasury",
        OperationPurpose::Payroll => "payroll",
        OperationPurpose::Fees => "fees",
        OperationPurpose::Internal => "internal",
        OperationPurpose::Other => "other",
    }
}

pub(crate) fn mode_text(m: ApprovalMode) -> &'static str {
    match m {
        ApprovalMode::ExactCandidate => "exact_candidate",
        ApprovalMode::BoundedDirectTransfer => "bounded_direct_transfer",
    }
}

fn fillable_text(f: FillableField) -> &'static str {
    match f {
        FillableField::SolanaRecentBlockhash => "solana_recent_blockhash",
        FillableField::EvmNonce => "evm_nonce",
        FillableField::EvmFeeFields => "evm_fee_fields",
        FillableField::EvmGasLimit => "evm_gas_limit",
    }
}

fn chunks(s: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars.chunks(width).map(|c| c.iter().collect()).collect()
}

struct Card<'a, 'b> {
    f: &'a mut fmt::Formatter<'b>,
}

impl Card<'_, '_> {
    fn rule(&mut self, c: char) -> fmt::Result {
        writeln!(self.f, "+{}+", c.to_string().repeat(CARD_WIDTH - 2))
    }
    fn text(&mut self, text: &str) -> fmt::Result {
        for line in chunks(&sanitize_display_text(text), INNER_WIDTH) {
            writeln!(self.f, "| {line:<INNER_WIDTH$} |")?;
        }
        Ok(())
    }
    fn row(&mut self, label: &str, value: &str) -> fmt::Result {
        for (i, line) in chunks(&sanitize_display_text(value), VALUE_WIDTH).into_iter().enumerate() {
            let l = if i == 0 { label } else { "" };
            writeln!(self.f, "| {l:<LABEL_WIDTH$}{line:<VALUE_WIDTH$} |")?;
        }
        Ok(())
    }
}

impl fmt::Display for ApprovalDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut c = Card { f };
        c.rule('=')?;
        c.text("OIC INDEPENDENT APPROVAL - VERIFY EVERY LINE BEFORE SIGNING")?;
        c.rule('=')?;
        c.row("OPERATION", &self.operation_kind)?;
        c.row("NETWORK", self.network_id.as_str())?;
        c.row("CHAIN PROFILE", self.chain_profile_id.as_str())?;
        c.row("FROM WALLET", &self.wallet_address_display)?;
        c.rule('-')?;
        c.row("AMOUNT", &format!("{} {}", self.amount_display, self.asset_symbol_from_registry))?;
        c.row("AMOUNT (BASE UNITS)", &format!("{} (decimals {})", self.amount_base_units, self.decimals))?;
        c.row("ASSET", &self.asset_identity)?;
        c.row("TO ADDRESS", &self.recipient_address_display)?;
        c.row("DESTINATION", &self.destination_display_name)?;
        c.row("DESTINATION ID", &format!("{} v{}", self.destination_id, self.destination_version))?;
        c.row("REGISTRY MATCH", if self.destination_matches_registry { "YES" } else { "NO - DO NOT APPROVE" })?;
        c.row("MAX NETWORK FEE", &format!("{} native base units", self.max_native_fee_base_units))?;
        c.rule('-')?;
        c.row("PURPOSE", purpose_text(self.purpose))?;
        c.row("INTENT", self.intent_id.as_str())?;
        c.row("EXTERNAL REFERENCE", &self.external_reference)?;
        c.row("CANDIDATE", &format!("{} rev {}", self.candidate_id, self.candidate_revision))?;
        c.row("POLICY", &format!("{} epoch {}", self.policy_id, self.policy_epoch))?;
        c.row("APPROVAL MODE", mode_text(self.approval_mode))?;
        c.row("PREVIEW HASH", &self.preview_hash.to_hex())?;
        c.row("INTENT HASH", &self.intent_hash.to_hex())?;
        c.row("EVIDENCE", &format!("height {} ({})", self.evidence_state.height, self.evidence_state.commitment))?;
        c.row("EVIDENCE BLOCK HASH", &self.evidence_state.hash)?;
        c.row("EVIDENCE AGE", &format!("{}s", self.evidence_age_seconds))?;
        if let Some(t) = &self.template {
            c.rule('-')?;
            c.text("BOUNDED TEMPLATE (builder may fill only the listed fields)")?;
            c.row("TEMPLATE WALLET", t.chain_wallet_id.as_str())?;
            c.row("TEMPLATE NETWORK", t.network_id.as_str())?;
            c.row("TEMPLATE ASSET", t.asset_id.as_str())?;
            c.row("TEMPLATE AMOUNT", &t.amount_base_units)?;
            c.row("TEMPLATE DESTINATION", &format!("{} v{}", t.destination_id, t.destination_version))?;
            c.row("TEMPLATE ADDRESS", &t.destination_address_display)?;
            c.row("TEMPLATE MAX FEE", &t.max_native_fee_base_units)?;
            c.row("TEMPLATE MAX PAYMENTS", &t.maximum_successful_payments.to_string())?;
            let fill: Vec<&str> = t.fillable.iter().map(|f| fillable_text(*f)).collect();
            c.row("TEMPLATE FILLABLE", &fill.join(", "))?;
        }
        c.rule('-')?;
        if self.warnings.is_empty() {
            c.text("WARNINGS: none")?;
        } else {
            c.text(&format!("WARNINGS: {}", self.warnings.len()))?;
            for w in &self.warnings {
                c.text(&format!("! {w}"))?;
            }
        }
        c.rule('=')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_formatting_rule() {
        assert_eq!(format_amount(1_500_000, 6), "1.5");
        assert_eq!(format_amount(1_000_000, 6), "1");
        assert_eq!(format_amount(1_234_500, 6), "1.2345");
        assert_eq!(format_amount(1, 6), "0.000001");
        assert_eq!(format_amount(0, 6), "0");
        assert_eq!(format_amount(0, 0), "0");
        assert_eq!(format_amount(42, 0), "42");
        assert_eq!(format_amount(1_000_000, 18), "0.000000000001");
        assert_eq!(format_amount(1_250_000_000_000_000_000, 18), "1.25");
        assert_eq!(format_amount(10u128.pow(18), 18), "1");
        assert_eq!(format_amount(1_000_000, 9), "0.001");
        assert_eq!(format_amount(123_456_789_012, 9), "123.456789012");
        assert_eq!(format_amount(100, 2), "1");
        assert_eq!(format_amount(1_010, 2), "10.1");
        // u128::MAX = 340282366920938463463374607431768211455 (39 digits).
        assert_eq!(format_amount(u128::MAX, 18), "340282366920938463463.374607431768211455");
        assert_eq!(format_amount(u128::MAX, 39), "0.340282366920938463463374607431768211455");
        assert_eq!(format_amount(5, 255), format!("0.{}5", "0".repeat(254)));
    }

    #[test]
    fn sanitizer_escapes_everything_but_printable_ascii() {
        assert_eq!(sanitize_display_text("Acme LLC #1"), "Acme LLC #1");
        assert_eq!(sanitize_display_text("a\nb"), "a\\u{000a}b");
        assert_eq!(sanitize_display_text("\u{1b}[31m"), "\\u{001b}[31m");
        assert_eq!(sanitize_display_text("\u{202e}"), "\\u{202e}");
        assert_eq!(sanitize_display_text("é"), "\\u{00e9}");
        assert_eq!(sanitize_display_text("\\u{0041}"), "\\\\u{0041}");
        assert_eq!(sanitize_display_text("\u{1f600}"), "\\u{1f600}");
    }

    #[test]
    fn address_and_asset_identity_formatting() {
        let evm = AdapterId::unchecked("evm");
        let sol = AdapterId::unchecked("solana");
        // EIP-55 reference vector.
        let a = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        assert_eq!(format_native_address(&evm, &a).unwrap(), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_eq!(format_native_address(&sol, &[0u8; 32]).unwrap(), "11111111111111111111111111111111");
        assert_eq!(format_native_address(&evm, &[0u8; 32]).unwrap_err().code, ErrorCode::UnverifiableTransaction);
        assert_eq!(format_native_address(&sol, &[0u8; 20]).unwrap_err().code, ErrorCode::UnverifiableTransaction);
        assert_eq!(format_native_address(&AdapterId::unchecked("xrpl"), &[0u8; 20]).unwrap_err().code, ErrorCode::UnsupportedCapability);

        assert_eq!(format_asset_identity(&AssetKind::Native).unwrap(), "native");
        assert_eq!(
            format_asset_identity(&AssetKind::Erc20 { contract: Bytes(a.clone()) }).unwrap(),
            "erc20 contract=0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        assert_eq!(
            format_asset_identity(&AssetKind::SplToken { mint: Bytes(vec![0; 32]), token_program: Bytes(vec![0; 32]) }).unwrap(),
            "spl mint=11111111111111111111111111111111 program=11111111111111111111111111111111"
        );
        assert!(format_asset_identity(&AssetKind::Erc20 { contract: Bytes(vec![1; 3]) }).is_err());
    }
}
