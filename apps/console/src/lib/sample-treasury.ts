// Illustrative read models only. These are not custody API responses or signed evidence.
export type SampleAsset = {
  symbol: string;
  decimals: number;
  network: string;
  network_identity: string;
  asset_identity: "native";
};

export type SampleTransfer = {
  id: string;
  reference: string;
  purpose: string;
  vault: string;
  asset: SampleAsset;
  source_address: string;
  destination: { name: string; address: string; version: string };
  amount_units: string;
  maximum_fee_units: string;
  actual_fee_units: string | null;
  reserved_units: string;
  state: "AwaitingApproval" | "SubmissionUnknown" | "FinalizedSuccess";
  reconciliation: "pending" | "matched";
  approvals: { recorded: number; required: number };
  updated_at: string;
  timeline: { time: string; title: string; detail: string }[];
};

export type SampleTreasury = {
  source: "illustrative_fixtures";
  as_of: string;
  checkpoint_sequence: string;
  holdings: {
    id: string;
    vault: string;
    asset: SampleAsset;
    canonical_units: string;
    reserved_units: string;
    available_units: string;
  }[];
  transfers: SampleTransfer[];
};

const eth: SampleAsset = {
  symbol: "ETH",
  decimals: 18,
  network: "ethereum-sepolia",
  network_identity: "EVM chain ID 11155111",
  asset_identity: "native",
};
const sol: SampleAsset = {
  symbol: "SOL",
  decimals: 9,
  network: "solana-devnet",
  network_identity: "Solana devnet (illustrative; genesis not verified)",
  asset_identity: "native",
};
const evmSource = "0x52908400098527886E0F7030069857D2E4169EE7";
const evmDestination = "0xde709f2102306220921060314715629080e2fb77";
const solSource = "11111111111111111111111111111111";
const solDestination = "Vote111111111111111111111111111111111111111";

export const sampleTreasury: SampleTreasury = {
  source: "illustrative_fixtures",
  as_of: "2026-10-20T14:12:00Z",
  checkpoint_sequence: "184",
  holdings: [
    {
      id: "sample-evm-vault",
      vault: "Operating treasury",
      asset: eth,
      canonical_units: "10000000000000000000",
      reserved_units: "125042000000000001",
      available_units: "9874957999999999999",
    },
    {
      id: "sample-sol-vault",
      vault: "Research treasury",
      asset: sol,
      canonical_units: "17345678910",
      reserved_units: "0",
      available_units: "17345678910",
    },
  ],
  transfers: [
    {
      id: "sample-eth-042",
      reference: "VENDOR-2026-042",
      purpose: "Infrastructure invoice · sample payment",
      vault: "Operating treasury",
      asset: eth,
      source_address: evmSource,
      destination: {
        name: "Infrastructure partner",
        address: evmDestination,
        version: "3",
      },
      amount_units: "125000000000000001",
      maximum_fee_units: "42000000000000",
      actual_fee_units: null,
      reserved_units: "125042000000000001",
      state: "SubmissionUnknown",
      reconciliation: "pending",
      approvals: { recorded: 2, required: 2 },
      updated_at: "2026-10-20T14:12:00Z",
      timeline: [
        {
          time: "2026-10-20T14:05:00Z",
          title: "Intent proposed",
          detail:
            "Business reference assigned; the request is not yet a payment.",
        },
        {
          time: "2026-10-20T14:08:00Z",
          title: "Approval records collected",
          detail:
            "Two illustrative records. This sample has no signed grants to verify.",
        },
        {
          time: "2026-10-20T14:09:00Z",
          title: "Exposure reserved",
          detail:
            "Principal and maximum native fee held against this operation family.",
        },
        {
          time: "2026-10-20T14:10:00Z",
          title: "Issuance committed",
          detail:
            "A signature may exist. Ordinary pre-issuance cancellation is no longer safe.",
        },
        {
          time: "2026-10-20T14:12:00Z",
          title: "Submission acknowledgement missing",
          detail:
            "RPC timeout does not prove failure. Keep exposure and inspect the existing attempt.",
        },
      ],
    },
    {
      id: "sample-sol-041",
      reference: "RESEARCH-2026-041",
      purpose: "Research allocation · sample payment",
      vault: "Research treasury",
      asset: sol,
      source_address: solSource,
      destination: {
        name: "Research partner",
        address: solDestination,
        version: "2",
      },
      amount_units: "1234567891",
      maximum_fee_units: "15000",
      actual_fee_units: null,
      reserved_units: "0",
      state: "AwaitingApproval",
      reconciliation: "pending",
      approvals: { recorded: 1, required: 2 },
      updated_at: "2026-10-20T14:06:00Z",
      timeline: [
        {
          time: "2026-10-20T14:03:00Z",
          title: "Intent proposed",
          detail: "The native amount and maximum fee are separate constraints.",
        },
        {
          time: "2026-10-20T14:06:00Z",
          title: "Awaiting independent approval",
          detail:
            "One of two illustrative approval records. No signature has been issued in this scenario.",
        },
      ],
    },
    {
      id: "sample-sol-040",
      reference: "RESEARCH-2026-040",
      purpose: "Test allocation · sample payment",
      vault: "Research treasury",
      asset: sol,
      source_address: solSource,
      destination: {
        name: "Research partner",
        address: solDestination,
        version: "2",
      },
      amount_units: "2000000001",
      maximum_fee_units: "15000",
      actual_fee_units: "5000",
      reserved_units: "0",
      state: "FinalizedSuccess",
      reconciliation: "pending",
      approvals: { recorded: 2, required: 2 },
      updated_at: "2026-10-20T13:58:00Z",
      timeline: [
        {
          time: "2026-10-20T13:50:00Z",
          title: "Authorized and issued",
          detail:
            "Illustrative authorization and issuance, not a verified authority receipt.",
        },
        {
          time: "2026-10-20T13:54:00Z",
          title: "Submitted to network",
          detail: "Submission is not inclusion or finality.",
        },
        {
          time: "2026-10-20T13:58:00Z",
          title: "Finalized successfully on chain",
          detail:
            "The chain outcome is finalized in this scenario. Journal reconciliation is still pending.",
        },
      ],
    },
    {
      id: "sample-eth-039",
      reference: "TREASURY-2026-039",
      purpose: "Treasury allocation · sample payment",
      vault: "Operating treasury",
      asset: eth,
      source_address: evmSource,
      destination: {
        name: "Treasury partner",
        address: evmDestination,
        version: "1",
      },
      amount_units: "350000000000000000",
      maximum_fee_units: "42000000000000",
      actual_fee_units: "21000000000000",
      reserved_units: "0",
      state: "FinalizedSuccess",
      reconciliation: "matched",
      approvals: { recorded: 2, required: 2 },
      updated_at: "2026-10-20T13:40:00Z",
      timeline: [
        {
          time: "2026-10-20T13:30:00Z",
          title: "Authorized and issued",
          detail: "Illustrative approval and issuance records only.",
        },
        {
          time: "2026-10-20T13:36:00Z",
          title: "Finalized successfully on chain",
          detail: "Principal and actual native fee recorded in the sample.",
        },
        {
          time: "2026-10-20T13:40:00Z",
          title: "Journal matched",
          detail:
            "Sample reconciliation completed separately after finality. No signed checkpoint is supplied.",
        },
      ],
    },
  ],
};
