import type { SampleTreasury } from "./sample-treasury";

export type Address = {
  network: string;
  address: string;
  label: string;
  imported_at: number;
};

export type Setup = {
  revision: number;
  workspace_name: string | null;
  inventory: Address[];
  updated_at: number;
};

export type Snapshot = {
  schema_version: 1;
  environment: "test";
  mode: "local" | "demo";
  local_only: boolean;
  setup: Setup;
  sample_treasury: SampleTreasury | null;
  preflight: {
    os: string;
    architecture: string;
    version: string;
    /** Local mode: the state database opened and took a write lock for this request. */
    durable_state: boolean;
    /** Whether the server holds the local custody API origin and bearer. Not a reachability check. */
    custody_bridge: "configured" | "not_configured" | "disabled";
    release_signature_verified: false;
  };
  production_ready: false;
  blockers: { title: string; reason: string }[];
};

export type Preview = {
  importable: number;
  excluded: number;
  rows: {
    row: number;
    network: string;
    address: string;
    label: string;
    status: "valid" | "invalid" | "duplicate" | "unsupported";
    reason: string;
  }[];
};
