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
  preflight: {
    os: string;
    architecture: string;
    version: string;
    durable_state: boolean;
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
