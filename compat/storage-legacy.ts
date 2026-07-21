import {
  accountsStorageSnapshotKey,
  saveStore,
  storagePull,
  storagePush,
  storageSync,
  type AccountsStorageSyncResult,
} from "../src/storage.js";
import type { Store } from "../src/types.js";

const env: NodeJS.ProcessEnv = { HASNA_ACCOUNTS_MACHINE_ID: "compile-probe" };

const keyWithEnv: string = accountsStorageSnapshotKey(env);
const keyWithDefault: string = accountsStorageSnapshotKey();
const pushWithEnv: Promise<AccountsStorageSyncResult> = storagePush(env);
const pullWithEnv: Promise<AccountsStorageSyncResult> = storagePull(env);
const syncWithEnv: Promise<AccountsStorageSyncResult> = storageSync(env);
const syncWithDefault: Promise<AccountsStorageSyncResult> = storageSync();
const legacyStore: Store = {
  version: 1,
  current: {},
  applied: {},
  toolLocks: {},
  profiles: [],
  tools: [],
};
saveStore(legacyStore);

void [
  keyWithEnv,
  keyWithDefault,
  pushWithEnv,
  pullWithEnv,
  syncWithEnv,
  syncWithDefault,
  legacyStore,
];
