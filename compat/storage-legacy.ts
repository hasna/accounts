import {
  accountsStorageSnapshotKey,
  storagePull,
  storagePush,
  storageSync,
  type AccountsStorageSyncResult,
} from "../src/storage.js";

const env: NodeJS.ProcessEnv = { HASNA_ACCOUNTS_MACHINE_ID: "compile-probe" };

const keyWithEnv: string = accountsStorageSnapshotKey(env);
const keyWithDefault: string = accountsStorageSnapshotKey();
const pushWithEnv: Promise<AccountsStorageSyncResult> = storagePush(env);
const pullWithEnv: Promise<AccountsStorageSyncResult> = storagePull(env);
const syncWithEnv: Promise<AccountsStorageSyncResult> = storageSync(env);
const syncWithDefault: Promise<AccountsStorageSyncResult> = storageSync();

void [
  keyWithEnv,
  keyWithDefault,
  pushWithEnv,
  pullWithEnv,
  syncWithEnv,
  syncWithDefault,
];
