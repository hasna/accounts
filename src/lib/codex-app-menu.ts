import { spawn, spawnSync, type SpawnOptions, type SpawnSyncOptions } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { Profile } from "../types.js";
import { AccountsError } from "../types.js";
import { accountsHome } from "../storage.js";
import { appliedProfile } from "./apply.js";
import { resolveStore, type AccountsStore } from "./store.js";
import { getTool } from "./tools.js";
import { switchProfile, type SwitchResult } from "./switch.js";

export interface CodexAppMenuProfile {
  name: string;
  tool: string;
  email?: string;
  displayName?: string;
  description?: string;
  dir: string;
  active: boolean;
  applied: boolean;
}

export interface CodexAppMenuState {
  tool: {
    id: "codex-app";
    label: string;
    bin: string;
  };
  activeProfileName?: string;
  appliedProfileName?: string;
  profiles: CodexAppMenuProfile[];
}

export interface CodexAppRelaunchOptions {
  args?: string[];
  quit?: boolean;
  launch?: boolean;
  relaunchDelayMs?: number;
  runner?: CodexAppProcessRunner;
}

export interface CodexAppMenuSwitchResult {
  switch: SwitchResult;
  quitAttempted: boolean;
  launchStarted: boolean;
  launchCommand: string[];
}

export interface CodexAppProcessRunner {
  spawnSync(command: string, args: string[], options?: SpawnSyncOptions): { status: number | null; error?: Error };
  spawn(command: string, args: string[], options?: SpawnOptions): { unref?: () => void };
}

const defaultRunner: CodexAppProcessRunner = {
  spawnSync,
  spawn,
};

const QUIT_CODEX_APP_SCRIPT = `
tell application "System Events"
  set codexIsRunning to exists (processes where name is "Codex")
end tell
if codexIsRunning then
  tell application "Codex" to quit
end if
`;

function toMenuProfile(profile: Profile, activeName?: string, appliedName?: string): CodexAppMenuProfile {
  return {
    name: profile.name,
    tool: profile.tool,
    ...(profile.email ? { email: profile.email } : {}),
    ...(profile.displayName ? { displayName: profile.displayName } : {}),
    ...(profile.description ? { description: profile.description } : {}),
    dir: profile.dir,
    active: profile.name === activeName,
    applied: profile.name === appliedName,
  };
}

export async function codexAppMenuState(store: AccountsStore = resolveStore()): Promise<CodexAppMenuState> {
  const tool = getTool("codex-app");
  const activeName = (await store.currentProfile("codex-app"))?.name;
  // appliedProfile is the machine-local applied-auth map, not the shared
  // registry — it stays local by design (see store.ts scope notes).
  const appliedName = appliedProfile("codex-app")?.name;
  const profiles = await store.listProfiles("codex-app");
  return {
    tool: {
      id: "codex-app",
      label: tool.label,
      bin: tool.bin,
    },
    ...(activeName ? { activeProfileName: activeName } : {}),
    ...(appliedName ? { appliedProfileName: appliedName } : {}),
    profiles: profiles.map((profile) => toMenuProfile(profile, activeName, appliedName)),
  };
}

async function assertCodexAppProfile(name: string, store: AccountsStore): Promise<Profile> {
  const profile = await store.getProfile(name, "codex-app");
  if (profile.tool !== "codex-app") {
    throw new AccountsError(`profile "${name}" is for ${profile.tool}, not codex-app`);
  }
  return profile;
}

function quitCodexApp(runner: CodexAppProcessRunner): void {
  if (process.platform !== "darwin") return;
  const result = runner.spawnSync("/usr/bin/osascript", ["-e", QUIT_CODEX_APP_SCRIPT], { stdio: "ignore" });
  if (result.error) throw new AccountsError(`failed to ask Codex.app to quit: ${result.error.message}`);
}

export async function switchCodexAppFromMenu(
  name: string,
  opts: CodexAppRelaunchOptions = {},
): Promise<CodexAppMenuSwitchResult> {
  const store = resolveStore();
  await assertCodexAppProfile(name, store);
  const result = await switchProfile(name, { tool: "codex-app", mode: "active", args: opts.args }, store);
  const [bin, ...launchArgs] = result.command;
  if (!bin) throw new AccountsError("codex-app launch command is empty");

  const shouldQuit = opts.quit !== false;
  const shouldLaunch = opts.launch !== false;
  const runner = opts.runner ?? defaultRunner;
  if (shouldQuit) quitCodexApp(runner);
  if (shouldQuit && shouldLaunch) await delay(opts.relaunchDelayMs ?? 1200);

  if (shouldLaunch) {
    const child = runner.spawn(bin, launchArgs, {
      detached: true,
      stdio: "ignore",
      env: { ...process.env, ...result.env },
    });
    child.unref?.();
  }

  return {
    switch: result,
    quitAttempted: shouldQuit,
    launchStarted: shouldLaunch,
    launchCommand: result.command,
  };
}

function swiftString(value: string): string {
  return JSON.stringify(value);
}

export function codexAppMenuSwiftSource(accountsBin = "accounts"): string {
  const commandLiteral = swiftString(accountsBin);
  return `import Cocoa
import Foundation

struct MenuProfile: Codable {
  let name: String
  let tool: String
  let email: String?
  let displayName: String?
  let description: String?
  let dir: String
  let active: Bool
  let applied: Bool
}

struct MenuTool: Codable {
  let id: String
  let label: String
  let bin: String
}

struct MenuState: Codable {
  let tool: MenuTool
  let activeProfileName: String?
  let appliedProfileName: String?
  let profiles: [MenuProfile]
}

final class AccountsCodexAppMenu: NSObject {
  let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
  let accountsCommand = ${commandLiteral}

  override init() {
    super.init()
    statusItem.button?.title = "Codex"
    refresh()
  }

  func runAccounts(_ args: [String]) -> Data? {
    let process = Process()
    if accountsCommand.contains("/") {
      process.executableURL = URL(fileURLWithPath: accountsCommand)
    } else {
      process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
      process.arguments = [accountsCommand] + args
    }
    if accountsCommand.contains("/") {
      process.arguments = args
    }
    let output = Pipe()
    process.standardOutput = output
    process.standardError = Pipe()
    do {
      try process.run()
      process.waitUntilExit()
      return process.terminationStatus == 0 ? output.fileHandleForReading.readDataToEndOfFile() : nil
    } catch {
      return nil
    }
  }

  func state() -> MenuState? {
    guard let data = runAccounts(["codex-app", "menu-state", "--json"]) else { return nil }
    return try? JSONDecoder().decode(MenuState.self, from: data)
  }

  @objc func refresh() {
    let menu = NSMenu()
    guard let state = state() else {
      let item = NSMenuItem(title: "Unable to load accounts", action: nil, keyEquivalent: "")
      item.isEnabled = false
      menu.addItem(item)
      menu.addItem(NSMenuItem.separator())
      let refreshItem = NSMenuItem(title: "Refresh", action: #selector(refresh), keyEquivalent: "r")
      refreshItem.target = self
      menu.addItem(refreshItem)
      let quitItem = NSMenuItem(title: "Quit Menu", action: #selector(quit), keyEquivalent: "q")
      quitItem.target = self
      menu.addItem(quitItem)
      statusItem.menu = menu
      return
    }

    statusItem.button?.title = state.activeProfileName.map { "Codex: \\($0)" } ?? "Codex"
    if state.profiles.isEmpty {
      let item = NSMenuItem(title: "No codex-app profiles", action: nil, keyEquivalent: "")
      item.isEnabled = false
      menu.addItem(item)
    } else {
      for profile in state.profiles {
        let label = profile.displayName ?? profile.email ?? profile.name
        let marker = profile.active ? "✓ " : ""
        let item = NSMenuItem(title: "\\(marker)\\(profile.name) - \\(label)", action: #selector(switchProfile(_:)), keyEquivalent: "")
        item.target = self
        item.representedObject = profile.name
        menu.addItem(item)
      }
    }
    menu.addItem(NSMenuItem.separator())
    let refreshItem = NSMenuItem(title: "Refresh", action: #selector(refresh), keyEquivalent: "r")
    refreshItem.target = self
    menu.addItem(refreshItem)
    let quitItem = NSMenuItem(title: "Quit Menu", action: #selector(quit), keyEquivalent: "q")
    quitItem.target = self
    menu.addItem(quitItem)
    statusItem.menu = menu
  }

  @objc func switchProfile(_ sender: NSMenuItem) {
    guard let name = sender.representedObject as? String else { return }
    DispatchQueue.global(qos: .userInitiated).async {
      _ = self.runAccounts(["codex-app", "menu-switch", name, "--json"])
      DispatchQueue.main.async {
        self.refresh()
      }
    }
  }

  @objc func quit() {
    NSApp.terminate(nil)
  }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AccountsCodexAppMenu()
withExtendedLifetime(delegate) {
  app.run()
}
`;
}

function resolveSwiftBinary(): string {
  const xcrun = spawnSync("/usr/bin/xcrun", ["--find", "swift"], { encoding: "utf8" });
  if (!xcrun.error && xcrun.status === 0) {
    const found = String(xcrun.stdout).trim();
    if (found) return found;
  }
  return "swift";
}

export interface RunCodexAppMenuBarOptions {
  accountsBin?: string;
  swiftBin?: string;
}

export function runCodexAppMenuBar(opts: RunCodexAppMenuBarOptions = {}): never {
  if (process.platform !== "darwin") {
    throw new AccountsError("codex-app menubar is only supported on macOS");
  }

  const sourcePath = join(accountsHome(), "codex-app-menubar.swift");
  mkdirSync(dirname(sourcePath), { recursive: true });
  writeFileSync(sourcePath, codexAppMenuSwiftSource(opts.accountsBin ?? "accounts"), { mode: 0o600 });

  const swiftBin = opts.swiftBin ?? resolveSwiftBinary();
  const result = spawnSync(swiftBin, [sourcePath], { stdio: "inherit" });
  if (result.error) throw new AccountsError(`failed to launch Swift menu bar: ${result.error.message}`);
  process.exit(result.status ?? 0);
}

export function codexAppBinaryExists(): boolean {
  return existsSync(getTool("codex-app").bin);
}
