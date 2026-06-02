# Changelog

All notable changes to `@hasna/accounts` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2026-06-02

### Added

- Initial release — a local-first CLI for managing multiple Claude Code (and other
  AI coding tool) profiles/accounts.
- Profiles with isolated config dirs and a remembered account email per profile.
- Email auto-detection from a tool's account file (Claude Code: `.claude.json` →
  `oauthAccount.emailAddress`).
- Commands: `add`, `list`/`ls`, `show`, `use`, `env`, `launch`/`run`, `shell`,
  `current`, `set`, `detect`, `rename`, `remove`/`rm`, `path`, `doctor`.
- Built-in tools: Claude Code (`CLAUDE_CONFIG_DIR`) and Codex CLI (`CODEX_HOME`).
- Runtime tool registration (`accounts tools add/remove`) so the CLI scales to any
  app that reads a config dir from an environment variable — no code change required.
