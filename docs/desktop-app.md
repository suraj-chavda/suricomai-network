# SuriComAI desktop app

A desktop window for the local node, in the manner of Bitcoin Core's Qt app: a status bar that is always visible, a guided first run, and one page each for Overview, Ask, Models, Network and Settings.

> **Development build.** The app runs the lab runtime inside the window. Answers are `not-private`, quotes are software quotes, and there is no wallet, payment or token. Running it requires the Owner's written permission. See the [license](../LICENSE).

## Run it

```bash
cd apps/desktop/src-tauri
cargo run
```

Linux needs the WebKitGTK 4.1 and GTK 3 development packages. Windows uses the system WebView2.

## Installers

| System | Files |
| --- | --- |
| macOS | `.dmg` (Apple silicon and Intel builds) |
| Windows | `-setup.exe` installer and `.msi` |
| Linux | `.AppImage` and `.deb` |

Build them locally with `cargo install tauri-cli --version "^2" --locked`, then `cargo tauri build` in `apps/desktop/src-tauri`. The `release` workflow builds all four targets and attaches the files, with SHA-256 checksums, to a **draft** pre-release when a `v*` tag is pushed. Nothing is published until the owner reviews the draft.

The installers are **not code-signed or notarized**, so macOS Gatekeeper and Windows SmartScreen will warn before opening them. Signing needs an Apple Developer ID and a Windows code-signing certificate, which the owner has not set up. An iOS `.ipa` is not planned: the app runs a node on the computer, and a phone build would need an Apple developer account and a separate design.

## Look

The interface follows the computer it runs on. The window picks a look at start (`html[data-os]`):

| System | Type | Shape |
| --- | --- | --- |
| macOS | SF Pro | Large radii, pill buttons, translucent sidebar |
| Windows | Segoe UI Variable | Fluent proportions, 4 px controls, accent bar on the current page |
| Linux | Cantarell, Ubuntu, Noto | Flat, rounded, generous spacing |

The palette is ivory and burgundy by day, obsidian and antique gold by night. Cards tilt toward the pointer and pages rise in. Both stop under the system "reduce motion" setting. Light or dark follows the system and can be set in Settings.

## Security model

- The page can call only ten named commands. Each is listed in the build manifest and in `capabilities/default.json`.
- The isolation pattern runs a gatekeeper (`isolation/isolation.js`) between the page and the app. It refuses any command or argument shape it does not know.
- The content security policy allows only the app's own files and IPC. The page has no inline script or style and no network access.
- The window may show only the app's own pages. Any other navigation is refused.
- A typed message is never a command. It is validated (not empty, at most 8192 bytes, no NUL) and then sealed.
- Errors are fixed codes. A poisoned lock fails closed.

## Status

| Check | State |
| --- | --- |
| Rust tests, clippy, isolation tests | Pass on macOS |
| Launches as a real window | Verified on macOS |
| Windows and Linux builds | CI workflow added, not yet run |
| macOS `.app` and `.dmg` build and launch | Verified on Apple silicon |
| Windows and Linux installers | Built by the release workflow, not yet opened on those systems |
| Code signing, notarization, auto-update | Not done |
