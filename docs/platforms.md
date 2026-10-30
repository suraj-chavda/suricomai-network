# Platform support

The network crates, the command-line tools and the desktop app are meant to run on macOS, Linux and Windows. CI (`.github/workflows/ci.yml` and `desktop.yml`) builds and tests all three. A Windows build has been type-checked from macOS; a full Windows test run happens only in CI.

| Area | macOS and Linux | Windows |
| --- | --- | --- |
| Crates, tools, tests | Supported | Supported |
| Node identity file (`--key-file`) | Supported. Mode 0600, regular file, no links, checked after opening | Refused with a clear message. Windows has no mode bits and the check cannot be made safely without a permissions API, so the node uses a fresh key each start |
| Trust file permission check | Group and other write refused | Not enforced. Keep the file in your user profile directory |
| Secret files from `suricomai-models keygen` | Created with mode 0600 | Created with the profile's default access. Keep them in your user profile directory |
| `scripts/check-release.sh`, `contracts/*.sh` | Run in sh and Docker | Run in WSL or Git Bash |
| Desktop app | See [desktop-app.md](desktop-app.md) | WebView2 |

Line endings are fixed to LF by `.gitattributes`, because test vectors and digests are over exact bytes.
