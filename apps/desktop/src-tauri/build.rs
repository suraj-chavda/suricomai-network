// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.

/// Every command the window may call. A command not listed here has no permission and the
/// window cannot reach it. `capabilities/default.json` grants exactly these.
const COMMANDS: &[&str] = &[
    "app_info",
    "status",
    "models",
    "transcript",
    "ask",
    "select_model",
    "set_temperature",
    "set_max_tokens",
    "clear_chat",
    "last_proof",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build failed");
}
