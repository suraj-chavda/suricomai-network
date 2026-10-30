// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! SuriComAI Network desktop app (development build).
//!
//! The window can call only the commands in `build.rs`, and only with the arguments checked in
//! `core.rs`. It holds no key, reads no file and opens no connection. Every error it gets is a
//! fixed code.

mod core;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use suricomai_runtime::Session;
use tauri::{Manager, State};

use crate::core::{Answer, AppInfo, Line, ModelView, Proof, Status};

/// The one session this app runs, shared by every command.
#[derive(Clone)]
struct AppState {
    session: Arc<Mutex<Session>>,
}

/// A clock before 1970 would make every approval and advertisement look wrong. Use the largest
/// time instead, so everything is refused rather than accepted on a bad clock.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// Lock the session. A lock poisoned by a panic means the state cannot be trusted, so refuse.
fn with_session<T>(
    state: &AppState,
    run: impl FnOnce(&mut Session) -> Result<T, &'static str>,
) -> Result<T, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "session_unavailable".to_string())?;
    run(&mut guard).map_err(str::to_string)
}

/// Run a job off the interface thread, so a long answer never freezes the window.
async fn blocking<T: Send + 'static>(
    state: &State<'_, AppState>,
    run: impl FnOnce(&mut Session) -> Result<T, &'static str> + Send + 'static,
) -> Result<T, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || with_session(&state, run))
        .await
        .map_err(|_| "task_failed".to_string())?
}

#[tauri::command]
fn app_info() -> AppInfo {
    core::app_info()
}

#[tauri::command]
fn status(state: State<'_, AppState>) -> Result<Status, String> {
    with_session(&state, |s| Ok(core::status(s, now())))
}

#[tauri::command]
fn models(state: State<'_, AppState>) -> Result<Vec<ModelView>, String> {
    with_session(&state, |s| Ok(core::models(s, now())))
}

#[tauri::command]
fn transcript(state: State<'_, AppState>) -> Result<Vec<Line>, String> {
    with_session(&state, |s| Ok(core::transcript(s)))
}

#[tauri::command]
fn last_proof(state: State<'_, AppState>) -> Result<Option<Proof>, String> {
    with_session(&state, |s| Ok(core::last_proof(s)))
}

#[tauri::command]
async fn ask(state: State<'_, AppState>, prompt: String) -> Result<Answer, String> {
    blocking(&state, move |s| core::ask(s, &prompt, now())).await
}

#[tauri::command]
async fn select_model(state: State<'_, AppState>, name: String) -> Result<(), String> {
    blocking(&state, move |s| core::select_model(s, &name, now())).await
}

#[tauri::command]
fn set_temperature(state: State<'_, AppState>, value: f64) -> Result<(), String> {
    with_session(&state, |s| core::set_temperature(s, value))
}

#[tauri::command]
fn set_max_tokens(state: State<'_, AppState>, value: u64) -> Result<(), String> {
    with_session(&state, |s| core::set_max_tokens(s, value))
}

#[tauri::command]
fn clear_chat(state: State<'_, AppState>) -> Result<(), String> {
    with_session(&state, |s| {
        core::clear_chat(s);
        Ok(())
    })
}

/// The only addresses the window may show: the app's own pages.
fn is_app_page(url: &tauri::Url) -> bool {
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost"),
        "http" => url.host_str() == Some("tauri.localhost"),
        _ => false,
    }
}

pub fn run() {
    let session = match Session::start(now()) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("SuriComAI could not start its local node: {err}");
            std::process::exit(1);
        }
    };
    let state = AppState {
        session: Arc::new(Mutex::new(session)),
    };
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            app_info,
            status,
            models,
            transcript,
            ask,
            select_model,
            set_temperature,
            set_max_tokens,
            clear_chat,
            last_proof,
        ])
        .setup(|app| {
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("SuriComAI Network")
            .inner_size(1180.0, 780.0)
            .min_inner_size(400.0, 560.0)
            .center()
            // Anything that is not one of the app's own pages is refused, so a link or a
            // redirect can never load outside content into this window.
            .on_navigation(is_app_page)
            .build()?;
            let _ = app.get_webview_window("main");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the SuriComAI window failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> tauri::Url {
        text.parse().unwrap()
    }

    #[test]
    fn only_the_apps_own_pages_may_be_shown() {
        for good in [
            "tauri://localhost/index.html",
            "http://tauri.localhost/index.html",
        ] {
            assert!(is_app_page(&url(good)), "{good}");
        }
        for bad in [
            "https://example.com/",
            "http://localhost:8080/",
            "http://tauri.localhost.evil.com/",
            "tauri://evil/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>1</script>",
            "ftp://tauri.localhost/",
            "https://tauri.localhost/",
        ] {
            assert!(!is_app_page(&url(bad)), "{bad}");
        }
    }
}
