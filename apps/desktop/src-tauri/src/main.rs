// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// Keeps Windows from opening a console window next to the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    suricomai_desktop::run();
}
