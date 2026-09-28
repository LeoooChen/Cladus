//! `cladus.exe`: the Cladus desktop app. Runs with the user's own rights and
//! controls the Cladus Engine service through its named pipe.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod autostart;
#[cfg(windows)]
mod commands;
#[cfg(windows)]
mod engine;
#[cfg(windows)]
mod icons;
#[cfg(windows)]
mod prefs;
#[cfg(windows)]
mod view;

#[cfg(windows)]
fn main() {
    app::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The Cladus desktop app supports Windows only for now.");
    std::process::exit(1);
}
