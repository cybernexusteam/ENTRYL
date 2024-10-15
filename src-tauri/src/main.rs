mod sysmon;
mod runmlchck

use sysinfo::System;
use std::sync::{Arc, Mutex};
use sysmon::{AppState, get_system_info, get_processes, start_cpu_refresh};
use std::process::Command;
use tauri::command;
use runmlchck::{AppState, run_ml_check}



fn main() {
    let system = Arc::new(Mutex::new(System::new_all()));
    
    // Start the CPU refresh task
    start_cpu_refresh(Arc::clone(&system));

    tauri::Builder::default()
        .manage(AppState { system })
        .invoke_handler(tauri::generate_handler![get_system_info, get_processes, run_ml_check]) 
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
