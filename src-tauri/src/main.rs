mod sysmon;
mod runmlchck;
mod results; // Add this line to include the results module

use sysinfo::System;
use std::sync::{Arc, Mutex};
use sysmon::{AppState, get_system_info, get_processes, start_cpu_refresh};
use tauri::command;
use runmlchck::{AppState as MLAppState, run_ml_check};
use results::get_results;

fn main() {
    let system = Arc::new(Mutex::new(System::new_all()));
    
    // Start the CPU refresh task
    start_cpu_refresh(Arc::clone(&system));

    tauri::Builder::default()
        .manage(AppState { system }) // Adjust if necessary for the app state
        .invoke_handler(tauri::generate_handler![get_system_info, get_processes, run_ml_check, get_results]) 
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
