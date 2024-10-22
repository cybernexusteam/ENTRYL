mod sysmon;
mod ml_check;

use sysinfo::System;
use std::sync::{Arc, Mutex};
use sysmon::{AppState, get_system_info, get_processes, start_cpu_refresh};

use ml_check::scan_and_get_results;

fn main() {
    let system = Arc::new(Mutex::new(System::new_all()));
    
    // Start the CPU refresh task
    start_cpu_refresh(Arc::clone(&system));

    tauri::Builder::default()
        .manage(AppState { system })
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            get_processes,
            scan_and_get_results
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
