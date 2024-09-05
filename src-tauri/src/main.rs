mod sysmon;

use sysinfo::System;
use std::sync::{Arc, Mutex};
use sysmon::{AppState, get_system_info, get_processes, start_cpu_refresh};

fn main() {
    let system = Arc::new(Mutex::new(System::new_all()));
    
    // Start the CPU refresh task
    start_cpu_refresh(Arc::clone(&system));

    tauri::Builder::default()
        .manage(AppState { system })
        .invoke_handler(tauri::generate_handler![get_system_info, get_processes])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}