mod sysmon;

use sysinfo::System;
use std::sync::{Arc, Mutex};
use sysmon::{AppState, get_system_info, get_processes, start_cpu_refresh};
use std::process::Command; // Import Command to run system commands
use tauri::command; // Import the command macro

#[command] // Mark this function as callable from the frontend
async fn run_ml_check(directory: String) -> Result<String, String> {
    let output = Command::new("python")
        .arg("C:/Users/26dwi/ENTRYL/src-ai/runmlchck.py")
        .arg("--directory")
        .arg(directory)
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let result = String::from_utf8_lossy(&output.stdout);
        Ok(result.to_string())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(error.to_string())
    }
}

fn main() {
    let system = Arc::new(Mutex::new(System::new_all()));
    
    // Start the CPU refresh task
    start_cpu_refresh(Arc::clone(&system));

    tauri::Builder::default()
        .manage(AppState { system })
        .invoke_handler(tauri::generate_handler![get_system_info, get_processes, run_ml_check]) // Include run_ml_check here
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
