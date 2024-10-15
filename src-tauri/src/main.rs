mod sysmon;

use sysinfo::System;
use std::sync::{Arc, Mutex};
use sysmon::{AppState, get_system_info, get_processes, start_cpu_refresh};
use std::process::Command; // Import Command to run system commands
use tauri::command; // Import the command macro

#[tauri::command] // Mark this function as callable from the frontend
async fn run_ml_check(directory: String) -> Result<String, String> {
    // Construct and run the command to invoke the Python script
    let output = Command::new("python")
        .arg("C:/Users/26dwi/ENTRYL/src-ai/runmlchck.py")
        .arg(&directory) // Pass the directory as an argument to the Python script
        .output(); // Execute the command and wait for it to finish

    match output {
        Ok(output) => {
            if output.status.success() {
                // Convert stdout to a string and return the result
                let result = String::from_utf8_lossy(&output.stdout).to_string();
                Ok(result)
            } else {
                // Handle the case where the Python script returned an error
                let error = String::from_utf8_lossy(&output.stderr).to_string();
                Err(format!("Python script failed: {}", error))
            }
        }
        Err(err) => {
            // Handle any errors that occurred while trying to run the command
            Err(format!("Failed to execute Python script: {}", err))
        }
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
