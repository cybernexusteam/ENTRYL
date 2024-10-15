use std::process::Command; // Import Command to run system commands
use tauri::command; // Import the command macro
use std::sync::{Arc, Mutex};

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