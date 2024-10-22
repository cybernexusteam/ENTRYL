use std::process::Command;
use std::fs;
use std::collections::HashMap;
use serde_json;
use tauri::command;

#[command] 
pub async fn run_ml_check(directory: String) -> Result<bool, String> {
    // Construct and run the command to invoke the Python script
    let output = Command::new("python")
        .arg("C:/Users/26dwi/ENTRYL/src-ai/runmlchck.py")
        .arg(&directory)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                let json_file_path = "results.json";
                match fs::read_to_string(json_file_path) {
                    Ok(content) => {
                        // Parse the JSON content
                        let results: HashMap<String, String> = serde_json::from_str(&content)
                            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

                        // Check if any file is marked as malicious
                        let is_malicious = results.values().any(|status| status == "malicious");

                        // Return true if malicious, false otherwise
                        return Ok(is_malicious);
                    }
                    Err(err) => {
                        // Handle errors reading the JSON file
                        return Err(format!("Failed to read results.json: {}", err));
                    }
                }
            } else {
                // Handle the case where the Python script returned an error
                let error = String::from_utf8_lossy(&output.stderr).to_string();
                return Err(format!("Python script failed: {}", error));
            }
        }
        Err(err) => {
            // Handle any errors that occurred while trying to run the command
            return Err(format!("Failed to execute Python script: {}", err));
        }
    }
}