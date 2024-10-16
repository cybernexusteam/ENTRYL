use std::process::Command; // Import Command to run system commands
use std::fs; // Import fs to read files
use std::collections::HashMap; // Import HashMap for JSON parsing
use serde_json; // Import serde_json for JSON handling
use tauri::command; // Import the command macro

#[command] // Mark this function as callable from the frontend
pub async fn run_ml_check(directory: String) -> Result<bool, String> {
    // Construct and run the command to invoke the Python script
    let output = Command::new("python")
        .arg("C:/Users/26dwi/ENTRYL/src-ai/runmlchck.py") // Path to the Python script
        .arg(&directory) // Pass the directory as an argument to the Python script
        .output(); // Execute the command and wait for it to finish

    match output {
        Ok(output) => {
            if output.status.success() {
                // Attempt to read the results.json file
                let json_file_path = "results.json"; // Path to the results.json
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