use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
pub struct FileResult {
    pub file_name: String,
    pub status: String,
}

#[tauri::command]
pub fn get_results() -> Result<Vec<FileResult>, String> {
    // Path to the results file generated by your Python script
    let results_file_path = "C:/ProgramData/ENTRYL/temp/results.json";

    // Read the results file
    let file_content = fs::read_to_string(results_file_path)
        .map_err(|e| format!("Failed to read results file: {}", e))?;

    // Deserialize the JSON content into a vector of FileResult
    let results: Vec<FileResult> = serde_json::from_str(&file_content)
        .map_err(|e| format!("Failed to parse results JSON: {}", e))?;

    Ok(results)
}
