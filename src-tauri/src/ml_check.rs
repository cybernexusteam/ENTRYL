use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::path::PathBuf;

// Make the struct public and use snake_case for fields
#[derive(Serialize, Deserialize, Debug)]
pub struct PredictionResult {
    sha256: String,
    prediction: String,
}

// Function to run the Python script
fn run_python_script() -> io::Result<()> {
    // Define the path to the Python executable and the script
    let python_executable = "python"; // Adjust if needed to match your Python installation
    let script_path = "C:/Users/26dwi/ENTRYL/src-ai/runmlchck.py"; // Change to the actual path of your Python script
    
    // Run the command to execute the Python script
    Command::new(python_executable)
        .arg(script_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    Ok(())
}

// Function to read the results from the temp directory, extracting sha256 and prediction
fn read_ml_results() -> Result<Vec<PredictionResult>, Box<dyn std::error::Error>> {
    // Define the path to the results.json file
    let temp_dir = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:/ProgramData".to_string());
    let results_path = PathBuf::from(temp_dir).join("ENTRYL/temp/results.json");
    
    // Read the file
    let mut file = File::open(results_path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    
    // Deserialize the JSON data into a vector of PredictionResult
    let results: Vec<PredictionResult> = serde_json::from_str(&mut data)?;
    Ok(results)
}

// Tauri command to run the Python script, then read and pass the results to the frontend
#[tauri::command]
pub fn scan_and_get_results() -> Result<Vec<PredictionResult>, String> {
    // Step 1: Run the Python script to generate results.json
    if let Err(e) = run_python_script() {
        return Err(format!("Error running Python script: {:?}", e));
    }

    // Step 2: Read the results.json file
    match read_ml_results() {
        Ok(results) => {
            // Step 3: Return the results (which includes sha256 and prediction for each file)
            Ok(results)
        }
        Err(e) => Err(format!("Error reading results: {:?}", e)),
    }
}