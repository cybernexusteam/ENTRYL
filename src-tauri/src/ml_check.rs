use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::path::PathBuf;

// Public struct for frontend communication using snake_case
#[derive(Serialize, Deserialize, Debug)]
pub struct PredictionResult {
    pub sha256: String,
    pub prediction: String,
}

// Private struct to match JSON file format
#[derive(Deserialize)]
struct RawResult {
    SHA256: String,
    Prediction: String,
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

// Function to read the results from the temp directory
fn read_ml_results() -> Result<Vec<PredictionResult>, Box<dyn std::error::Error>> {
    // Define the path to the results.json file
    let temp_dir = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:/ProgramData".to_string());
    let results_path = PathBuf::from(temp_dir).join("ENTRYL/temp/results.json");
    
    // Read the file
    let mut file = File::open(results_path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    
    // Deserialize the JSON data into a vector of RawResult first
    let raw_results: Vec<RawResult> = serde_json::from_str(&data)?;
    
    // Convert RawResult into PredictionResult
    let results = raw_results
        .into_iter()
        .map(|raw| PredictionResult {
            sha256: raw.SHA256,
            prediction: raw.Prediction,
        })
        .collect();
    
    Ok(results)
}

// Tauri command to run the Python script and get results
#[tauri::command]
pub fn scan_and_get_results() -> Result<Vec<PredictionResult>, String> {
    // Step 1: Run the Python script to generate results.json
    if let Err(e) = run_python_script() {
        return Err(format!("Error running Python script: {:?}", e));
    }

    // Step 2: Read and return the results
    match read_ml_results() {
        Ok(results) => Ok(results),
        Err(e) => Err(format!("Error reading results: {:?}", e)),
    }
}