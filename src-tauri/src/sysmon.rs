use sysinfo::{System, Cpu};
use tauri::State;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct AppState {
    pub system: Arc<Mutex<System>>,
}

// Function to periodically refresh CPU information
pub fn start_cpu_refresh(system: Arc<Mutex<System>>) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(1));
            let mut system = system.lock().unwrap();
            system.refresh_cpu();  // Refresh CPU information
        }
    });
}

// Function to periodically refresh process information
pub fn start_process_refresh(system: Arc<Mutex<System>>) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));  // Refresh processes every 2 seconds
            let mut system = system.lock().unwrap();
            system.refresh_processes();  // Refresh process information
        }
    });
}

// Command to retrieve system info (CPU usage, memory, etc.)
#[tauri::command]
pub fn get_system_info(state: State<AppState>) -> String {
    let system = state.system.lock().unwrap();
    let cpu_usage = system.global_cpu_info().cpu_usage();
    let total_memory = system.total_memory();
    let used_memory = system.used_memory();
    let total_swap = system.total_swap();
    let used_swap = system.used_swap();
    serde_json::json!({
        "cpu_usage": cpu_usage,
        "total_memory": total_memory,
        "used_memory": used_memory,
        "total_swap": total_swap,
        "used_swap": used_swap,
    }).to_string()
}

// Command to retrieve the list of processes (with CPU and memory usage)
#[tauri::command]
pub fn get_processes(state: State<AppState>) -> String {
    let system = state.system.lock().unwrap();
    let processes: Vec<_> = system.processes().iter().map(|(pid, process)| {
        serde_json::json!({
            "pid": pid.to_string(),
            "name": process.name(),
            "cpu_usage": process.cpu_usage(),
            "memory_usage": process.memory(),
        })
    }).collect();
    serde_json::json!(processes).to_string()
}
