use sysinfo::{System, Cpu};
use tauri::State;
use std::sync::{Arc, Mutex};

struct AppState {
    system: Arc<Mutex<System>>,
}

#[tauri::command]
fn get_system_info(state: State<AppState>) -> String {
    let mut system = state.system.lock().unwrap();
    system.refresh_all();

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

#[tauri::command]
fn get_processes(state: State<AppState>) -> String {
    let mut system = state.system.lock().unwrap();
    system.refresh_all();

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

fn main() {
    let system = Arc::new(Mutex::new(System::new_all()));
    
    tauri::Builder::default()
        .manage(AppState { system })
        .invoke_handler(tauri::generate_handler![get_system_info, get_processes])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}