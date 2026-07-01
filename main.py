"""NAC System - Main Launcher
Khởi chạy các service trong orchestrator: Listener, PDP, Action, JIT Portal
"""

import subprocess
import sys
import time
import signal
import os
import threading
from pathlib import Path
from queue import Queue, Empty

import httpx

# Service configurations
SERVICES = [
    {
        "name": "Listener Service",
        "port": 8000,
        "cwd": "orchestrator/listener_service",
        "module": "listener_api:app",
        "color": "\033[94m"  # Blue
    },
    {
        "name": "PDP Service",
        "port": 8001,
        "cwd": "orchestrator/pdp_service",
        "module": "pdp_api:app",
        "color": "\033[92m"  # Green
    },
    {
        "name": "Action Service",
        "port": 8002,
        "cwd": "orchestrator/action_service",
        "module": "action_api:app",
        "color": "\033[93m"  # Yellow
    },
    {
        "name": "JIT Portal",
        "port": 8003,
        "cwd": "jit_portal",
        "module": "main:app",
        "color": "\033[95m"  # Magenta
    }
]

RESET_COLOR = "\033[0m"
processes = []
log_queue: Queue[tuple[str, str, str]] = Queue()


def _stream_process_output(name: str, color: str, process: subprocess.Popen):
    if process.stdout is None:
        return
    for line in process.stdout:
        log_queue.put((name, color, line.rstrip("\n")))


def _drain_log_queue():
    while True:
        try:
            name, color, line = log_queue.get_nowait()
        except Empty:
            break
        if line:
            print(f"{color}[{name}]{RESET_COLOR} {line}")


def _wait_for_service_health(port: int, timeout_seconds: float = 10.0) -> bool:
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + timeout_seconds
    with httpx.Client(timeout=1.5) as client:
        while time.time() < deadline:
            try:
                response = client.get(url)
                if response.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(0.3)
    return False


def _stop_process(process: subprocess.Popen):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def _stop_all_processes_only():
    for process in processes:
        if process:
            _stop_process(process)


def _print_service_failure(name: str, color: str, reason: str):
    print(f"{color}[{name}]{RESET_COLOR} ❌ {reason}")
    _drain_log_queue()


def _validate_service_started(service: dict, process: subprocess.Popen) -> bool:
    name = service["name"]
    color = service["color"]
    port = service["port"]

    time.sleep(0.8)
    if process.poll() is not None:
        _print_service_failure(name, color, f"Crashed on startup (exit={process.returncode})")
        return False

    if not _wait_for_service_health(port):
        _print_service_failure(name, color, "Health check failed at /health")
        _stop_process(process)
        return False

    print(f"{color}[{name}]{RESET_COLOR} ✓ Healthy on port {port} (PID: {process.pid})")
    return True


def print_banner():
    """Print startup banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║           NAC System - Orchestrator Services              ║
║          Listener, PDP, Action, JIT Portal Launcher        ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def start_service(service):
    """Start a single service using uvicorn."""
    name = service["name"]
    port = service["port"]
    cwd = service["cwd"]
    module = service["module"]
    color = service["color"]

    print(f"{color}[{name}]{RESET_COLOR} Starting on port {port}...")

    base_dir = Path(__file__).parent
    service_dir = base_dir / cwd

    if not service_dir.exists():
        _print_service_failure(name, color, f"Directory not found: {service_dir}")
        return None

    cmd = [
        sys.executable, "-m", "uvicorn",
        module,
        "--host", "0.0.0.0",
        "--port", str(port)
    ]

    try:
        child_env = os.environ.copy()
        child_env.setdefault("PYTHONUNBUFFERED", "1")
        process = subprocess.Popen(
            cmd,
            cwd=str(service_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=child_env
        )
        threading.Thread(target=_stream_process_output, args=(name, color, process), daemon=True).start()
        return process
    except Exception as e:
        _print_service_failure(name, color, f"Failed to start: {e}")
        return None


def stop_all_services(signum=None, frame=None):
    """Stop all running services."""
    print("\n\n🛑 Stopping all services...")
    _stop_all_processes_only()
    _drain_log_queue()
    print("✓ All services stopped")
    sys.exit(0)


def monitor_services():
    """Monitor service output and restart if crashed."""
    print("\n" + "="*60)
    print("All services running. Press Ctrl+C to stop.")
    print("="*60 + "\n")

    try:
        while True:
            _drain_log_queue()
            for i, process in enumerate(processes):
                service = SERVICES[i]
                if process and process.poll() is not None:
                    print(f"\n⚠️  {service['name']} crashed (exit={process.returncode}). Restarting...")
                    restarted = start_service(service)
                    if restarted and _validate_service_started(service, restarted):
                        processes[i] = restarted
                    else:
                        processes[i] = None
                        _stop_all_processes_only()
                        print("\n❌ Startup/Restart failed. Exiting.")
                        return
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_all_services()


def main():
    """Main entry point"""
    os.environ.setdefault("LOG_FORMAT", "console")

    # Register signal handlers
    signal.signal(signal.SIGINT, stop_all_services)
    signal.signal(signal.SIGTERM, stop_all_services)

    print_banner()

    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        sys.exit(1)

    # Start all services
    print("Starting services...\n")
    for service in SERVICES:
        process = start_service(service)
        processes.append(process)
        time.sleep(1)  # Stagger startup

    # Check if any service failed to start
    failed = [s["name"] for i, s in enumerate(SERVICES) if not processes[i]]
    if failed:
        print(f"\n❌ Failed to start: {', '.join(failed)}")
        stop_all_services()
        sys.exit(1)

    # Print service URLs
    print("\n" + "="*60)
    print("Service URLs:")
    print("="*60)
    for service in SERVICES:
        print(f"  • {service['name']}: http://localhost:{service['port']}")

    # Monitor services
    monitor_services()


if __name__ == "__main__":
    main()
