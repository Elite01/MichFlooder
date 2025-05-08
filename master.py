import asyncio
import os
import subprocess
import signal
import sys

SHUTDOWN = False

async def worker(task_id: int):
    print(f"[Worker {task_id}] Started")
    while not SHUTDOWN:
        await asyncio.sleep(1)
        print(f"[Worker {task_id}] Working...")

def pull_updates() -> bool:
    """Returns True if new code was pulled."""
    print("[Update Check] Checking for updates...")
    result = subprocess.run(["git", "pull"], capture_output=True, text=True)
    updated = "Already up to date" not in result.stdout
    if updated:
        print("[Update Check] Update detected!")
    else:
        print("[Update Check] No updates.")
    return updated

def shutdown_handler():
    global SHUTDOWN
    print("[Signal] Shutdown requested.")
    SHUTDOWN = True

async def monitor_and_run():
    global SHUTDOWN

    # Register shutdown signals
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, shutdown_handler)
    loop.add_signal_handler(signal.SIGTERM, shutdown_handler)

    num_cores = os.cpu_count() or 1
    print(f"[Startup] Launching {num_cores} workers.")

    workers = [asyncio.create_task(worker(core_index)) for core_index in range(num_cores)]

    # Periodically check for updates
    try:
        while not SHUTDOWN:
            await asyncio.sleep(60)  # Check for updates every 60s
            if pull_updates():
                print("[Restart] Exiting for update.")
                SHUTDOWN = True
    finally:
        print("[Shutdown] Waiting for workers to finish.")
        await asyncio.gather(*workers, return_exceptions=True)

    # Relaunch the script (self-restart)
    print("[Restarting] Relaunching process.")
    os.execv(sys.executable, [sys.executable] + sys.argv)

if __name__ == "__main__":
    try:
        asyncio.run(monitor_and_run())
    except Exception as e:
        print(f"[Fatal] {e}")
        sys.exit(1)
