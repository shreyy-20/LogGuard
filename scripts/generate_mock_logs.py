import os
import time
import random
from datetime import datetime

# Define target paths
LOGS_DIR = os.getenv("LOGS_DIR", "logs")
SYSLOG_PATH = os.path.join(LOGS_DIR, "syslog")
AUTH_PATH = os.path.join(LOGS_DIR, "auth.log")
KERN_PATH = os.path.join(LOGS_DIR, "kern.log")
APP_PATH = os.path.join(LOGS_DIR, "app.log")

# Sample values
HOSTNAMES = ["srv-prod-web01", "srv-db-repl02", "lb-edge-nginx", "dev-workstation"]
PROGRAMS = ["systemd", "cron", "dbus-daemon", "networkd", "kernel", "sshd", "docker", "nginx", "redis"]
LEVELS = ["INFO", "WARNING", "ERROR", "DEBUG"]

SYSLOG_TEMPLATES = [
    "Started Session {session_id} of user {username}.",
    "Received disconnect from {ip} port {port}:11: user request",
    "Disconnected from user {username} {ip} port {port}",
    "Reloading configuration file /etc/nginx/nginx.conf.",
    "Database connection established successfully.",
    "Periodic cron job run-parts /etc/cron.daily started.",
    "Periodic cron job run-parts /etc/cron.daily finished.",
    "Dbus connection request from PID {pid} approved.",
    "Container {container_id} restarted due to healthcheck status.",
]

AUTH_TEMPLATES_FAIL = [
    "Failed password for invalid user {username} from {ip} port {port} ssh2",
    "Failed password for {username} from {ip} port {port} ssh2",
    "Invalid user {username} from {ip} port {port} ssh2"
]

AUTH_TEMPLATES_SUCCESS = [
    "Accepted password for {username} from {ip} port {port} ssh2",
    "session opened for user {username} by (uid=0)"
]

KERN_TEMPLATES = [
    "Initializing cgroup subsys cpuset",
    "ext4: recovery complete on read-only filesystem",
    "eth0: link up, 1000Mbps, full-duplex, lpa 0x01E1",
    "ACPI: Core revision 20221020",
    "usb 1-1.2: New USB device found, idVendor=046d, idProduct=c52b",
]

CRITICAL_TEMPLATES = [
    "kernel: [{time_offset}] Out of memory: Kill process {pid} ({proc_name}) score {score} or sacrifice child",
    "kernel: [{time_offset}] {proc_name}[{pid}]: segfault at {mem_addr} ip {ip_addr} sp {sp_addr} error 4 in libc.so",
    "kernel: [{time_offset}] EXT4-fs error (device sda1): ext4_lookup: deleted inode referenced: {inode}",
    "kernel: [{time_offset}] Kernel panic - not syncing: Attempted to kill init! exitcode={exit_code}"
]

APP_TEMPLATES = [
    "[{timestamp}] [INFO] [UserController] User login request received for '{username}'",
    "[{timestamp}] [INFO] [PaymentGateway] Processed charge of ${amount} successfully",
    "[{timestamp}] [WARNING] [DatabasePool] High pool connection wait time detected ({wait_ms}ms)",
    "[{timestamp}] [ERROR] [MailerService] Failed to send email to '{username}@example.com': connection timeout",
    "[{timestamp}] [DEBUG] [CacheManager] Key '{cache_key}' hit ratio: 94.2%"
]

def get_syslog_timestamp():
    """Returns timestamp in traditional syslog RFC 3164 format (e.g. May 24 01:40:15)"""
    return datetime.now().strftime("%b %d %H:%M:%S")

def get_app_timestamp():
    """Returns timestamp in custom app log format YYYY-MM-DD HH:MM:SS"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def make_ip():
    return f"{random.randint(10, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def main():
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    # Initialize empty files or append to existing
    for path in [SYSLOG_PATH, AUTH_PATH, KERN_PATH, APP_PATH]:
        with open(path, "a") as f:
            f.write(f"# Mock Log stream started at {datetime.now().isoformat()}\n")

    print(f"Log generator running. Simulating active logs in: {LOGS_DIR}/")
    print("Press Ctrl+C to terminate.")

    # Counters to schedule alerts and bursts
    counter = 0

    try:
        while True:
            counter += 1
            now_syslog = get_syslog_timestamp()
            now_app = get_app_timestamp()
            hostname = random.choice(HOSTNAMES)

            # 1. Generate standard Syslog logs (every iteration)
            with open(SYSLOG_PATH, "a", encoding="utf-8") as f_sys:
                prog = random.choice(PROGRAMS)
                pid = random.randint(100, 32000)
                template = random.choice(SYSLOG_TEMPLATES)
                msg = template.format(
                    session_id=random.randint(1000, 9999),
                    username=random.choice(["admin", "guest", "root", "dev", "user1"]),
                    ip=make_ip(),
                    port=random.randint(1024, 65535),
                    pid=pid,
                    container_id=random.choice(["a1b2c3d4", "e5f6g7h8"])
                )
                f_sys.write(f"{now_syslog} {hostname} {prog}[{pid}]: {msg}\n")
                f_sys.flush()

            # 2. Generate Custom App logs (every iteration)
            with open(APP_PATH, "a", encoding="utf-8") as f_app:
                template = random.choice(APP_TEMPLATES)
                msg = template.format(
                    timestamp=now_app,
                    username=random.choice(["alice", "bob", "charlie"]),
                    amount=random.randint(5, 500),
                    wait_ms=random.randint(100, 3500),
                    cache_key=f"user_session:{random.randint(1, 100)}"
                )
                f_app.write(f"{msg}\n")
                f_app.flush()

            # 3. Generate Auth logs (every 3 seconds)
            if counter % 3 == 0:
                with open(AUTH_PATH, "a", encoding="utf-8") as f_auth:
                    is_success = random.random() > 0.4
                    if is_success:
                        template = random.choice(AUTH_TEMPLATES_SUCCESS)
                        msg = template.format(
                            username=random.choice(["root", "admin", "operator", "sysadmin"]),
                            ip=make_ip(),
                            port=random.randint(1024, 65535)
                        )
                    else:
                        template = random.choice(AUTH_TEMPLATES_FAIL)
                        msg = template.format(
                            username=random.choice(["ubuntu", "root", "guest", "admin", "test", "ftp"]),
                            ip=make_ip(),
                            port=random.randint(1024, 65535)
                        )
                    f_auth.write(f"{now_syslog} {hostname} sshd[{random.randint(1000, 9999)}]: {msg}\n")
                    f_auth.flush()

            # 4. Generate Kern logs (every 8 seconds)
            if counter % 8 == 0:
                with open(KERN_PATH, "a", encoding="utf-8") as f_kern:
                    msg = random.choice(KERN_TEMPLATES)
                    f_kern.write(f"{now_syslog} {hostname} kernel: {msg}\n")
                    f_kern.flush()

            # 5. Trigger SSH Brute Force Security Event (every 25 seconds)
            if counter % 25 == 0:
                print("==> Injecting SSH brute-force attack signature...")
                attacker_ip = "198.51.100.42"
                target_user = "admin"
                with open(AUTH_PATH, "a", encoding="utf-8") as f_auth:
                    # Write 6 quick failed attempts (exceeds threshold of 5 attempts/60s)
                    for _ in range(6):
                        f_auth.write(
                            f"{get_syslog_timestamp()} {hostname} sshd[{random.randint(1000, 9999)}]: "
                            f"Failed password for {target_user} from {attacker_ip} port {random.randint(1024, 65535)} ssh2\n"
                        )
                    f_auth.flush()

            # 6. Trigger Critical System Events - OOM/Segfault/EXT4 (every 40 seconds)
            if counter % 40 == 0:
                print("==> Injecting critical kernel panic/segfault/OOM error signatures...")
                with open(KERN_PATH, "a", encoding="utf-8") as f_kern:
                    template = random.choice(CRITICAL_TEMPLATES)
                    msg = template.format(
                        time_offset=f"{random.randint(100, 999999)}.{random.randint(1000, 9999)}",
                        pid=random.randint(100, 32000),
                        proc_name=random.choice(["java", "python3", "mysqld", "node"]),
                        score=random.randint(800, 999),
                        mem_addr=hex(random.randint(0, 100000000000)),
                        ip_addr=hex(random.randint(0, 100000000000)),
                        sp_addr=hex(random.randint(0, 100000000000)),
                        inode=random.randint(10000, 999999),
                        exit_code=random.randint(1, 255)
                    )
                    f_kern.write(f"{get_syslog_timestamp()} {hostname} {msg}\n")
                    f_kern.flush()

            # Sleep
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\nLog generator stopped.")

if __name__ == "__main__":
    main()
