# Nova Total Security — PC Version (All-in-One)
# Created by ChatGPT + User

import os
import hashlib
import psutil
import socket
import threading
import time
import re
from collections import defaultdict
from datetime import datetime

# === 1. Хэши известных вирусов ===
KNOWN_VIRUSES = {
    '5d41402abc4b2a76b9719d911017c592',  # Пример
}

# === 2. Подозрительные расширения ===
SUSPICIOUS_EXTENSIONS = {'.exe', '.bat', '.scr', '.pif', '.vbs', '.js', '.cmd', '.dll', '.ps1'}

# === 3. Системные директории для исключения ===
SKIP_DIRS = {
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "C:\\$Recycle.Bin", "C:\\System Volume Information"
}

# === 4. Подозрительные имена процессов и параметры запуска ===
SUSPICIOUS_PROCESS_NAMES = {
    "rat.exe", "keylogger.exe", "miner.exe", "backdoor.exe",
    "darkcomet.exe", "njrat.exe", "blackshades.exe"
}
SUSPICIOUS_CMD_PARTS = {
    "--hidden", "--silent", "--inject", "temp\\", "appdata\\roaming\\", "powershell", "base64"
}

# === 5. Мониторинг системной активности ===
def monitor_system_activity(duration=30):
    print("\n🧠 Поведенческий анализ процессов ({} сек)...".format(duration))
    start_time = time.time()
    cpu_alerts, proc_alerts = [], []
    while time.time() - start_time < duration:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                cpu = proc.cpu_percent(interval=0.1)
                if cpu > 50:
                    cpu_alerts.append((proc.pid, proc.info['name'], cpu))
            except: continue
    if cpu_alerts:
        print("⚠️ Обнаружена высокая загрузка CPU:")
        for pid, name, cpu in cpu_alerts:
            print(f"[CPU] PID {pid} | {name} | CPU: {cpu}%")
    else:
        print("✅ Нет аномальной нагрузки на систему.")

# === 6. WatchDog на файлы ===
def monitor_files(paths, duration=30):
    print(f"\n📁 Контроль изменений файлов ({duration} сек)...")
    snapshot = {}
    for path in paths:
        for root, _, files in os.walk(path):
            for f in files:
                full = os.path.join(root, f)
                try:
                    snapshot[full] = os.path.getmtime(full)
                except: continue
    time.sleep(duration)
    for path in paths:
        for root, _, files in os.walk(path):
            for f in files:
                full = os.path.join(root, f)
                try:
                    mtime = os.path.getmtime(full)
                    if full not in snapshot:
                        print(f"[⚠️ Добавлен файл] {full}")
                    elif snapshot[full] != mtime:
                        print(f"[⚠️ Изменён файл] {full}")
                except: continue

# === 7. Анализ подозрительных скриптов ===
SCRIPT_PATTERNS = [
    r"powershell", r"base64", r"Invoke-", r"New-Object", r"cmd\.exe", r"wget", r"bitsadmin"
]
def scan_scripts(start_path):
    print("\n📜 Анализ подозрительных скриптов...")
    for root, _, files in os.walk(start_path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in {'.bat', '.vbs', '.ps1', '.cmd', '.js'}:
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for pattern in SCRIPT_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                print(f"[❗] Подозрительный скрипт: {os.path.join(root, file)} [Обнаружено: {pattern}]")
                                break
                except: continue

# === 8. Сканирование папок (файлы) ===
def md5_hash_file(filepath):
    try:
        with open(filepath, "rb") as f:
            file_hash = hashlib.md5()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except: return None

def scan_directory(start_path):
    report_danger = []
    report_suspicious = []
    for root, _, files in os.walk(start_path):
        root_lower = root.lower()
        if any(root_lower.startswith(skip.lower()) for skip in SKIP_DIRS):
            continue
        for filename in files:
            filepath = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()
            file_hash = md5_hash_file(filepath)
            if file_hash and file_hash in KNOWN_VIRUSES:
                report_danger.append(filepath)
                continue
            if ext in SUSPICIOUS_EXTENSIONS:
                report_suspicious.append(filepath)
    return report_danger, report_suspicious

# === 9. Сканирование процессов ===
def scan_processes():
    found_suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info['name'] or ""
            exe = proc.info['exe'] or ""
            cmd = " ".join(proc.info['cmdline'] or [])
            if name.lower() in SUSPICIOUS_PROCESS_NAMES:
                found_suspicious.append((proc.pid, name, exe, "Подозрительное имя"))
            for pattern in SUSPICIOUS_CMD_PARTS:
                if pattern in cmd.lower() or pattern in exe.lower():
                    found_suspicious.append((proc.pid, name, exe, f"Обнаружен фрагмент: {pattern}"))
                    break
        except: continue
    return found_suspicious

# === 10. Сниффер сети (упрощённый) ===
def monitor_connections(threshold=100):
    print("\n🌐 Сетевой мониторинг...")
    conn_count = defaultdict(int)
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ip = conn.raddr.ip
            conn_count[ip] += 1
    for ip, count in conn_count.items():
        if count > threshold:
            print(f"[🔥 Подозрительно] {ip} => {count} соединений (возможный DDoS)")
    if not conn_count:
        print("Нет активных подключений.")

# === ЗАПУСК ===
if __name__ == "__main__":
    print("🛡 Nova (ПК-версия)")
    start = time.time()
    
    print("\n🔍 Сканирование диска C:\\ ...")
    dangers, suspicious = scan_directory("C:\\")
    for f in dangers:
        print("[ОПАСНО] ", f)
    for f in suspicious:
        print("[ПОДОЗРИТЕЛЬНО] ", f)
    
    print("\n🔍 Сканирование процессов ...")
    processes = scan_processes()
    for pid, name, path, reason in processes:
        print(f"[ПРОЦЕСС] PID {pid} | {name} | {path} => {reason}")

    monitor_system_activity(10)
    monitor_connections()
    monitor_files(["C:\\Users"], duration=10)
    scan_scripts("C:\\Users")
    
    print("\n✅ Сканирование завершено за %.2f сек" % (time.time() - start))
    input("\n✅ Нажми Enter для выхода...")
