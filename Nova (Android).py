# Nova Total Security — Android Version (All-in-One)
# Created by ChatGPT + User

import os
import hashlib
import psutil
import time
import re

# === 1. Хэши известных вирусов ===
KNOWN_VIRUSES = {
    '5d41402abc4b2a76b9719d911017c592',  # Пример
}

# === 2. Подозрительные расширения ===
SUSPICIOUS_EXT = {'.apk', '.exe', '.sh', '.py', '.dex', '.jar', '.bat'}

# === 3. Подозрительные папки для сканирования ===
SCAN_PATHS = [
    "/sdcard/Download",
    "/sdcard/DCIM",
    "/sdcard/Music",
    "/sdcard/Movies",
    "/sdcard/Documents",
    "/sdcard/Telegram",
    "/storage/emulated/0/Download",
]

# === 4. Подозрительные имена процессов и ключи ===
SUSPICIOUS_PROCESS_NAMES = {
    "rat", "keylogger", "miner", "backdoor",
    "com.example.hack", "suspicious", "payload"
}
SUSPICIOUS_CMD_PARTS = {
    "su", "root", "payload", "inject", "hidden", "libnative.so"
}

# === 5. Подозрительные скрипты (shell, python) ===
SCRIPT_PATTERNS = [
    r"base64", r"sh ", r"su", r"wget", r"curl", r"chmod", r"kill", r"am start", r"pm install"
]
def scan_scripts(start_path):
    print("\n📜 Анализ скриптов на Android...")
    for root, _, files in os.walk(start_path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in {'.sh', '.py', '.bat'}:
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for pattern in SCRIPT_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                print(f"[❗] Подозрительный скрипт: {os.path.join(root, file)} [Обнаружено: {pattern}]")
                                break
                except: continue

# === 6. Получение md5 хэша файла ===
def md5_hash_file(filepath):
    try:
        with open(filepath, "rb") as f:
            hash_md5 = hashlib.md5()
            while chunk := f.read(8192):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return None

# === 7. Сканирование одной папки ===
def scan_folder(folder):
    dangers = []
    suspicious = []
    for root, _, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            file_hash = md5_hash_file(path)
            if file_hash in KNOWN_VIRUSES:
                dangers.append(path)
            elif ext in SUSPICIOUS_EXT:
                suspicious.append(path)
    return dangers, suspicious

# === 8. Скан процессов ===
def scan_processes():
    found = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = (proc.info['name'] or "").lower()
            cmd = " ".join(proc.info['cmdline'] or []).lower()
            if any(susp in name for susp in SUSPICIOUS_PROCESS_NAMES):
                found.append((proc.pid, name, "Подозрительное имя"))
            for pattern in SUSPICIOUS_CMD_PARTS:
                if pattern in cmd:
                    found.append((proc.pid, name, f"Найдено: {pattern}"))
                    break
        except: continue
    return found

# === ЗАПУСК ===
if __name__ == "__main__":
    print("🛡️ Nova Total Security (Android-версия)")
    all_danger = []
    all_suspect = []

    print("\n🚀 Сканирование хранилища Android...")
    for path in SCAN_PATHS:
        if os.path.exists(path):
            print(f"📁 Проверка папки: {path}")
            danger, suspect = scan_folder(path)
            all_danger += danger
            all_suspect += suspect
        else:
            print(f"⛔ Папка не найдена: {path}")

    print("\n🛑 Найдено опасных файлов:", len(all_danger))
    for f in all_danger:
        print("[ОПАСНО] ", f)

    print("\n⚠️ Подозрительных файлов:", len(all_suspect))
    for f in all_suspect:
        print("[ПОДОЗРИТЕЛЬНО] ", f)

    print("\n🔍 Сканирование скриптов...")
    for path in SCAN_PATHS:
        if os.path.exists(path):
            scan_scripts(path)

    print("\n🔍 Сканирование процессов...")
    processes = scan_processes()
    print("⚠️ Подозрительные процессы:", len(processes))
    for pid, name, reason in processes:
        print(f"[ПРОЦЕСС] PID {pid} | {name} => {reason}")

    print("\n✅ Проверка завершена.")
