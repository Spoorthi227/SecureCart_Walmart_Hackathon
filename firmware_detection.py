
import os
import subprocess
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

# -----------------------------------------
# CONFIGURATION: Update these as needed
# -----------------------------------------

# Known-good firmware hash (from golden SPI dump)
GOLDEN_HASH = "your_known_good_hash_here"

# Path to save firmware dump
FIRMWARE_DUMP_PATH = "/tmp/firmware_dump.bin"

# Known-safe GUIDs (you can expand this list)
KNOWN_GOOD_GUIDS = {
    "7C79AC8C-5FA3-4E73-8D46-97859C5D2C0E",
    "F0A30A0F-2D28-4212-81B9-46A3C3ABFE2D",
    "A1B2C3D4-E5F6-7890-1234-56789ABCDEF0"
}

# -----------------------------------------
# FUNCTION DEFINITIONS
# -----------------------------------------

def run_spi_dump_and_hash():
    log = ["[SPI FLASH DUMP + HASH CHECK]"]
    try:
        subprocess.run(f"sudo chipsec_util spi dump {FIRMWARE_DUMP_PATH}", shell=True, check=True)
        log.append(f"✔️ Firmware dumped to {FIRMWARE_DUMP_PATH}")
    except subprocess.CalledProcessError as e:
        log.append(f"❌ SPI dump failed: {e}")
        return log

    try:
        with open(FIRMWARE_DUMP_PATH, "rb") as f:
            sha256 = hashlib.sha256()
            while chunk := f.read(4096):
                sha256.update(chunk)
        dumped_hash = sha256.hexdigest()
        log.append(f"🔍 Dumped SHA256: {dumped_hash}")
        if dumped_hash == GOLDEN_HASH:
            log.append("✔️ Firmware hash matches the golden image.")
        else:
            log.append("❗ Firmware hash mismatch! Possible tampering.")
    except Exception as e:
        log.append(f"❌ Hashing failed: {e}")
    return log

def run_chipsec_malware_scan():
    log = ["\n[CHIPSEC MALWARE SCAN]"]
    try:
        result = subprocess.check_output("sudo chipsec_main -m uefi.malware", shell=True, stderr=subprocess.STDOUT)
        decoded = result.decode()
        log.append(decoded)
    except subprocess.CalledProcessError as e:
        log.append(f"❌ CHIPSEC scan failed:\n{e.output.decode()}")
    return log

def extract_guids_from_firmware():
    log = ["\n[UEFI MODULE GUID SCAN]"]
    try:
        result = subprocess.check_output("strings " + FIRMWARE_DUMP_PATH, shell=True).decode()
        found_guids = set()
        import re
        matches = re.findall(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", result, re.I)
        found_guids = set(matches)
        for guid in found_guids:
            if guid.upper() in KNOWN_GOOD_GUIDS:
                log.append(f"✔️ {guid} is known good.")
            else:
                log.append(f"⚠️ {guid} is unknown or suspicious.")
    except Exception as e:
        log.append(f"❌ GUID extraction failed: {e}")
    return log

def run_full_scan():
    log = []
    log += run_spi_dump_and_hash()
    log += run_chipsec_malware_scan()
    log += extract_guids_from_firmware()
    log.append("\n[SCAN COMPLETE]")
    return "\n".join(log)

# -----------------------------------------
# GUI SETUP
# -----------------------------------------

def run_scan():
    results = run_full_scan()
    text_box.delete("1.0", tk.END)
    text_box.insert(tk.END, results)

def export_log():
    data = text_box.get("1.0", tk.END)
    path = filedialog.asksaveasfilename(defaultextension=".txt")
    if path:
        with open(path, "w") as f:
            f.write(data)
        messagebox.showinfo("Log Saved", f"Log exported to:\n{path}")

app = tk.Tk()
app.title("Firmware Integrity Scanner")
app.geometry("800x600")

header = tk.Label(app, text="Firmware Integrity Scanner", font=("Arial", 18, "bold"))
header.pack(pady=10)

scan_btn = tk.Button(app, text="🔍 Run Full Scan", command=run_scan)
scan_btn.pack(pady=5)

export_btn = tk.Button(app, text="📁 Export Log", command=export_log)
export_btn.pack(pady=5)

text_box = tk.Text(app, height=30, width=100)
text_box.pack(padx=10, pady=10)

app.mainloop()
