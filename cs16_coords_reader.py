import ctypes
from ctypes import wintypes
import struct
import time
import os

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260)
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260)
    ]

PLAYER_OFFSET = 0x001AF1B8

def get_module_base(pid, module_name):
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x18, pid)
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    base = None
    if ctypes.windll.kernel32.Module32First(snapshot, ctypes.byref(entry)):
        while True:
            name = entry.szModule.decode('utf-8', errors='ignore').lower()
            if name == module_name.lower():
                base = ctypes.addressof(entry.modBaseAddr.contents)
                break
            if not ctypes.windll.kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                break
    ctypes.windll.kernel32.CloseHandle(snapshot)
    return base

def find_process(process_name):
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x2, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None
    if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.decode('utf-8', errors='ignore').lower() == process_name.lower():
                pid = entry.th32ProcessID
                break
            if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break
    ctypes.windll.kernel32.CloseHandle(snapshot)
    return pid

def read_float3(handle, address):
    buffer = ctypes.create_string_buffer(12)
    if ctypes.windll.kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, 12, 0):
        return struct.unpack('fff', buffer.raw)
    return None

def scan_for_players(handle, my_address, my_x, my_y):
    print("\nScanning for other players in server...")
    print("-------------------------------------")
    
    found = []
    
    # scan 0x50000 bytes ahead of your address in steps of 4
    for offset in range(4, 0x50000, 4):
        addr = my_address + offset
        result = read_float3(handle, addr)
        
        if result:
            x, y, z = result
            # valid coordinate range for CS 1.6 maps
            if (-4096 < x < 4096 and -4096 < y < 4096 and -4096 < z < 4096):
                # must be far enough from zero to not be garbage
                if abs(x) > 50 and abs(y) > 50:
                    # must be different from our own position
                    if abs(x - my_x) > 20 or abs(y - my_y) > 20:
                        found.append((offset, addr, x, y, z))

    if found:
        print(f"Found {len(found)} potential player coordinates:\n")
        for offset, addr, x, y, z in found:
            print(f"Offset: 0x{offset:05X}  Address: 0x{addr:08X}  X={x:8.1f}  Y={y:8.1f}  Z={z:8.1f}")
    else:
        print("No players found. Make sure bots are in the server and moving.")
    
    return found

def main():
    os.system('cls')
    print("CS 1.6 Player Scanner")
    print("-------------------------------------")

    pid = find_process("hl.exe")
    if not pid:
        print("Waiting for CS 1.6 to start...")
        while not pid:
            pid = find_process("hl.exe")
            time.sleep(1)

    print(f"Attached to hl.exe (PID: {pid})")

    hw_base = get_module_base(pid, "hw.dll")
    if not hw_base:
        print("Could not find hw.dll!")
        return

    final_address = hw_base + PLAYER_OFFSET
    print(f"hw.dll Base:       0x{hw_base:08X}")
    print(f"Your Address:      0x{final_address:08X}")

    handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)

    # first read your own coordinates
    result = read_float3(handle, final_address)
    if not result:
        print("Failed to read your coordinates!")
        return
    
    my_x, my_y, my_z = result
    print(f"Your Position:     X={my_x:.1f}  Y={my_y:.1f}  Z={my_z:.1f}")

    # scan for bots once
    found = scan_for_players(handle, final_address, my_x, my_y)

    if not found:
        ctypes.windll.kernel32.CloseHandle(handle)
        return

    # ask user to pick which offset looks right
    print("\nEnter the offset of the bot you want to track (e.g. 4CC): ")
    user_offset = int(input(), 16)
    bot_address = final_address + user_offset

    print(f"\nTracking bot at 0x{bot_address:08X}")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            os.system('cls')
            my = read_float3(handle, final_address)
            bot = read_float3(handle, bot_address)

            if my:
                print(f"You:  X={my[0]:8.1f}  Y={my[1]:8.1f}  Z={my[2]:8.1f}  Address: 0x{final_address:08X}")
            if bot:
                print(f"Bot:  X={bot[0]:8.1f}  Y={bot[1]:8.1f}  Z={bot[2]:8.1f}  Address: 0x{bot_address:08X}")

            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\nStopped.")
        ctypes.windll.kernel32.CloseHandle(handle)

if __name__ == "__main__":
    main()