"""
CS 1.6 Memory Scanner (Fixed & Improved)
Finds dynamic player coordinates for Build 4554 / Protocol 48
"""

import ctypes
from ctypes import wintypes
import struct
import time

# --- CONSTANTS & STRUCTURES ---

PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

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

# --- HELPER FUNCTIONS ---

def get_module_info(pid, module_name):
    """Finds the base address and size of a specific DLL (e.g., hw.dll)"""
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    
    base_addr = None
    module_size = None

    if ctypes.windll.kernel32.Module32First(snapshot, ctypes.byref(entry)):
        while True:
            name = entry.szModule.decode('utf-8', errors='ignore').lower()
            if name == module_name.lower():
                base_addr = ctypes.addressof(entry.modBaseAddr.contents)
                module_size = entry.modBaseSize
                break
            if not ctypes.windll.kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                break
                
    ctypes.windll.kernel32.CloseHandle(snapshot)
    return base_addr, module_size

def find_process(process_name="hl.exe"):
    """Finds the Process ID (PID) of the game"""
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    process_entry = PROCESSENTRY32()
    process_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    
    if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(process_entry)):
        while True:
            if process_entry.szExeFile.decode('utf-8', errors='ignore') == process_name:
                pid = process_entry.th32ProcessID
                ctypes.windll.kernel32.CloseHandle(snapshot)
                return pid
            if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(process_entry)):
                break
    
    ctypes.windll.kernel32.CloseHandle(snapshot)
    return None

def read_memory(handle, address, size):
    """Reads raw bytes from memory"""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    
    success = ctypes.windll.kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read)
    )
    
    if success and bytes_read.value == size:
        return buffer.raw
    return None

def read_float(handle, address):
    """Reads a single float value from memory"""
    data = read_memory(handle, address, 4)
    if data:
        try:
            return struct.unpack('f', data)[0]
        except:
            return None
    return None

def scan_for_coordinates(handle, start_addr, size, search_range=(-8000, 8000)):
    """
    Scans a memory range for 3 consecutive floats (X, Y, Z)
    """
    end_addr = start_addr + size
    print(f"  > Scanning range: 0x{start_addr:08X} - 0x{end_addr:08X} ({size/1024/1024:.1f} MB)")
    
    candidates = []
    chunk_size = 4096  # 4KB chunks
    current = start_addr
    
    while current < end_addr:
        # Prevent reading past the end
        read_size = min(chunk_size, end_addr - current)
        data = read_memory(handle, current, read_size)
        
        if data:
            # Step by 4 bytes (size of float)
            for offset in range(0, len(data) - 12, 4):
                try:
                    x = struct.unpack('f', data[offset:offset+4])[0]
                    y = struct.unpack('f', data[offset+4:offset+8])[0]
                    z = struct.unpack('f', data[offset+8:offset+12])[0]
                    
                    # Basic validity check for CS coordinates
                    if (search_range[0] <= x <= search_range[1] and 
                        search_range[0] <= y <= search_range[1] and 
                        -2000 <= z <= 2000): # Z height is usually smaller range
                        
                        # Filter out exact zeros (usually null memory)
                        if not (x == 0 and y == 0 and z == 0):
                            # Filter out when all 3 are equal (rarely coords)
                            if not (x == y == z):
                                # Filter out huge integers (often not coords)
                                if not (x % 1 == 0 and y % 1 == 0 and x > 100):
                                    addr = current + offset
                                    candidates.append({
                                        'address': addr,
                                        'x': x, 'y': y, 'z': z
                                    })
                except:
                    pass
        
        current += chunk_size
        
    return candidates

# --- MAIN EXECUTION ---

def main():
    print("=" * 70)
    print("CS 1.6 MEMORY SCANNER - Position Finder")
    print("=" * 70)
    print("\nIMPORTANT INSTRUCTIONS:")
    print("1. Make sure you are ALIVE in-game (not spectating)")
    print("2. Stand still in one spot")
    print("3. Press Enter to start the scan")
    print("=" * 70)
    
    pid = find_process("hl.exe")
    if not pid:
        print("\n✗ ERROR: CS 1.6 (hl.exe) not found!")
        input("Press Enter to exit...")
        return
    
    print(f"\n✓ Found CS 1.6 (PID: {pid})")
    
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        print("✗ ERROR: Could not open process! Run as Administrator.")
        input("Press Enter to exit...")
        return
    
    # 1. Locate DLLs Dynamically
    print("\n[+] Dynamically locating DLLs...")
    
    hw_base, hw_size = get_module_info(pid, "hw.dll")
    if hw_base:
        print(f"✓ Found hw.dll at: 0x{hw_base:08X} (Size: {hw_size})")
    else:
        print("✗ Could not find hw.dll - Scanning will likely fail.")
        hw_base = 0x04930000; hw_size = 0x01230000

    client_base, client_size = get_module_info(pid, "client.dll")
    if client_base:
        print(f"✓ Found client.dll at: 0x{client_base:08X} (Size: {client_size})")
    else:
        print("✗ Could not find client.dll.")
        client_base = 0x0E990000; client_size = 0x00159000

    input("\nPress Enter when you are standing still to start scanning...")

    # 2. Perform the Scan (This was missing in your error)
    print("\n" + "=" * 70)
    print("STEP 1: Initial Scan")
    print("=" * 70)
    
    candidates1 = []
    
    if hw_base:
        print("Scanning hw.dll memory...")
        results = scan_for_coordinates(handle, hw_base, hw_size)
        candidates1.extend(results)
        print(f"Found {len(results)} candidates in hw.dll")

    if client_base:
        print("Scanning client.dll memory...")
        results = scan_for_coordinates(handle, client_base, client_size)
        candidates1.extend(results)
        print(f"Found {len(results)} candidates in client.dll")

    if len(candidates1) == 0:
        print("\n✗ No candidates found. Ensure you are in a map and alive.")
        ctypes.windll.kernel32.CloseHandle(handle)
        input("Press Enter to exit...")
        return
    
    print(f"\n✓ Total Candidates Found: {len(candidates1)}")
    
    # 3. Verification Step
    print("\n" + "=" * 70)
    print("STEP 2: Verification Scan")
    print("=" * 70)
    print("\n>>> MOVE your player now! Walk a few steps and stop. <<<")
    input("Press Enter after you have moved...")
    
    print("\nRe-scanning candidates to find which ones changed...")
    
    confirmed_addresses = []
    
    for c in candidates1:
        x = read_float(handle, c['address'])
        y = read_float(handle, c['address'] + 4)
        z = read_float(handle, c['address'] + 8)
        
        if x is not None:
            # Check if values changed significantly (movement)
            dx = abs(x - c['x'])
            dy = abs(y - c['y'])
            
            # If position changed by more than 1 unit, it's likely the player
            if dx > 1.0 or dy > 1.0:
                confirmed_addresses.append({
                    'address': c['address'],
                    'old': (c['x'], c['y'], c['z']),
                    'new': (x, y, z)
                })
    
    if not confirmed_addresses:
        print("\n✗ No coordinates changed. Did you move far enough?")
        ctypes.windll.kernel32.CloseHandle(handle)
        input("Press Enter to exit...")
        return

    # 4. Final Results
    print("\n" + "=" * 70)
    print("RESULTS - FOUND PLAYER ADDRESSES")
    print("=" * 70)
    
    # Sort by address to group them
    confirmed_addresses.sort(key=lambda x: x['address'])
    
    # Pick the best one (usually the one in hw.dll is what we want for reading)
    best_candidate = confirmed_addresses[0] 
    
    for res in confirmed_addresses[:5]: # Show top 5
        addr = res['address']
        mod_name = "Unknown"
        offset = 0
        
        if hw_base and hw_base <= addr < hw_base + hw_size:
            mod_name = "hw.dll"
            offset = addr - hw_base
        elif client_base and client_base <= addr < client_base + client_size:
            mod_name = "client.dll"
            offset = addr - client_base
            
        print(f"\nAddress: 0x{addr:08X} ({mod_name} + 0x{offset:08X})")
        print(f"  Old: {res['old']}")
        print(f"  New: {res['new']}")
        
        # Prefer hw.dll results
        if mod_name == "hw.dll":
            best_candidate = res

    # 5. Live Monitor
    print("\n" + "=" * 70)
    print(f"LIVE MONITORING: 0x{best_candidate['address']:08X}")
    print("=" * 70)
    print("Move around. If these update correctly, this is your address.\n")
    
    try:
        for _ in range(50): # Monitor for 10 seconds
            x = read_float(handle, best_candidate['address'])
            y = read_float(handle, best_candidate['address'] + 4)
            z = read_float(handle, best_candidate['address'] + 8)
            print(f"Pos: {x:8.2f}, {y:8.2f}, {z:8.2f}", end='\r')
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
        
    # 6. Final Instructions for User
    final_addr = best_candidate['address']
    final_offset = 0
    base_addr = 0
    base_name = "hw.dll" # default
    
    if hw_base and hw_base <= final_addr < hw_base + hw_size:
        final_offset = final_addr - hw_base
        base_addr = hw_base
        base_name = "hw.dll"
    elif client_base and client_base <= final_addr < client_base + client_size:
        final_offset = final_addr - client_base
        base_addr = client_base
        base_name = "client.dll"
        
    print("\n\n" + "=" * 70)
    print("COPY THIS INTO YOUR MAIN SCRIPT:")
    print("=" * 70)
    print(f"self.{base_name.replace('.', '_')}_base = 0x{base_addr:08X}  # (Dynamic, auto-detected)")
    print(f"self.OFFSET_ORIGIN = 0x{final_offset:08X}")
    print("=" * 70)

    ctypes.windll.kernel32.CloseHandle(handle)
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()