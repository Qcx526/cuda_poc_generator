import ctypes, sys
dll = ctypes.WinDLL("nvapi64.dll")
print("loaded", flush=True)
sys.stdin.read(1)
