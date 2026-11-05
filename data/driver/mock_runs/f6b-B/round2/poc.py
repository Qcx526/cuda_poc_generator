import mock_gpu

calls = []
def record(api, status):
    calls.append({"api": api, "status": int(status)})
    return status

def do_open(hint):
    st, h = mock_gpu.open_adapter(hint)
    record("open_adapter", st)
    return st, h

def do_create_device(hA):
    st, h = mock_gpu.create_device(hA)
    record("create_device", st)
    return st, h

def do_create_context(hD, node=0):
    st, h = mock_gpu.create_context(hD, node)
    record("create_context", st)
    return st, h

def do_escape(hA, hD, hC, type_, flags, payload):
    st = mock_gpu.escape(hA, hD, hC, type_, flags, payload)
    record("escape", st)
    return st

def do_destroy_context(hC):
    st = mock_gpu.destroy_context(hC)
    record("destroy_context", st)
    return st

def do_destroy_device(hD):
    st = mock_gpu.destroy_device(hD)
    record("destroy_device", st)
    return st

def do_close_adapter(hA):
    st = mock_gpu.close_adapter(hA)
    record("close_adapter", st)
    return st

def do_reset():
    st = mock_gpu.reset()
    record("reset", st)
    return st

def u32(n):
    return n.to_bytes(4, 'little')

def overwrite(base, off, value):
    b = bytearray(base)
    if off + 4 <= len(b):
        b[off:off+4] = u32(value)
    return bytes(b)

do_reset()
st1, hA1 = do_open("A")
st2, hD1 = do_create_device(hA1) if st1 == 0 else (1, 0)
st3, hC1 = do_create_context(hD1) if st2 == 0 else (1, 0)

st4, hA2 = do_open("B")
st5, hD2 = do_create_device(hA2) if st4 == 0 else (1, 0)
st6, hC2 = do_create_context(hD2) if st5 == 0 else (1, 0)

setup_ok = (st1 == 0 and st2 == 0 and st3 == 0 and st4 == 0 and st5 == 0 and st6 == 0)

baselines = []
ownership_vuln = False
length_vuln = False
notes = ""

if setup_ok:
    payloads = [
        ("empty", b""),
        ("u32_0", u32(0)),
        ("u32_4_data4", u32(4) + b"ABCD"),
        ("u32_12_data12", u32(12) + b"0123456789AB"),
        ("u32_16_data16", u32(16) + b"Y" * 16),
        ("zeros16", b"\x00" * 16),
        ("zeros24", b"\x00" * 24),
    ]
    for type_ in range(8):
        for flags in (1, 0, 3, 2):
            for pname, payload in payloads:
                st = do_escape(hA1, hD1, hC1, type_, flags, payload)
                if st == 0:
                    baselines.append((type_, flags, pname, payload))
                    break

    if not baselines:
        notes = "no baseline success"
    else:
        for (type_, flags, pname, payload) in baselines:
            if ownership_vuln and length_vuln:
                break

            if not ownership_vuln:
                st_mc = do_escape(hA1, hD1, hC2, type_, flags, payload)
                st_md = do_escape(hA1, hD2, hC1, type_, flags, payload)
                st_ma = do_escape(hA2, hD1, hC1, type_, flags, payload)
                if st_mc == 0 or st_md == 0 or st_ma == 0:
                    ownership_vuln = True

                for f in (0, 1, 2, 3):
                    st_m = do_escape(hA1, hD1, hC2, type_, f, payload)
                    if st_m == 0:
                        ownership_vuln = True
                        break

            if not length_vuln:
                L = len(payload)
                if L >= 4:
                    for off in (0, 4, 8, 12):
                        if off + 4 > L:
                            continue
                        for header_size in (4, 16):
                            if L < header_size:
                                continue
                            boundary = L - header_size + 1
                            invalid = L - header_size + 100
                            p_b = overwrite(payload, off, boundary)
                            p_i = overwrite(payload, off, invalid)
                            st_b = do_escape(hA1, hD1, hC1, type_, flags, p_b)
                            st_i = do_escape(hA1, hD1, hC1, type_, flags, p_i)
                            if st_b == 0 and st_i != 0:
                                length_vuln = True
                                break
                        if length_vuln:
                            break

                    if not length_vuln:
                        p_max = u32(1024) + b"X" * 1020
                        p_inv = u32(1030) + b"X" * 1020
                        st_max = do_escape(hA1, hD1, hC1, type_, flags, p_max)
                        st_inv = do_escape(hA1, hD1, hC1, type_, flags, p_inv)
                        if st_max == 0 and st_inv != 0:
                            length_vuln = True

        notes_parts = []
        if ownership_vuln:
            notes_parts.append("context ownership bypass observed")
        if length_vuln:
            notes_parts.append("declared length boundary error observed")
        if not notes_parts:
            notes_parts.append("no vulnerability triggered")
        notes = "; ".join(notes_parts) + f" (baselines={len(baselines)})"

if st6 == 0:
    do_destroy_context(hC2)
if st3 == 0:
    do_destroy_context(hC1)
if st5 == 0:
    do_destroy_device(hD2)
if st2 == 0:
    do_destroy_device(hD1)
if st4 == 0:
    do_close_adapter(hA2)
if st1 == 0:
    do_close_adapter(hA1)

reached = bool(ownership_vuln or length_vuln)
calls_json = "[" + ",".join([f'{{"api": "{c["api"]}", "status": {c["status"]}}}' for c in calls]) + "]"
notes_escaped = notes.replace('"', '\\"')
result = f'{{"reached": {str(reached).lower()}, "calls": {calls_json}, "notes": "{notes_escaped}"}}'
print("CPG_RESULT " + result)