import mock_gpu

def main():
    calls = []
    def add(api, status):
        if status is None:
            status = 0
        calls.append({"api": api, "status": int(status)})

    mock_gpu.reset()
    add("reset", 0)

    st, hAdapter = mock_gpu.open_adapter("probe")
    add("open_adapter", st)
    if st != 0:
        return False, calls, ["open_adapter failed"]

    st, hDevice1 = mock_gpu.create_device(hAdapter)
    add("create_device", st)
    if st != 0:
        return False, calls, ["create_device(1) failed"]

    st, hContext1 = mock_gpu.create_context(hDevice1, 0)
    add("create_context", st)
    if st != 0:
        return False, calls, ["create_context(1) failed"]

    st, hDevice2 = mock_gpu.create_device(hAdapter)
    add("create_device", st)
    if st != 0:
        return False, calls, ["create_device(2) failed"]

    st, hContext2 = mock_gpu.create_context(hDevice2, 0)
    add("create_context", st)
    if st != 0:
        return False, calls, ["create_context(2) failed"]

    # Find working escape type/payload combinations on a valid context.
    working_combos = []
    for type_ in range(8):
        for payload in [b"", (0).to_bytes(4, 'little'), (0).to_bytes(8, 'little'),
                        (4).to_bytes(4, 'little') + b"AAAA",
                        (4).to_bytes(8, 'little') + b"AAAA"]:
            st = mock_gpu.escape(hAdapter, hDevice1, hContext1, type_, 0, payload)
            add("escape", st)
            if st == 0:
                working_combos.append((type_, payload))

    bypass_context = False
    notes = []

    # Probe context ownership bypass: use a context from the other device.
    for type_, payload in working_combos:
        for flags in [0, 0x1, 0x2, 0x3]:
            st = mock_gpu.escape(hAdapter, hDevice1, hContext2, type_, flags, payload)
            add("escape", st)
            if st == 0:
                bypass_context = True
                notes.append(f"cross-context dev1/ctx2 type={type_} flags={flags} succeeded")
            st = mock_gpu.escape(hAdapter, hDevice2, hContext1, type_, flags, payload)
            add("escape", st)
            if st == 0:
                bypass_context = True
                notes.append(f"cross-context dev2/ctx1 type={type_} flags={flags} succeeded")

    valid_types = list(set(t for t, _ in working_combos))
    length_boundary = False

    # Probe private data declared length boundary: vary declared length vs actual data.
    for type_ in valid_types:
        for flags in [0, 0x2]:
            for length_bytes in [4, 8]:
                for actual_len in [0, 4, 8, 16, 32, 64, 128, 256, 512, 1016, 1020]:
                    for delta in [-1, 0, 1, 2]:
                        declared_len = actual_len + delta
                        if declared_len < 0:
                            continue
                        if declared_len > (1 << (8 * length_bytes)) - 1:
                            continue
                        payload = declared_len.to_bytes(length_bytes, 'little') + b"A" * actual_len
                        if len(payload) > 1024:
                            continue
                        st = mock_gpu.escape(hAdapter, hDevice1, hContext1, type_, flags, payload)
                        add("escape", st)
                        if st == 0 and declared_len > actual_len:
                            length_boundary = True
                            notes.append(f"len{length_bytes} boundary: type={type_} flags={flags} actual={actual_len} declared={declared_len} accepted")
                        if st != 0 and declared_len == actual_len and actual_len > 0:
                            notes.append(f"len{length_bytes} equal rejected: type={type_} flags={flags} actual={actual_len}")

    # Cleanup and verify destroyed context is rejected.
    st = mock_gpu.destroy_context(hContext1)
    add("destroy_context", st)
    st = mock_gpu.escape(hAdapter, hDevice1, hContext1, 0, 0, b"")
    add("escape", st)
    st = mock_gpu.destroy_context(hContext2)
    add("destroy_context", st)
    st = mock_gpu.destroy_device(hDevice1)
    add("destroy_device", st)
    st = mock_gpu.destroy_device(hDevice2)
    add("destroy_device", st)
    st = mock_gpu.close_adapter(hAdapter)
    add("close_adapter", st)

    reached = bypass_context or length_boundary
    if not notes:
        notes.append("No vulnerability triggered")
    notes = list(dict.fromkeys(notes))
    if len(notes) > 10:
        notes = notes[:10] + ["..."]
    return reached, calls, notes

reached, calls, notes = main()
calls_json = "[" + ", ".join('{"api": "%s", "status": %d}' % (c["api"], c["status"]) for c in calls) + "]"
notes_str = "; ".join(notes).replace('"', "'")
result = 'CPG_RESULT {"reached": %s, "calls": %s, "notes": "%s"}' % (str(reached).lower(), calls_json, notes_str)
print(result)