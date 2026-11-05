import mock_gpu

def make_payload(L, offset, length_size, declared):
    payload = bytearray(L)
    for i in range(L):
        payload[i] = 0xAA
    if offset + length_size <= L:
        b = declared.to_bytes(length_size, 'little')
        payload[offset:offset+length_size] = b
    return bytes(payload)

def main():
    calls = []
    def rec(api, status):
        calls.append({"api": api, "status": status})
        return status

    mock_gpu.reset()
    st, adapter = mock_gpu.open_adapter("probe")
    rec("open_adapter", st)
    if st != 0:
        print_result(False, calls, "open_adapter failed")
        return

    st, dev1 = mock_gpu.create_device(adapter)
    rec("create_device", st)
    if st != 0:
        st2 = mock_gpu.close_adapter(adapter)
        rec("close_adapter", st2)
        print_result(False, calls, "create_device failed")
        return

    st, ctx1 = mock_gpu.create_context(dev1)
    rec("create_context", st)
    if st != 0:
        st2 = mock_gpu.destroy_device(dev1)
        rec("destroy_device", st2)
        st3 = mock_gpu.close_adapter(adapter)
        rec("close_adapter", st3)
        print_result(False, calls, "create_context failed")
        return

    st, dev2 = mock_gpu.create_device(adapter)
    rec("create_device", st)
    if st != 0:
        st2 = mock_gpu.destroy_context(ctx1)
        rec("destroy_context", st2)
        st3 = mock_gpu.destroy_device(dev1)
        rec("destroy_device", st3)
        st4 = mock_gpu.close_adapter(adapter)
        rec("close_adapter", st4)
        print_result(False, calls, "create_device2 failed")
        return

    st, ctx2 = mock_gpu.create_context(dev2)
    rec("create_context", st)
    if st != 0:
        st2 = mock_gpu.destroy_device(dev2)
        rec("destroy_device", st2)
        st3 = mock_gpu.destroy_context(ctx1)
        rec("destroy_context", st3)
        st4 = mock_gpu.destroy_device(dev1)
        rec("destroy_device", st4)
        st5 = mock_gpu.close_adapter(adapter)
        rec("close_adapter", st5)
        print_result(False, calls, "create_context2 failed")
        return

    reached_owner = False
    reached_len = False
    notes = []

    # Ownership bypass probe
    for type_ in range(8):
        if reached_owner:
            break
        for flags in [0, 0x1, 0x2, 0x3]:
            st = mock_gpu.escape(adapter, dev1, ctx2, type_, flags, b'\x00' * 8)
            rec("escape", st)
            if st == 0:
                reached_owner = True
                notes.append("owner bypass type=%d flags=%d" % (type_, flags))
                break

    # Length boundary probe
    configs = [
        (0, 4, 8, 4, 5),
        (0, 4, 8, 8, 9),
        (0, 4, 16, 12, 13),
        (0, 4, 16, 16, 17),
        (0, 4, 32, 28, 29),
        (0, 4, 32, 32, 33),
        (4, 4, 12, 4, 5),
        (4, 4, 12, 12, 13),
        (0, 8, 16, 8, 9),
        (0, 8, 16, 16, 17),
    ]

    for (offset, length_size, L, valid_decl, bad_decl) in configs:
        if reached_len:
            break
        for type_ in range(8):
            if reached_len:
                break
            for flags in [0, 0x1, 0x2, 0x3]:
                payload_valid = make_payload(L, offset, length_size, valid_decl)
                st_valid = mock_gpu.escape(adapter, dev1, ctx1, type_, flags, payload_valid)
                rec("escape", st_valid)
                if st_valid == 0:
                    payload_bad = make_payload(L, offset, length_size, bad_decl)
                    st_bad = mock_gpu.escape(adapter, dev1, ctx1, type_, flags, payload_bad)
                    rec("escape", st_bad)
                    if st_bad == 0:
                        reached_len = True
                        notes.append("length bypass type=%d flags=%d offset=%d lsize=%d L=%d valid=%d bad=%d" % (type_, flags, offset, length_size, L, valid_decl, bad_decl))
                        break

    # Cleanup
    st = mock_gpu.destroy_context(ctx2)
    rec("destroy_context", st)
    st = mock_gpu.destroy_device(dev2)
    rec("destroy_device", st)
    st = mock_gpu.destroy_context(ctx1)
    rec("destroy_context", st)
    st = mock_gpu.destroy_device(dev1)
    rec("destroy_device", st)
    st = mock_gpu.close_adapter(adapter)
    rec("close_adapter", st)

    reached = reached_owner or reached_len
    if not notes:
        notes.append("no suspicious behavior triggered")
    print_result(reached, calls, "; ".join(notes))

def print_result(reached, calls, notes):
    calls_str = []
    for c in calls:
        calls_str.append('{"api": "%s", "status": %d}' % (c["api"], c["status"]))
    calls_json = "[" + ", ".join(calls_str) + "]"
    notes_escaped = notes.replace('\\', '\\\\').replace('"', '\\"')
    print('CPG_RESULT {"reached": %s, "calls": %s, "notes": "%s"}' % (str(reached).lower(), calls_json, notes_escaped))

if __name__ == "__main__":
    main()