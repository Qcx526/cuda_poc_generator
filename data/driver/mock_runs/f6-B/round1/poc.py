import mock_gpu

calls = []


def log(api, status):
    try:
        s = int(status)
    except Exception:
        s = -1
    calls.append((api, s))
    return s


def api_open(hint=""):
    try:
        st, h = mock_gpu.open_adapter(hint)
    except Exception:
        return log("open_adapter", -1), 0
    return log("open_adapter", st), h


def api_create_device(h):
    try:
        st, hd = mock_gpu.create_device(h)
    except Exception:
        return log("create_device", -1), 0
    return log("create_device", st), hd


def api_create_context(h, node=0):
    try:
        st, hc = mock_gpu.create_context(h, node)
    except Exception:
        return log("create_context", -1), 0
    return log("create_context", st), hc


def api_escape(ha, hd, hc, t, f, p):
    try:
        st = mock_gpu.escape(ha, hd, hc, t, f, p)
    except Exception:
        st = -1
    return log("escape", st)


def api_destroy_context(hc):
    try:
        st = mock_gpu.destroy_context(hc)
    except Exception:
        st = -1
    return log("destroy_context", st)


def api_destroy_device(hd):
    try:
        st = mock_gpu.destroy_device(hd)
    except Exception:
        st = -1
    return log("destroy_device", st)


def api_close_adapter(ha):
    try:
        st = mock_gpu.close_adapter(ha)
    except Exception:
        st = -1
    return log("close_adapter", st)


def le32(v):
    return (v & 0xFFFFFFFF).to_bytes(4, "little")


def json_escape(s):
    s = str(s)
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def main():
    try:
        mock_gpu.reset()
        log("reset", 0)
    except Exception:
        log("reset", -1)

    reached_own = False
    reached_len = False
    ev = []

    st, a1 = api_open("")
    d1 = c1 = 0
    if st == 0:
        st, d1 = api_create_device(a1)
        if st == 0:
            st, c1 = api_create_context(d1, 0)

    a2 = d2 = c2 = 0
    st2, a2_tmp = api_open("")
    if st2 == 0:
        a2 = a2_tmp
        st2d, d2_tmp = api_create_device(a2)
        if st2d == 0:
            d2 = d2_tmp
            st2c, c2_tmp = api_create_context(d2, 0)
            if st2c == 0:
                c2 = c2_tmp

    if d2 == 0 and a1:
        stx, d2_tmp = api_create_device(a1)
        if stx == 0:
            d2 = d2_tmp
            stx2, c2_tmp = api_create_context(d2, 0)
            if stx2 == 0:
                c2 = c2_tmp

    if a1 and d1 and c1:
        safe_payloads = [
            b"\x00" * 4,
            b"\x00" * 8,
            le32(0) + b"A" * 4,
            le32(4) + b"A" * 4,
            le32(0) + b"A" * 12,
            le32(12) + b"A" * 12,
            le32(8) + b"A" * 4,
        ]

        good_by_tf = {}
        for t in range(8):
            for f in range(4):
                for p in safe_payloads:
                    st = api_escape(a1, d1, c1, t, f, p)
                    if st == 0:
                        good_by_tf[(t, f)] = p
                        break

        mismatch_pairs = []
        if a2 and d2 and c1:
            mismatch_pairs.append(("cross", a2, d2, c1))
        if a2 and d1 and c1:
            mismatch_pairs.append(("adapter", a2, d1, c1))
        if d2 and c1:
            mismatch_pairs.append(("device", a1, d2, c1))
        if c2:
            mismatch_pairs.append(("context", a1, d1, c2))

        for label, ha, hd, hc in mismatch_pairs:
            if reached_own:
                break
            for t in range(8):
                if reached_own:
                    break
                payload = good_by_tf.get((t, 0))
                if payload is None:
                    for f0 in (1, 2, 3):
                        payload = good_by_tf.get((t, f0))
                        if payload is not None:
                            break
                if payload is None:
                    continue

                for f in range(4):
                    stn = api_escape(a1, d1, c1, t, f, payload)
                    stm = api_escape(ha, hd, hc, t, f, payload)
                    if stn == 0 and stm == 0:
                        reached_own = True
                        ev.append(
                            "ownership bypass %s type=%d flags=%d"
                            % (label, t, f)
                        )
                        break

        length_payloads = []
        for declared in (0, 1, 4, 8, 12, 13, 14, 15, 16, 17, 1024, 1025, 0xFFFFFFFF):
            length_payloads.append((declared, le32(declared) + b"A" * 12))
        length_payloads.append((1024, le32(1024) + b"B" * 1020))
        length_payloads.append((1025, le32(1025) + b"B" * 1020))

        for (t, f) in good_by_tf:
            if reached_len:
                break
            for declared, p in length_payloads:
                total = len(p)
                data_avail = total - 4 if total >= 4 else 0
                if declared <= data_avail and declared <= 1024:
                    continue

                st = api_escape(a1, d1, c1, t, f, p)
                if st == 0:
                    reached_len = True
                    ev.append(
                        "length bypass type=%d flags=%d declared=%d total=%d"
                        % (t, f, declared, total)
                    )
                    break

    if c2 and c2 != c1:
        api_destroy_context(c2)
    if c1:
        api_destroy_context(c1)
    if d2 and d2 != d1:
        api_destroy_device(d2)
    if d1:
        api_destroy_device(d1)
    if a2 and a2 != a1:
        api_close_adapter(a2)
    if a1:
        api_close_adapter(a1)

    reached = bool(reached_own or reached_len)
    if not ev:
        notes = "no trigger observed"
    else:
        notes = "; ".join(ev[:8])

    calls_json = ",".join(
        '{"api":"%s","status":%d}' % (json_escape(a), s) for a, s in calls
    )
    print(
        'CPG_RESULT {"reached": %s, "calls": [%s], "notes": "%s"}'
        % ("true" if reached else "false", calls_json, json_escape(notes))
    )


if __name__ == "__main__":
    main()