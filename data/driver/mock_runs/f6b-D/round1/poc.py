import mock_gpu

CALLS = []


def rec(api, status):
    try:
        s = int(status)
    except Exception:
        s = 0
    CALLS.append({"api": api, "status": s})
    return s


def mk(kind, n):
    if n <= 0:
        return b""
    if kind == "fill":
        return b"\x5a" * n
    return b"\x00" * n


def esc(s):
    return s.replace("\\", "/").replace('"', "'")


def run():
    own = {}
    cross = {}
    reached = False
    notes = "probe aborted before escape coverage"

    mock_gpu.reset()
    rec("reset", 0)

    s1, hA1 = mock_gpu.open_adapter("probe-primary")
    rec("open_adapter", s1)
    s2, hA2 = mock_gpu.open_adapter("probe-secondary")
    rec("open_adapter", s2)

    adapters = [h for h in (hA1, hA2) if h]
    devices = []
    contexts = []
    hD1 = hD2 = hC1 = hC2 = 0

    if hA1 and hA2:
        s, hD1 = mock_gpu.create_device(hA1)
        rec("create_device", s)
        s, hD2 = mock_gpu.create_device(hA1)
        rec("create_device", s)
        for h in (hD1, hD2):
            if h:
                devices.append(h)
        if hD1:
            s, hC1 = mock_gpu.create_context(hD1, 0)
            rec("create_context", s)
            if hC1:
                contexts.append(hC1)
        if hD2:
            s, hC2 = mock_gpu.create_context(hD2, 0)
            rec("create_context", s)
            if hC2:
                contexts.append(hC2)

    if hD1 and hD2 and hC1 and hC2:
        lens_a = [0, 1, 2, 3, 4, 5, 15, 16, 17, 1023, 1024]
        lens_b = [4, 16, 1024]

        # 1) own-object sweep: declared private-data length across the legal range,
        #    plus every flag combination (0..3) and every escape type (0..7).
        for t in range(8):
            for n in lens_a:
                s = mock_gpu.escape(hA1, hD1, hC1, t, 0, mk("zeros", n))
                rec("escape", s)
                own[(t, 0, n)] = s
            for f in (1, 2, 3):
                for n in lens_b:
                    s = mock_gpu.escape(hA1, hD1, hC1, t, f, mk("fill", n))
                    rec("escape", s)
                    own[(t, f, n)] = s

        # 2) ownership probes: valid device + context that belongs to ANOTHER device,
        #    across all request attributes (flags), all types, two declared lengths.
        for t in range(8):
            for f in (0, 1, 2, 3):
                s = mock_gpu.escape(hA1, hD1, hC2, t, f, mk("zeros", 16))
                rec("escape", s)
                cross[("dev-mismatch", t, f, 16)] = s
                if t in (0, 7):
                    s = mock_gpu.escape(hA1, hD1, hC2, t, f, mk("zeros", 1024))
                    rec("escape", s)
                    cross[("dev-mismatch", t, f, 1024)] = s

        # 3) reversed device pairing and adapter-mismatch pairing.
        for f in (0, 1, 2, 3):
            s = mock_gpu.escape(hA1, hD2, hC1, 0, f, mk("zeros", 16))
            rec("escape", s)
            cross[("dev-reverse", 0, f, 16)] = s
            s = mock_gpu.escape(hA2, hD1, hC1, 0, f, mk("zeros", 16))
            rec("escape", s)
            cross[("adapter-mismatch", 0, f, 16)] = s

        bypass = sorted(k for k, v in cross.items() if v == 0)
        by_flag = sorted({k[2] for k in bypass})
        by_scope = sorted({k[0] for k in bypass})

        len_anom = []
        for t in range(8):
            for f in (0, 1, 2, 3):
                small = own.get((t, f, 16))
                if small is None:
                    small = own.get((t, f, 4))
                big = own.get((t, f, 1024))
                if small == 0 and big is not None and big != 0:
                    len_anom.append((t, f, big))

        min_ok = None
        for n in (0, 1, 2, 3, 4, 5, 15, 16, 17, 1023, 1024):
            if own.get((0, 0, n), 1) == 0:
                min_ok = n
                break

        reached = bool(bypass) or bool(len_anom)
        notes = (
            "own-object escape sweep types 0-7 / flags 0-3 / len 0-1024 complete; "
            "cross-object probes=%d; cross accepted with status 0=%d; "
            "accepted scopes=%s; accepted flags=%s; "
            "len-1024 rejected while small len accepted (boundary suspect)=%d; "
            "smallest accepted declared len at type0/flags0=%s"
            % (
                len(cross),
                len(bypass),
                by_scope if by_scope else "none",
                by_flag if by_flag else "none",
                len(len_anom),
                min_ok,
            )
        )

    for h in reversed(contexts):
        rec("destroy_context", mock_gpu.destroy_context(h))
    for h in reversed(devices):
        rec("destroy_device", mock_gpu.destroy_device(h))
    for h in reversed(adapters):
        rec("close_adapter", mock_gpu.close_adapter(h))

    return reached, notes


def main():
    reached, notes = run()
    chunks = []
    for c in CALLS:
        chunks.append('{"api": "%s", "status": %d}' % (c["api"], c["status"]))
    body = ", ".join(chunks)
    print(
        'CPG_RESULT {"reached": %s, "calls": [%s], "notes": "%s"}'
        % ("true" if reached else "false", body, esc(notes))
    )


main()