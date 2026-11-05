import mock_gpu

calls = []

def rec(api, status):
    if status is None:
        status = 0
    try:
        status = int(status)
    except Exception:
        status = -1
    calls.append((api, status))

def payload(kind, n):
    if kind == "empty":
        return b""
    if kind == "zeros":
        return bytes(n)
    if kind == "fill":
        return bytes([0xFF]) * n
    if kind == "fill41":
        return bytes([0x41]) * n
    if kind == "random":
        return bytes(((i * 37 + 11) & 0xFF) for i in range(n))
    return bytes(n)

def esc(a, d, c, t, f, kind, n):
    p = payload(kind, n)
    try:
        st = mock_gpu.escape(a, d, c, t, f, p)
    except Exception:
        st = -1
    rec("escape", st)
    return st

mock_gpu.reset()
rec("reset", 0)

st, a1 = mock_gpu.open_adapter("primary")
rec("open_adapter", st)
st, a2 = mock_gpu.open_adapter("secondary")
rec("open_adapter", st)

st, d1 = mock_gpu.create_device(a1)
rec("create_device", st)
st, d2 = mock_gpu.create_device(a2)
rec("create_device", st)

st, c1 = mock_gpu.create_context(d1, 0)
rec("create_context", st)
st, c2 = mock_gpu.create_context(d2, 0)
rec("create_context", st)

cross_successes = []
length_suspicious = []
status_store = {}

exact = [
    (0, 0, "empty", 0, "single"),
    (0, 0, "zeros", 16, "single"),
    (0, 0, "zeros", 16, "cross_device"),
    (1, 0, "zeros", 16, "single"),
    (0, 1, "zeros", 16, "single"),
    (0, 0, "empty", 0, "cross_device"),
    (1, 0, "zeros", 16, "cross_device"),
    (0, 3, "empty", 0, "cross_device"),
    (0, 2, "zeros", 16, "single"),
]

for t, f, kind, n, plan in exact:
    if plan == "single":
        st = esc(a1, d1, c1, t, f, kind, n)
    else:
        st = esc(a1, d1, c2, t, f, kind, n)
    status_store[(t, f, kind, n, plan)] = st
    if plan == "cross_device" and st == 0:
        cross_successes.append((t, f, kind, n))

for t in range(8):
    for f in range(4):
        for kind, n in [
            ("empty", 0),
            ("zeros", 16),
            ("fill", 16),
            ("random", 16),
            ("zeros", 1024),
            ("fill", 1024),
        ]:
            st = esc(a1, d1, c2, t, f, kind, n)
            if st == 0:
                cross_successes.append((t, f, kind, n))

for t in range(8):
    for f in range(4):
        for n in [0, 16, 17, 256, 1024]:
            if n == 0:
                kinds = ["empty"]
            else:
                kinds = ["zeros", "fill", "fill41"]
            for kind in kinds:
                st = esc(a1, d1, c1, t, f, kind, n)
                status_store[(t, f, kind, n, "single")] = st

        for n in [16, 17, 256, 1024]:
            z = status_store.get((t, f, "zeros", n, "single"))
            q = status_store.get((t, f, "fill", n, "single"))
            r = status_store.get((t, f, "fill41", n, "single"))
            if z is not None and q is not None and z != 0 and q == 0:
                length_suspicious.append((t, f, "zeros_fail_ff_fill_success", n))
            if r is not None and q is not None and r != 0 and q == 0:
                length_suspicious.append((t, f, "fill41_fail_ff_fill_success", n))
            if z is not None and q is not None and z == 0 and q != 0:
                pass

reached = bool(cross_successes) or bool(length_suspicious)

notes_parts = []
notes_parts.append("cross_successes=%d" % len(cross_successes))
if cross_successes:
    c0 = cross_successes[0]
    notes_parts.append(
        "first_cross_type=%d flags=%d kind=%s len=%d"
        % (c0[0], c0[1], c0[2], c0[3])
    )

notes_parts.append("length_suspicious=%d" % len(length_suspicious))
if length_suspicious:
    l0 = length_suspicious[0]
    notes_parts.append(
        "first_length_type=%d flags=%d case=%s len=%d"
        % (l0[0], l0[1], l0[2], l0[3])
    )

escape_count = 0
for api, st in calls:
    if api == "escape":
        escape_count += 1
notes_parts.append("escape_calls=%d" % escape_count)
notes = "; ".join(notes_parts)

st = mock_gpu.destroy_context(c1)
rec("destroy_context", st)
st = mock_gpu.destroy_context(c2)
rec("destroy_context", st)

st = mock_gpu.destroy_device(d1)
rec("destroy_device", st)
st = mock_gpu.destroy_device(d2)
rec("destroy_device", st)

st = mock_gpu.close_adapter(a1)
rec("close_adapter", st)
st = mock_gpu.close_adapter(a2)
rec("close_adapter", st)

parts = []
for api, st in calls:
    parts.append('{"api": "%s", "status": %d}' % (api, st))
calls_json = ", ".join(parts)

print(
    'CPG_RESULT {"reached": %s, "calls": [%s], "notes": "%s"}'
    % ("true" if reached else "false", calls_json, notes)
)