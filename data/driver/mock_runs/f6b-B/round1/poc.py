import mock_gpu

calls = []

def rec(name, st):
    calls.append({"api": name, "status": int(st)})
    return st

def p32(n):
    return (int(n) & 0xFFFFFFFF).to_bytes(4, "little")

mock_gpu.reset()

st, adapter = mock_gpu.open_adapter("")
rec("open_adapter", st)

st, dev1 = mock_gpu.create_device(adapter)
rec("create_device", st)

st, dev2 = mock_gpu.create_device(adapter)
rec("create_device", st)

st, ctx1 = mock_gpu.create_context(dev1)
rec("create_context", st)

st, ctx2 = mock_gpu.create_context(dev2)
rec("create_context", st)

st, ctx1b = mock_gpu.create_context(dev1)
rec("create_context", st)

# Baseline: legitimate context on legitimate device.
s = mock_gpu.escape(adapter, dev1, ctx1, 7, 0, p32(0))
rec("escape", s)

# Probe (1): use a context owned by a different device, varying request type/flags.
reached_owner = False
owner_notes = []

for t in range(8):
    for f in (0, 1, 2, 3):
        s = mock_gpu.escape(adapter, dev1, ctx2, t, f, p32(0))
        rec("escape", s)
        if s == 0:
            reached_owner = True
            owner_notes.append("cross type=%d flags=%d" % (t, f))

# Probe (2): declared private-data length versus actual payload bytes.
# Payload format exercised: first 4 bytes little-endian declared length, then actual data.
reached_len = False
len_notes = []

for t in range(8):
    for f in (0, 2):
        # Valid control.
        s0 = mock_gpu.escape(adapter, dev1, ctx1, t, f, p32(0))
        rec("escape", s0)

        # Invalid/huge declared length control.
        sH = mock_gpu.escape(adapter, dev1, ctx1, t, f, p32(0xFFFFFFFF) + b"A" * 4)
        rec("escape", sH)

        enforces = (sH != 0)
        found_here = False

        for actual in (0, 1, 2, 3, 4, 12, 13, 15, 16, 20, 1020):
            if found_here:
                break
            for extra in (1, 2, 3, 4):
                declared = actual + extra
                payload = p32(declared) + (b"A" * actual)
                if len(payload) > 1024:
                    continue
                s = mock_gpu.escape(adapter, dev1, ctx1, t, f, payload)
                rec("escape", s)
                if s == 0 and declared > actual:
                    if enforces or t == 7:
                        reached_len = True
                        found_here = True
                        len_notes.append(
                            "len type=%d flags=%d actual=%d declared=%d" %
                            (t, f, actual, declared)
                        )
                        break

# Cleanup in dependency order.
for h in (ctx1b, ctx1, ctx2):
    st = mock_gpu.destroy_context(h)
    rec("destroy_context", st)

for h in (dev1, dev2):
    st = mock_gpu.destroy_device(h)
    rec("destroy_device", st)

st = mock_gpu.close_adapter(adapter)
rec("close_adapter", st)

reached = bool(reached_owner or reached_len)

notes = []
if reached_owner:
    notes.append("context-ownership bypass")
if reached_len:
    notes.append("private-length boundary bypass")
if not notes:
    notes.append("no bypass observed")
if owner_notes:
    notes.append(owner_notes[0])
if len_notes:
    notes.append(len_notes[0])

note = "; ".join(notes).replace('"', "'").replace("\n", " ")
calls_str = "[" + ", ".join(
    '{"api": "%s", "status": %d}' % (c["api"], c["status"]) for c in calls
) + "]"

print('CPG_RESULT {"reached": %s, "calls": %s, "notes": "%s"}' % (
    "true" if reached else "false",
    calls_str,
    note
))