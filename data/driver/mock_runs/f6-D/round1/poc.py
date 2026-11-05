import mock_gpu

calls = []

def rec(api, status):
    calls.append((api, int(status)))

def json_quote(s):
    r = s.replace('\\', '\\\\').replace('"', '\\"')
    r = r.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return '"' + r + '"'

def print_result(reached, call_list, notes):
    parts = []
    for api, st in call_list:
        parts.append('{"api": %s, "status": %d}' % (json_quote(api), st))
    print('CPG_RESULT {"reached": %s, "calls": [%s], "notes": %s}' % (
        'true' if reached else 'false',
        ', '.join(parts),
        json_quote(notes)
    ))

def open_adapter(hint):
    st, h = mock_gpu.open_adapter(hint)
    rec("open_adapter", st)
    return st, h

def create_device(ha):
    st, hd = mock_gpu.create_device(ha)
    rec("create_device", st)
    return st, hd

def create_context(hd):
    st, hc = mock_gpu.create_context(hd)
    rec("create_context", st)
    return st, hc

def escape(ha, hd, hc, t, f, payload):
    st = mock_gpu.escape(ha, hd, hc, t, f, payload)
    rec("escape", st)
    return st

def destroy_context(hc):
    st = mock_gpu.destroy_context(hc)
    rec("destroy_context", st)
    return st

def destroy_device(hd):
    st = mock_gpu.destroy_device(hd)
    rec("destroy_device", st)
    return st

def close_adapter(ha):
    st = mock_gpu.close_adapter(ha)
    rec("close_adapter", st)
    return st

mock_gpu.reset()

# Stack A
stA, hA = open_adapter("A")
hDevA = 0
hCtxA = 0
if stA == 0:
    stDevA, hDevA = create_device(hA)
    if stDevA == 0:
        stCtxA, hCtxA = create_context(hDevA)

# Stack B
stB, hB = open_adapter("B")
hDevB = 0
hCtxB = 0
if stB == 0:
    stDevB, hDevB = create_device(hB)
    if stDevB == 0:
        stCtxB, hCtxB = create_context(hDevB)

reached = False
notes = []

if hCtxA != 0:
    single_tests = [
        (0, 0, 16), (1, 0, 16), (0, 1, 16), (0, 2, 16), (0, 3, 16),
        (1, 1, 16), (1, 2, 16), (1, 3, 16),
        (0, 0, 0), (0, 3, 0),
        (1, 0, 3), (1, 0, 4), (1, 0, 5),
        (1, 2, 3), (1, 2, 4), (1, 2, 5),
        (0, 0, 1023), (0, 0, 1024),
        (0, 3, 1023), (0, 3, 1024),
        (1, 0, 1023), (1, 0, 1024),
        (1, 2, 1023), (1, 2, 1024),
    ]
    single_status = {}
    for t, f, ln in single_tests:
        st = escape(hA, hDevA, hCtxA, t, f, b'\x00' * ln)
        single_status[(t, f, ln)] = st

    # Length boundary anomalies for type 1
    for f in [0, 2]:
        st3 = single_status.get((1, f, 3))
        st4 = single_status.get((1, f, 4))
        st5 = single_status.get((1, f, 5))
        st1023 = single_status.get((1, f, 1023))
        st1024 = single_status.get((1, f, 1024))
        if st3 == 0:
            reached = True
            notes.append("type1 f%d len3 accepted" % f)
        if st4 is not None and st5 is not None and st4 != st5:
            reached = True
            notes.append("type1 f%d len4/5 mismatch %d/%d" % (f, st4, st5))
        if st1023 is not None and st1024 is not None and st1023 != st1024:
            reached = True
            notes.append("type1 f%d len1023/1024 mismatch %d/%d" % (f, st1023, st1024))

    # Length boundary anomalies for type 0
    for f in [0, 3]:
        st1023 = single_status.get((0, f, 1023))
        st1024 = single_status.get((0, f, 1024))
        if st1023 is not None and st1024 is not None and st1023 != st1024:
            reached = True
            notes.append("type0 f%d len1023/1024 mismatch %d/%d" % (f, st1023, st1024))

if hCtxA != 0 and hCtxB != 0:
    cross_tests = [
        (0, 0, 16), (0, 1, 16), (0, 2, 16), (0, 3, 16),
        (1, 0, 16), (1, 1, 16), (1, 2, 16), (1, 3, 16),
        (0, 0, 0), (0, 3, 0), (0, 2, 1024),
        (1, 0, 3), (1, 0, 4), (1, 0, 5),
        (1, 2, 3), (1, 2, 4), (1, 2, 5),
    ]
    for t, f, ln in cross_tests:
        payload = b'\x00' * ln
        st = escape(hA, hDevA, hCtxB, t, f, payload)
        if st == 0:
            reached = True
            notes.append("cross A-dev/B-ctx success t%d f%d len%d" % (t, f, ln))
        st = escape(hB, hDevB, hCtxA, t, f, payload)
        if st == 0:
            reached = True
            notes.append("cross B-dev/A-ctx success t%d f%d len%d" % (t, f, ln))

if hCtxA != 0:
    destroy_context(hCtxA)
if hDevA != 0:
    destroy_device(hDevA)
if hA != 0:
    close_adapter(hA)
if hCtxB != 0:
    destroy_context(hCtxB)
if hDevB != 0:
    destroy_device(hDevB)
if hB != 0:
    close_adapter(hB)

if not notes:
    notes.append("no cross-device success or length boundary anomaly detected")

print_result(reached, calls, "; ".join(notes))