import mock_gpu

calls = []
def add_call(api, status):
    calls.append('{"api": "%s", "status": %d}' % (api, status))

def open_adapter(hint):
    status, h = mock_gpu.open_adapter(hint)
    add_call("open_adapter", status)
    return status, h

def create_device(hAdapter):
    status, h = mock_gpu.create_device(hAdapter)
    add_call("create_device", status)
    return status, h

def create_context(hDevice, node=0):
    status, h = mock_gpu.create_context(hDevice, node)
    add_call("create_context", status)
    return status, h

def escape(hAdapter, hDevice, hContext, type_, flags, payload):
    status = mock_gpu.escape(hAdapter, hDevice, hContext, type_, flags, payload)
    add_call("escape", status)
    return status

def destroy_context(hContext):
    status = mock_gpu.destroy_context(hContext)
    add_call("destroy_context", status)
    return status

def destroy_device(hDevice):
    status = mock_gpu.destroy_device(hDevice)
    add_call("destroy_device", status)
    return status

def close_adapter(hAdapter):
    status = mock_gpu.close_adapter(hAdapter)
    add_call("close_adapter", status)
    return status

def reset():
    mock_gpu.reset()
    add_call("reset", 0)

# Begin
reset()

# Create first stack
st, a1 = open_adapter("stack1")
st, d1 = create_device(a1)
st, c1 = create_context(d1)

# Create second stack
st, a2 = open_adapter("stack2")
st, d2 = create_device(a2)
st, c2 = create_context(d2)

# Payloads
empty = b""
zeros_16 = b"\x00" * 16
zeros_1023 = b"\x00" * 1023
zeros_1024 = b"\x00" * 1024
fill_16 = b"\xff" * 16
fill_1023 = b"\xff" * 1023
fill_1024 = b"\xff" * 1024
random_16 = b"\x01\x02\x03\x04" * 4
random_1024 = b"\x01\x02\x03\x04" * 256

results = []
def run_escape(desc, hA, hD, hC, type_, flags, payload, is_cross):
    status = escape(hA, hD, hC, type_, flags, payload)
    results.append((is_cross, type_, flags, len(payload), desc, status))
    return status

# Single stack baseline and length variations
run_escape("single_type0_flags0_len0_empty", a1, d1, c1, 0, 0, empty, False)
run_escape("single_type0_flags0_len16_zeros", a1, d1, c1, 0, 0, zeros_16, False)
run_escape("single_type0_flags0_len1023_zeros", a1, d1, c1, 0, 0, zeros_1023, False)
run_escape("single_type0_flags0_len1024_zeros", a1, d1, c1, 0, 0, zeros_1024, False)
run_escape("single_type0_flags0_len1024_fill", a1, d1, c1, 0, 0, fill_1024, False)
run_escape("single_type0_flags0_len1024_random", a1, d1, c1, 0, 0, random_1024, False)

# Single stack mutation candidates
run_escape("cand1_single_type1_flags0_len16_zeros", a1, d1, c1, 1, 0, zeros_16, False)
run_escape("cand2_single_type0_flags1_len16_zeros", a1, d1, c1, 0, 1, zeros_16, False)
run_escape("cand6_single_type0_flags2_len16_zeros", a1, d1, c1, 0, 2, zeros_16, False)

# Cross-device context tests (stack1 adapter/device with stack2 context)
run_escape("cand3_cross_type0_flags0_len0_empty", a1, d1, c2, 0, 0, empty, True)
run_escape("cand5_cross_type0_flags3_len0_empty", a1, d1, c2, 0, 3, empty, True)
run_escape("cand4_cross_type1_flags0_len16_zeros", a1, d1, c2, 1, 0, zeros_16, True)
run_escape("cross_type0_flags1_len0_empty", a1, d1, c2, 0, 1, empty, True)
run_escape("cross_type0_flags2_len0_empty", a1, d1, c2, 0, 2, empty, True)
run_escape("cross_type0_flags0_len16_zeros", a1, d1, c2, 0, 0, zeros_16, True)
run_escape("cross_type0_flags1_len16_zeros", a1, d1, c2, 0, 1, zeros_16, True)
run_escape("cross_type0_flags2_len16_zeros", a1, d1, c2, 0, 2, zeros_16, True)
run_escape("cross_type0_flags3_len16_zeros", a1, d1, c2, 0, 3, zeros_16, True)
run_escape("cross_type1_flags2_len16_zeros", a1, d1, c2, 1, 2, zeros_16, True)
for t in range(8):
    run_escape("cross_type%d_flags2_len0_empty" % t, a1, d1, c2, t, 2, empty, True)

# Reverse cross tests (stack2 adapter/device with stack1 context)
run_escape("rev_cross_type0_flags0_len0_empty", a2, d2, c1, 0, 0, empty, True)
run_escape("rev_cross_type0_flags2_len0_empty", a2, d2, c1, 0, 2, empty, True)
run_escape("rev_cross_type0_flags3_len0_empty", a2, d2, c1, 0, 3, empty, True)

# Cleanup
destroy_context(c2)
destroy_device(d2)
close_adapter(a2)
destroy_context(c1)
destroy_device(d1)
close_adapter(a1)

# Analyze
cross_success = False
for is_cross, type_, flags, plen, desc, status in results:
    if is_cross and status == 0:
        cross_success = True
        break

length_boundary = False
single_status = {}
for is_cross, type_, flags, plen, desc, status in results:
    if not is_cross:
        single_status[(type_, flags, plen)] = status

# Check if 1024 rejected while 1023 accepted
for (type_, flags, plen), status in single_status.items():
    if plen == 1024 and status != 0:
        if single_status.get((type_, flags, 1023)) == 0:
            length_boundary = True
            break

# Check if 0 rejected while 16 accepted (empty boundary)
for (type_, flags, plen), status in single_status.items():
    if plen == 0 and status != 0:
        if single_status.get((type_, flags, 16)) == 0:
            length_boundary = True
            break

reached = cross_success or length_boundary

notes = ""
if cross_success:
    notes += "Cross-device context ownership check bypassed (escape returned 0 for cross-context). "
if length_boundary:
    notes += "Length boundary error detected (off-by-one in payload length check). "
if not reached:
    notes += "No vulnerability triggered in the tested sequences."

calls_json = ", ".join(calls)
result_json = '{"reached": %s, "calls": [%s], "notes": "%s"}' % (
    "true" if reached else "false",
    calls_json,
    notes.replace('"', '\\"')
)
print("CPG_RESULT " + result_json)