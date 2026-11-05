import mock_gpu

calls = []

def log(api, status):
    calls.append((api, status))

def do_reset():
    mock_gpu.reset()
    log("reset", 0)

def do_open_adapter(hint=""):
    st, h = mock_gpu.open_adapter(hint)
    log("open_adapter", st)
    return st, h

def do_create_device(hAdapter):
    st, h = mock_gpu.create_device(hAdapter)
    log("create_device", st)
    return st, h

def do_create_context(hDevice, node=0):
    st, h = mock_gpu.create_context(hDevice, node)
    log("create_context", st)
    return st, h

def do_escape(hAdapter, hDevice, hContext, type_, flags, payload):
    st = mock_gpu.escape(hAdapter, hDevice, hContext, type_, flags, payload)
    log("escape", st)
    return st

def do_destroy_context(hContext):
    st = mock_gpu.destroy_context(hContext)
    log("destroy_context", st)
    return st

def do_destroy_device(hDevice):
    st = mock_gpu.destroy_device(hDevice)
    log("destroy_device", st)
    return st

def do_close_adapter(hAdapter):
    st = mock_gpu.close_adapter(hAdapter)
    log("close_adapter", st)
    return st

def make_payload(off, declared, data_len):
    total = off + 4 + data_len
    buf = bytearray(total)
    buf[off:off + 4] = (declared & 0xFFFFFFFF).to_bytes(4, 'little')
    for i in range(off + 4, total):
        buf[i] = 0x41
    return bytes(buf)

def esc(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

# ---- setup ----
do_reset()

hAdapter1 = hDevice1 = hContext1 = 0
hDevice2 = hContext2 = 0
hAdapter2 = hDevice3 = hContext3 = 0

st, hAdapter1 = do_open_adapter("probe1")
if st == 0:
    st, hDevice1 = do_create_device(hAdapter1)
    if st == 0:
        st, hContext1 = do_create_context(hDevice1)

    st2, hDevice2 = do_create_device(hAdapter1)
    if st2 == 0:
        st2, hContext2 = do_create_context(hDevice2)

    stA2, hAdapter2 = do_open_adapter("probe2")
    if stA2 == 0:
        stD3, hDevice3 = do_create_device(hAdapter2)
        if stD3 == 0:
            stC3, hContext3 = do_create_context(hDevice3)

# ---- probe 1: context ownership / request attributes ----
reached_ownership = False
reached_length = False
notes = []

if hAdapter1 and hDevice1 and hContext1:
    payload_own = b'\x00\x00\x00\x00'
    for type_ in range(8):
        for flags in (0, 1, 2, 3):
            # valid baseline
            do_escape(hAdapter1, hDevice1, hContext1, type_, flags, payload_own)

            # context from device2 used with device1
            if hDevice2 and hContext2:
                st = do_escape(hAdapter1, hDevice1, hContext2, type_, flags, payload_own)
                if st == 0:
                    reached_ownership = True
                    if len(notes) < 20:
                        notes.append("ownership bypass: device1+context2 type=%d flags=%d" % (type_, flags))

            # context from device1 used with device2
            if hDevice2:
                st = do_escape(hAdapter1, hDevice2, hContext1, type_, flags, payload_own)
                if st == 0:
                    reached_ownership = True
                    if len(notes) < 20:
                        notes.append("ownership bypass: device2+context1 type=%d flags=%d" % (type_, flags))

            # context from adapter1/device1 used with adapter2/device3
            if hAdapter2 and hDevice3:
                st = do_escape(hAdapter2, hDevice3, hContext1, type_, flags, payload_own)
                if st == 0:
                    reached_ownership = True
                    if len(notes) < 20:
                        notes.append("ownership bypass: adapter2+device3+context1 type=%d flags=%d" % (type_, flags))

# ---- probe 2: declared private-data length boundaries ----
length_results = {}

if hAdapter1 and hDevice1 and hContext1:
    for type_ in range(8):
        for flags in (0, 1):
            for off in (0, 4, 8):
                for data_len in (0, 1, 2, 4, 8):
                    total = off + 4 + data_len
                    declared_list = [
                        data_len,
                        data_len + 1,
                        data_len + 2,
                        total,
                        total + 1,
                        total + 2,
                        0xFFFFFFFF,
                    ]
                    for declared in declared_list:
                        payload = make_payload(off, declared, data_len)
                        st = do_escape(hAdapter1, hDevice1, hContext1, type_, flags, payload)
                        length_results[(type_, flags, off, data_len, declared)] = st

    for type_ in range(8):
        for flags in (0, 1):
            for off in (0, 4, 8):
                for data_len in (0, 1, 2, 4, 8):
                    total = off + 4 + data_len
                    st_max = length_results.get((type_, flags, off, data_len, 0xFFFFFFFF))
                    st_plus1 = length_results.get((type_, flags, off, data_len, data_len + 1))
                    st_plus2 = length_results.get((type_, flags, off, data_len, data_len + 2))
                    st_tot1 = length_results.get((type_, flags, off, data_len, total + 1))
                    st_tot2 = length_results.get((type_, flags, off, data_len, total + 2))

                    if st_max == 0:
                        reached_length = True
                        if len(notes) < 20:
                            notes.append("length max accepted: type=%d flags=%d off=%d data_len=%d" % (type_, flags, off, data_len))

                    if st_plus1 == 0 and st_plus2 is not None and st_plus2 != 0:
                        reached_length = True
                        if len(notes) < 20:
                            notes.append("length boundary off-by-one (data): type=%d flags=%d off=%d data_len=%d" % (type_, flags, off, data_len))

                    if st_tot1 == 0 and st_tot2 is not None and st_tot2 != 0:
                        reached_length = True
                        if len(notes) < 20:
                            notes.append("length boundary off-by-one (total): type=%d flags=%d off=%d data_len=%d" % (type_, flags, off, data_len))

                    if st_plus1 == 0 and st_max is not None and st_max != 0:
                        reached_length = True
                        if len(notes) < 20:
                            notes.append("length over-data accepted while max fails: type=%d flags=%d off=%d data_len=%d" % (type_, flags, off, data_len))

                    if st_tot1 == 0 and st_max is not None and st_max != 0:
                        reached_length = True
                        if len(notes) < 20:
                            notes.append("length over-total accepted while max fails: type=%d flags=%d off=%d data_len=%d" % (type_, flags, off, data_len))

# ---- cleanup ----
if hContext1:
    do_destroy_context(hContext1)
if hContext2:
    do_destroy_context(hContext2)
if hContext3:
    do_destroy_context(hContext3)

if hDevice1:
    do_destroy_device(hDevice1)
if hDevice2:
    do_destroy_device(hDevice2)
if hDevice3:
    do_destroy_device(hDevice3)

if hAdapter1:
    do_close_adapter(hAdapter1)
if hAdapter2:
    do_close_adapter(hAdapter2)

# ---- result ----
change_note = "修改：增加跨device/adapter归属探测、flags 0..3、声明长度边界(+1/+2/0xFFFFFFFF)探测"
notes_str = change_note
if notes:
    notes_str += "; " + "; ".join(notes)
if len(notes) >= 20:
    notes_str += " ... (truncated)"

call_strs = []
for api, status in calls:
    call_strs.append('{"api": "' + esc(api) + '", "status": ' + str(status) + '}')

result_str = (
    '{'
    '"reached": ' + ('true' if (reached_ownership or reached_length) else 'false') + ', '
    '"calls": [' + ', '.join(call_strs) + '], '
    '"notes": "' + esc(notes_str) + '"'
    '}'
)

print("CPG_RESULT " + result_str)