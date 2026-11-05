import mock_gpu

calls = []
def rec(api, status):
    try:
        st = int(status)
    except Exception:
        st = 0
    calls.append({"api": api, "status": st})
    return st

def jstr(s):
    out = []
    for ch in str(s):
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'

def esc(tag, hA, hD, hC, type_, flags, payload):
    st = mock_gpu.escape(hA, hD, hC, type_, flags, payload)
    rec("escape[%s;type=%d;flags=%d;len=%d]" % (tag, type_, flags, len(payload)), st)
    return st

def mkdecl(decl, total, off):
    b = bytearray(b"\x41" * total)
    if total >= off + 4:
        b[off:off + 4] = (decl & 0xffffffff).to_bytes(4, "little")
    return bytes(b)

hA = hDA = hCA = 0
hB = hDB = hCB = 0
observed = {}
decl_meta = []
priv_meta = []
exception_text = ""

try:
    mock_gpu.reset()

    st, hA = mock_gpu.open_adapter("A")
    rec("open_adapter(A)", st)
    if hA:
        st, hDA = mock_gpu.create_device(hA)
        rec("create_device(A)", st)
        if hDA:
            st, hCA = mock_gpu.create_context(hDA, 0)
            rec("create_context(A)", st)

    st, hB = mock_gpu.open_adapter("B")
    rec("open_adapter(B)", st)
    if hB:
        st, hDB = mock_gpu.create_device(hB)
        rec("create_device(B)", st)
        if hDB:
            st, hCB = mock_gpu.create_context(hDB, 0)
            rec("create_context(B)", st)

    if hA and hDA and hCA and hB and hDB and hCB:
        observed["valid0"] = esc("valid", hA, hDA, hCA, 0, 0, b"")

        for f in (0, 1, 2, 3):
            observed["xctx_%d" % f] = esc("xctx", hA, hDA, hCB, 0, f, b"")

        observed["xdev"] = esc("xdev", hA, hDB, hCA, 0, 0, b"")
        observed["xadapter"] = esc("xadapter", hB, hDA, hCA, 0, 0, b"")

        for t in range(8):
            observed["xtype_%d" % t] = esc("xctx_type", hA, hDA, hCB, t, 2, b"")

        for L in (0, 1, 3, 4, 7, 8, 15, 16, 1023, 1024):
            observed["alen_%d" % L] = esc("actual_len", hA, hDA, hCA, 0, 0, b"\x41" * L)

        decl_tests = [
            ("d0_t4_o0", 0, 4, 0),
            ("d4_t4_o0", 4, 4, 0),
            ("d1023_t4_o0", 1023, 4, 0),
            ("d1024_t4_o0", 1024, 4, 0),
            ("d1025_t4_o0", 1025, 4, 0),
            ("dffff_t4_o0", 0xffffffff, 4, 0),
            ("d1024_t8_o0", 1024, 8, 0),
            ("d1025_t8_o0", 1025, 8, 0),
            ("d1024_t1024_o0", 1024, 1024, 0),
            ("d1025_t1024_o0", 1025, 1024, 0),
            ("d1023_t1024_o0", 1023, 1024, 0),
            ("dffff_t1024_o0", 0xffffffff, 1024, 0),
            ("d1024_t1024_o4", 1024, 1024, 4),
            ("d1025_t1024_o4", 1025, 1024, 4),
        ]
        for name, decl, total, off in decl_tests:
            p = mkdecl(decl, total, off)
            observed["decl_" + name] = esc("decl_" + name, hA, hDA, hCA, 0, 0, p)
            decl_meta.append((name, decl, total, off))

        priv_tests = [
            ("d1024_t4_o0", 1024, 4, 0),
            ("d1025_t4_o0", 1025, 4, 0),
            ("d1024_t1024_o0", 1024, 1024, 0),
            ("d1025_t1024_o0", 1025, 1024, 0),
        ]
        for name, decl, total, off in priv_tests:
            p = mkdecl(decl, total, off)
            observed["decl_priv_" + name] = esc("decl_priv_" + name, hA, hDA, hCA, 0, 2, p)
            priv_meta.append((name, decl, total, off))

except Exception as e:
    exception_text = str(e)

finally:
    if hCB:
        try:
            rec("destroy_context(B)", mock_gpu.destroy_context(hCB))
        except Exception:
            rec("destroy_context(B)", -1)
    if hDB:
        try:
            rec("destroy_device(B)", mock_gpu.destroy_device(hDB))
        except Exception:
            rec("destroy_device(B)", -1)
    if hB:
        try:
            rec("close_adapter(B)", mock_gpu.close_adapter(hB))
        except Exception:
            rec("close_adapter(B)", -1)

    if hCA:
        try:
            rec("destroy_context(A)", mock_gpu.destroy_context(hCA))
        except Exception:
            rec("destroy_context(A)", -1)
    if hDA:
        try:
            rec("destroy_device(A)", mock_gpu.destroy_device(hDA))
        except Exception:
            rec("destroy_device(A)", -1)
    if hA:
        try:
            rec("close_adapter(A)", mock_gpu.close_adapter(hA))
        except Exception:
            rec("close_adapter(A)", -1)

    ctx_bypass = any(
        observed.get(k) == 0
        for k in ("xctx_0", "xctx_1", "xctx_2", "xctx_3", "xdev", "xadapter")
    )

    len_anomaly = False
    for name, decl, total, off in decl_meta:
        st = observed.get("decl_" + name)
        avail = max(0, total - (off + 4))
        if st == 0 and (decl > 1024 or (decl >= 1024 and decl > avail)):
            len_anomaly = True
            break
    if not len_anomaly:
        for name, decl, total, off in priv_meta:
            st = observed.get("decl_priv_" + name)
            avail = max(0, total - (off + 4))
            if st == 0 and (decl > 1024 or (decl >= 1024 and decl > avail)):
                len_anomaly = True
                break

    reached = bool(ctx_bypass or len_anomaly)

    notes = (
        "changed=added cross-handle context/device/adapter probes and declared-length boundary probes; "
        "valid0=%s; xctx0=%s; xctx1=%s; xctx2=%s; xctx3=%s; xdev=%s; xadapter=%s; "
        "decl1025_t4=%s; decl1024_t4=%s; decl1024_t1024=%s; decl1025_t1024=%s; "
        "ctx_bypass=%s; len_anomaly=%s"
    ) % (
        observed.get("valid0"),
        observed.get("xctx_0"),
        observed.get("xctx_1"),
        observed.get("xctx_2"),
        observed.get("xctx_3"),
        observed.get("xdev"),
        observed.get("xadapter"),
        observed.get("decl_d1025_t4_o0"),
        observed.get("decl_d1024_t4_o0"),
        observed.get("decl_d1024_t1024_o0"),
        observed.get("decl_d1025_t1024_o0"),
        ctx_bypass,
        len_anomaly,
    )
    if exception_text:
        notes = "exception=%s; " % exception_text + notes

    calls_json = ",".join(
        '{"api":%s,"status":%d}' % (jstr(c["api"]), c["status"]) for c in calls
    )
    print(
        'CPG_RESULT {"reached": %s, "calls": [%s], "notes": %s}'
        % (str(reached).lower(), calls_json, jstr(notes))
    )