import mock_gpu

# 修改点：上一轮跨上下文 escape 只用 flags=0，被拒绝（0xC0000022）。
# 本轮补充 flags=0x1/0x2/0x3 的跨上下文尝试，并针对私有数据声明长度做 +1 边界测试。

calls = []

def rec(api, status):
    calls.append((api, status))
    return status

def u32le(n):
    return bytes((n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff))

def do_escape(hA, hD, hC, t, f, p):
    st = mock_gpu.escape(hA, hD, hC, t, f, p)
    calls.append(("escape", st))
    return st

# 1. 合法 adapter/device/context 构造
st, hAdapter = mock_gpu.open_adapter("cpg")
rec("open_adapter", st)
st, devA = mock_gpu.create_device(hAdapter)
rec("create_device", st)
st, ctxA = mock_gpu.create_context(devA, 0)
rec("create_context", st)
st, devB = mock_gpu.create_device(hAdapter)
rec("create_device", st)
st, ctxB = mock_gpu.create_context(devB, 0)
rec("create_context", st)

context_bypass = False
length_bug = False

# 2. context 归属校验：devA + ctxB 是跨上下文。
# 上一轮这里 flags=0 被拒绝；本轮尝试所有 flags，尤其是 PRIVILEGED。
for flags in (0, 1, 2, 3):
    st = do_escape(hAdapter, devA, ctxB, 0, flags, b"")
    if st == 0:
        context_bypass = True

valid_payload = u32le(8) + b"ABCDEFGH"
# 对其他 type 也用 PRIVILEGED 试探，避免只测到 type 0。
for t in range(1, 8):
    st = do_escape(hAdapter, devA, ctxB, t, 2, valid_payload)
    if st == 0:
        context_bypass = True
# type 0 用合法 payload 再试一次 PRIVILEGED。
st = do_escape(hAdapter, devA, ctxB, 0, 2, valid_payload)
if st == 0:
    context_bypass = True

# 3. 私有数据声明长度边界：payload 前 4 字节为 little-endian 声明长度。
data = b"ABCDEFGH"  # 实际私有数据 8 字节
payload_exact = u32le(len(data)) + data          # 声明 8，合法
payload_off = u32le(len(data) + 1) + data        # 声明 9，+1 边界
payload_inv = u32le(len(data) + 64) + data       # 声明 72，明显非法

for t in range(8):
    st_inv = do_escape(hAdapter, devA, ctxA, t, 0, payload_inv)
    st_off = do_escape(hAdapter, devA, ctxA, t, 0, payload_off)
    # 若明显非法被拒，但 +1 边界被接受，则触发长度校验边界误差。
    if st_inv != 0 and st_off == 0:
        length_bug = True

# 最大边界附近：payload 总长 1024 以内的合法/非法/+1 测试
st_small_exact = do_escape(hAdapter, devA, ctxA, 0, 0, payload_exact)
data_max_exact = b"B" * 1020
payload_max_exact = u32le(1020) + data_max_exact  # 4+1020=1024，合法最大
st_max_exact = do_escape(hAdapter, devA, ctxA, 0, 0, payload_max_exact)
if st_small_exact == 0 and st_max_exact != 0:
    length_bug = True

data_max = b"A" * 1019
payload_max_off = u32le(1020) + data_max  # 4+1019=1023，声明比实际多 1
payload_max_inv = u32le(1024) + data_max  # 4+1019=1023，明显非法
st_max_inv = do_escape(hAdapter, devA, ctxA, 0, 0, payload_max_inv)
st_max_off = do_escape(hAdapter, devA, ctxA, 0, 0, payload_max_off)
if st_max_inv != 0 and st_max_off == 0:
    length_bug = True

# 4. 清理
st = mock_gpu.destroy_context(ctxB)
rec("destroy_context", st)
st = mock_gpu.destroy_device(devB)
rec("destroy_device", st)
st = mock_gpu.destroy_context(ctxA)
rec("destroy_context", st)
st = mock_gpu.destroy_device(devA)
rec("destroy_device", st)
st = mock_gpu.close_adapter(hAdapter)
rec("close_adapter", st)

reached = context_bypass or length_bug
notes = "context_bypass=%s length_boundary=%s" % (
    "true" if context_bypass else "false",
    "true" if length_bug else "false",
)
calls_json = ", ".join(['{"api": "%s", "status": %d}' % (api, st) for api, st in calls])
print('CPG_RESULT {"reached": %s, "calls": [%s], "notes": "%s"}' % (
    "true" if reached else "false",
    calls_json,
    notes,
))