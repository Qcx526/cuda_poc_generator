import mock_gpu

# 针对上一轮的修改说明：
# 1. 上一轮 valid/cross 调用混在一起，无法区分“合法成功”与“归属校验被跳过”。
#    本轮对每个 type/flags 成对执行 valid 与 cross，只有 cross 返回 0 才判定归属绕过。
# 2. 上一轮未明确验证“私有数据声明长度”的边界误差。
#    本轮对 4 字节和 2 字节长度头分别测试：合法长度、差一长度、远端非法长度。
#    若“差一长度”成功而“远端非法长度”失败，则判定边界误差被实际触发。
# 3. 清理阶段仍按要求执行 destroy_context/destroy_device/close_adapter，并记录状态。

calls = []

def rec(api, status):
    calls.append((api, status))
    return status

def pack_le(n, width):
    return (n & ((1 << (8 * width)) - 1)).to_bytes(width, "little")

def call_escape(ad, dev, ctx, type_, flags, payload):
    st = mock_gpu.escape(ad, dev, ctx, type_, flags, payload)
    rec("escape", st)
    return st

def call_len(width, L, n, type_, flags):
    if L < width:
        return None
    if n < 0:
        return None
    header = pack_le(n, width)
    payload = header + b"\x00" * (L - width)
    return call_escape(a1, d1, c1, type_, flags, payload)

mock_gpu.reset()

# Setup A
st, a1 = mock_gpu.open_adapter("A")
rec("open_adapter", st)
st, d1 = mock_gpu.create_device(a1)
rec("create_device", st)
st, c1 = mock_gpu.create_context(d1)
rec("create_context", st)

# Setup B（用于跨 context 归属测试）
st, a2 = mock_gpu.open_adapter("B")
rec("open_adapter", st)
st, d2 = mock_gpu.create_device(a2)
rec("create_device", st)
st, c2 = mock_gpu.create_context(d2)
rec("create_context", st)

ownership_bypass = False
length_bypass = False
notes_parts = []

# 1) context 归属校验绕过测试
for type_ in range(8):
    for flags in range(4):
        payload = b"\x00" * 16
        st_valid = call_escape(a1, d1, c1, type_, flags, payload)
        st_cross = call_escape(a1, d1, c2, type_, flags, payload)
        if st_cross == 0:
            ownership_bypass = True
            if len(notes_parts) < 10:
                notes_parts.append("cross-ctx ok t=%d f=%d" % (type_, flags))

# 2) 私有数据声明长度边界测试
# 4 字节长度头
ls4 = [4, 5, 8, 9, 16, 17, 32, 33, 64, 65, 128, 129, 256, 257, 512, 1024]
for type_ in range(8):
    for flags in (0, 2):
        for L in ls4:
            n_over1 = L - 4 + 1       # 比合法数据长度多 1
            st_over1 = call_len(4, L, n_over1, type_, flags)
            n_far = L + 100           # 远端非法
            st_far = call_len(4, L, n_far, type_, flags)
            if st_over1 == 0 and st_far != 0:
                length_bypass = True
                if len(notes_parts) < 10:
                    notes_parts.append("len4 off-by-one t=%d f=%d L=%d" % (type_, flags, L))
            n_total = L               # 未扣除头长度，也可能是边界问题
            st_total = call_len(4, L, n_total, type_, flags)
            if st_total == 0 and st_far != 0:
                length_bypass = True
                if len(notes_parts) < 10:
                    notes_parts.append("len4 total-accept t=%d f=%d L=%d" % (type_, flags, L))

# 2 字节长度头
ls2 = [2, 3, 4, 5, 8, 9, 16, 17, 32, 33, 64, 65, 128, 129, 256, 512, 1024]
for type_ in range(8):
    for flags in (0, 2):
        for L in ls2:
            n_over1 = L - 2 + 1
            st_over1 = call_len(2, L, n_over1, type_, flags)
            n_far = L + 100
            st_far = call_len(2, L, n_far, type_, flags)
            if st_over1 == 0 and st_far != 0:
                length_bypass = True
                if len(notes_parts) < 10:
                    notes_parts.append("len2 off-by-one t=%d f=%d L=%d" % (type_, flags, L))

# 清理
if c1:
    rec("destroy_context", mock_gpu.destroy_context(c1))
if d1:
    rec("destroy_device", mock_gpu.destroy_device(d1))
if a1:
    rec("close_adapter", mock_gpu.close_adapter(a1))
if c2:
    rec("destroy_context", mock_gpu.destroy_context(c2))
if d2:
    rec("destroy_device", mock_gpu.destroy_device(d2))
if a2:
    rec("close_adapter", mock_gpu.close_adapter(a2))

reached = bool(ownership_bypass or length_bypass)
if notes_parts:
    notes = "; ".join(notes_parts)
else:
    notes = "no bypass observed"

def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')

calls_json = "[" + ",".join(
    '{"api":"%s","status":%d}' % (esc(api), status)
    for api, status in calls
) + "]"

print('CPG_RESULT {"reached": %s, "calls": %s, "notes": "%s"}' % (
    str(reached).lower(), calls_json, esc(notes)
))