# 修复点（针对上一轮的具体失败）：
# 1) 上一轮前 6 次 escape 全部为 0xC000000D。若驱动把 payload 前 4 字节当作“私有数据声明长度”，
#    全零/空 payload 会让声明长度=0 或无法读取，直接命中参数非法路径，导致基准调用全部失败。
#    本轮先扫描 empty/zeros/fill/LE 长度头等多种 payload，选首个 status==0 的组合作为基准，
#    后续所有变异都基于该基准构造，避免用非法输入当参考。
# 2) 上一轮疑似部分调用复用了 reset 后的旧句柄。本轮严格 open_adapter -> create_device ->
#    create_context，测试期间不 reset、不销毁，最后统一清理。
# 3) context 归属测试改为受控的第二 device/context 与第二 adapter，并覆盖 flags=0/1/2/3，
#    专门检查 PRIVILEGED/ASYNC 等请求属性是否跳过归属校验。
# 4) 长度边界从单一 16 扩到 0..4、15..17、1024，并用 zeros 与 le_over/le_ff 做对照：
#    只有“超界声明被接受而正常声明被拒”或“短包(<4)被接受而 4 字节全零声明被拒”才判为触发。

import mock_gpu as g


def P(kind, n):
    if n < 0:
        n = 0
    if n > 1024:
        n = 1024
    if kind == "empty":
        return b""
    if kind == "zeros":
        return b"\x00" * n
    if kind == "fill10":
        return b"\x10" * n
    if kind == "fillff":
        return b"\xff" * n
    if kind == "le_avail":
        if n < 4:
            return b"\x00" * n
        return (n - 4).to_bytes(4, "little") + b"\x00" * (n - 4)
    if kind == "le_n":
        if n < 4:
            return b"\x00" * n
        return n.to_bytes(4, "little") + b"\x00" * (n - 4)
    if kind == "le_4":
        if n < 4:
            return b"\x00" * n
        return (4).to_bytes(4, "little") + b"\x00" * (n - 4)
    if kind == "le_over":
        if n < 4:
            return b"\x00" * n
        return (1024).to_bytes(4, "little") + b"\x00" * (n - 4)
    if kind == "le_ff":
        if n < 4:
            return b"\x00" * n
        return (0xFFFFFFFF).to_bytes(4, "little") + b"\x00" * (n - 4)
    return b"\x00" * n


def jesc(s):
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        else:
            out.append(ch)
    return "".join(out)


def main():
    calls = []

    def rec(api, st):
        calls.append((api, int(st)))

    parts = []
    reached_ctx = False
    reached_len = False

    g.reset()
    rec("reset", 0)

    st, hA = g.open_adapter("verify")
    rec("open_adapter", st)

    hD = 0
    hC = 0
    hD2 = 0
    hC2 = 0
    hA2 = 0
    hD3 = 0
    hC3 = 0

    base_kind = None
    base_type = 0
    ref_ok = False
    ctx_ev = []
    len_ev = {}
    over_ev = {}

    if st != 0 or hA == 0:
        parts.append("open_adapter failed")
    else:
        st, hD = g.create_device(hA)
        rec("create_device", st)
        if st != 0 or hD == 0:
            parts.append("create_device failed")
        else:
            st, hC = g.create_context(hD, 0)
            rec("create_context", st)
            if st != 0 or hC == 0:
                parts.append("create_context failed")
            else:
                # 先找能成功的基准 payload；不再直接使用全零 16 字节作为唯一基准。
                for kind in ["le_avail", "le_n", "fill10", "le_4",
                             "fillff", "zeros", "empty", "le_over", "le_ff"]:
                    st = g.escape(hA, hD, hC, 0, 0, P(kind, 16))
                    rec("escape", st)
                    if st == 0 and base_kind is None:
                        base_kind = kind

                if base_kind is None:
                    for t in range(1, 8):
                        st = g.escape(hA, hD, hC, t, 0, P("le_avail", 16))
                        rec("escape", st)
                        if st == 0 and base_kind is None:
                            base_kind = "le_avail"
                            base_type = t

                ref_ok = base_kind is not None
                if not ref_ok:
                    parts.append("baseline escape all failed; channel unusable")
                else:
                    parts.append("baseline=%s/type=%d" % (base_kind, base_type))
                    bp = P(base_kind, 16)

                    # ---- 漏洞(1)：context 归属校验 ----
                    st, hD2 = g.create_device(hA)
                    rec("create_device", st)
                    if st == 0 and hD2 != 0:
                        st, hC2 = g.create_context(hD2, 0)
                        rec("create_context", st)

                    if hD2 != 0:
                        if hC2 != 0:
                            ref2 = g.escape(hA, hD2, hC2, base_type, 0, bp)
                            rec("escape", ref2)

                        tests = [
                            ("cross_ctx_other_dev_f0", hA, hD2, hC, base_type, 0),
                            ("cross_ctx_other_dev_f1", hA, hD2, hC, base_type, 1),
                            ("cross_ctx_other_dev_f2", hA, hD2, hC, base_type, 2),
                            ("cross_ctx_other_dev_f3", hA, hD2, hC, base_type, 3),
                        ]
                        if hC2 != 0:
                            tests.append(("cross_ctx2_same_adapter_f0", hA, hD, hC2, base_type, 0))
                            tests.append(("cross_ctx2_same_adapter_f2", hA, hD, hC2, base_type, 2))

                        for name, x1, x2, x3, xt, xf in tests:
                            xst = g.escape(x1, x2, x3, xt, xf, bp)
                            rec("escape", xst)
                            ctx_ev.append((name, xst))

                        for name, xst in ctx_ev:
                            if xst == 0:
                                reached_ctx = True

                    # 跨 adapter 的归属检查
                    st, hA2 = g.open_adapter("verify2")
                    rec("open_adapter", st)
                    if st == 0 and hA2 != 0:
                        st, hD3 = g.create_device(hA2)
                        rec("create_device", st)
                        if st == 0 and hD3 != 0:
                            st, hC3 = g.create_context(hD3, 0)
                            rec("create_context", st)
                            if st == 0 and hC3 != 0:
                                for xt, xf in [(base_type, 0), (base_type, 2)]:
                                    xst = g.escape(hA2, hD3, hC, xt, xf, bp)
                                    rec("escape", xst)
                                    if xst == 0:
                                        reached_ctx = True

                    # ---- 漏洞(2)：私有数据声明长度边界 ----
                    if base_kind in ("le_avail", "le_n", "le_4", "le_over", "le_ff"):
                        scan_kinds = [base_kind, "zeros"]
                    elif base_kind == "zeros":
                        scan_kinds = ["zeros", "le_avail"]
                    else:
                        scan_kinds = [base_kind, "zeros"]

                    for n in [0, 1, 2, 3, 4, 8, 15, 16, 17, 1024]:
                        for kind in scan_kinds:
                            xst = g.escape(hA, hD, hC, base_type, 0, P(kind, n))
                            rec("escape", xst)
                            len_ev[(kind, n)] = xst

                    for n in [4, 8, 16, 17]:
                        for kind in ["le_over", "le_ff"]:
                            xst = g.escape(hA, hD, hC, base_type, 0, P(kind, n))
                            rec("escape", xst)
                            over_ev[(kind, n)] = xst

                    # 短包 (<4) 被接受，但 4 字节全零声明被拒 => 短包跳过声明校验
                    short_ok = False
                    for n in [0, 1, 2, 3]:
                        if len_ev.get(("zeros", n), 1) == 0:
                            short_ok = True
                    four_zero = len_ev.get(("zeros", 4), 1)
                    if short_ok and four_zero != 0:
                        reached_len = True

                    # 超界声明被接受，而同长度正常全零声明被拒 => 长度边界/溢出
                    for (kind, n), xst in over_ev.items():
                        if xst == 0 and len_ev.get(("zeros", n), 1) != 0:
                            reached_len = True

                    if base_kind in ("le_over", "le_ff"):
                        # 基准本身就是“超界声明”，说明长度校验已失效
                        reached_len = True

                    if reached_ctx:
                        parts.append("context ownership bypassed")
                    if reached_len:
                        parts.append("private length boundary bypassed")
                    if not reached_ctx and not reached_len:
                        parts.append("no bypass observed")

    # 清理：context -> device -> adapter，且测试期间绝不销毁句柄
    if hC3:
        rec("destroy_context", g.destroy_context(hC3))
    if hC2:
        rec("destroy_context", g.destroy_context(hC2))
    if hC:
        rec("destroy_context", g.destroy_context(hC))
    if hD3:
        rec("destroy_device", g.destroy_device(hD3))
    if hD2:
        rec("destroy_device", g.destroy_device(hD2))
    if hD:
        rec("destroy_device", g.destroy_device(hD))
    if hA2:
        rec("close_adapter", g.close_adapter(hA2))
    if hA:
        rec("close_adapter", g.close_adapter(hA))

    reached = reached_ctx or reached_len
    notes = "; ".join(parts) if parts else "no observation"
    calls_json = ", ".join(
        '{"api": "%s", "status": %d}' % (jesc(a), s) for a, s in calls
    )
    return 'CPG_RESULT {"reached": %s, "calls": [%s], "notes": "%s"}' % (
        "true" if reached else "false", calls_json, jesc(notes)
    )


print(main())