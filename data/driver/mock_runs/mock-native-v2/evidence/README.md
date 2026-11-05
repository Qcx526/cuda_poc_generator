# mock-native-v2 证据包

**标签：REPRODUCED_UNDER_F5_R2** —— 两轮 poc.py 用 F5-R2 的 Runner 重新执行；
原始生成轮次的 prompt/response 仍保留在本地（未入库），此处只记哈希。

| 轮 | level | native | 对象 | escape | 有效escape | oracle | flaws |
|---|---|---|---|---|---|---|---|
| 1 | TRIGGER_CONFIRMED | True | True | True | True | True | AUTHZ_BYPASS,OOB_READ |
| 2 | TRIGGER_CONFIRMED | True | True | True | True | True | AUTHZ_BYPASS,OOB_READ |

## DLL

`9cf8b3e55df3705eacd37275f6f3802b6b10910e5169c68822e7cfadb39a6a8a`

## 文件哈希（SHA256）

- round1/prompt.txt  7bab5aa8841f8291485ded275dd0e06b327bb523018a9ddf5e1fc0a9df327754
- round1/response.txt  ef162224a11788ba95998d632d98e4d6d5d5005916155052e7e42cc08aeebdb9
- round1/poc.py  5a5d19b07b40f422b586fa1de8b130083828adfa60445e43eab67dc787f41c08
- round2/prompt.txt  67bc723e97ea4a785b77dcd56f65097e6b01747ba506b8835da40a47d8892c17
- round2/response.txt  54d8ad1b6bac277f28614f6b762f05e23111fd06e2879bb10dfa55e91c76f55e
- round2/poc.py  ff1fc484fdead4adc8cb2c9319e26d8060bb49435b99dd995214a241c15f1ebc

## 复现

```bash
python -m tools.driver.mock_bench data/driver/mock_runs/mock-native-v2/round1/poc.py
python -m pytest -q -m native_required tests/test_mock_bench_native.py
```

## 产物说明

- `trace_roundN.json`：Runner 从 server 取回的权威轨迹（含每步 op/参数/状态/对象存活）。
- `verdict_roundN.json`：自述、Runner 观测、Oracle 判定三源分离的原始记录。
- `summary.json`：两轮汇总 + DLL SHA256。