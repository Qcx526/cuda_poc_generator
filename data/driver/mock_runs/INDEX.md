# Mock Benchmark 实验记录索引

Benchmark 版本：
- **v1** DLL `9cf8b3e5…`：mock-native-A / mock-native-B / mock-native-v2（作废，仅历史对照）
- **v2** DLL `cf8c619f…`：修复了"被拒调用仍记触发"的问题；此后实验必须用 v2

Benchmark 版本：
- **v1** DLL `9cf8b3e5…`：mock-native-A / mock-native-B / mock-native-v2（作废，仅历史对照）
- **v2** DLL `cf8c619f…`：修复了"被拒调用仍记触发"的问题；此后实验必须用 v2

> 注意：mock-native-A / mock-native-B 产生于旧 Runner（Python mock + 候选可写轨迹），
> 按 F5 审计标准**作废**，仅保留为历史对照，不得用于任何验收结论。

本文件只含索引与摘要；prompt/response/poc.py 本体在本地 data/driver/mock_runs/，未入库。

## mock-native-A
- round1  poc_sha256=4b4ac71c8d9f9d58  level=None  flaws=[]  trace=None
- round2  poc_sha256=1070c1c5c0870818  level=None  flaws=['AUTHZ_BYPASS']  trace=None

## mock-native-B
- round1  poc_sha256=8c8cf6ba99877aba  level=None  flaws=['AUTHZ_BYPASS', 'OOB_READ']  trace=None
- round2  poc_sha256=c2408ab55c8506ef  level=None  flaws=['AUTHZ_BYPASS', 'OOB_READ']  trace=None

## mock-native-v2
- round1  poc_sha256=5a5d19b07b40f422  level=CANDIDATE_EXECUTION_VERIFIED  flaws=['AUTHZ_BYPASS', 'OOB_READ']  trace=15
- round2  poc_sha256=ff1fc484fdead4ad  level=CANDIDATE_EXECUTION_VERIFIED  flaws=['AUTHZ_BYPASS', 'OOB_READ']  trace=42
