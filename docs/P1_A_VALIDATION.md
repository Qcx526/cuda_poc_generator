# P1-A 交付与实际验收

开发基线为 `main@9a7bd531ace1177dfb2a7597f2dd6a7bf0e1b35e`。开始时本地main、HEAD、origin/main一致，工作区和暂存区干净。按用户要求直接在main开发，不创建feature branch或PR。Commit与推送结果见最终汇报及Git记录。

完整修改前后数据流、模型/函数合同、示例JSON和外部接口迁移见 [P1-A 合同](P1_A_CONTRACT.md)。P0历史审计保留为当时基线记录，不把旧“未实现schema”的描述当作当前实现。

## 实现与兼容性

- 新增七维归一化与诊断：原始字段、来源文件、JSON Pointer、精确字节SHA-256、字段状态和未验证资料标记；flat/wrapped兼容，明确冲突不选一方。
- 专家输出schema从严格Pydantic模型生成；完整JSON解析、必需字段/类型、有限数值范围、步骤ID和目标CVE校验。无效分析在专家、pipeline及生成器入口均被阻断。
- 保留完整SDK文本content原文：非法JSON及结构失败也保存原文；不strip、不改CRLF。供应商未返回文本时不生成假原文。
- 保留原Single-shot和`cuda_analysis_v1.json/cuda_poc_v1.py`；新增输入manifest、候选静态状态和调用报告；`GENERATED/STATIC_VALID/STATIC_INVALID/NOT_EXECUTED/NOT_VERIFIED`不混用。
- 输入检查在LLM初始化之前；失败报告与CLI非零退出；旧产物保留但不当当前成功，重复pipeline调用不追加嵌套CVE目录。
- 归一化字段用于RAG查询，短名/正式组件名和两种根因摘要都保留；RAG/Tavily接口与知识库算法保留。

六套案例、42个JSON全部通过，不改原始文件或测试样本。兼容性对照保留原`ANALYSIS` fixture、生成请求次数、静态纠正上限和原产物内容断言；P0测试只迁移Mock原文封装及新增产物清单，没有降低校验判据。

## 双环境实际结果

修改前Windows3.12.13与WSL3.10.12的原35测试均PASS。修改后两环境均使用已有独立venv，没有安装新依赖或修改CUDA/系统配置。

| 检查 | Windows Python3.12.13 | WSL Python3.10.12 | 限制 |
|---|---|---|---|
| 全量pytest | **107 PASS** | **107 PASS** | 全部离线，Mock模型/检索/宿主探测 |
| 全量unittest | **107 PASS** | **107 PASS** | 候选只保存与AST检查，不执行 |
| 核心依赖pip check | PASS | PASS | 使用P0 core/dev快照，未安装可选RAG/search |
| Ruff限定检查 | PASS | PASS | 原E9/F63/F7/F82规则，非完整风格或安全证明 |
| 无site-packages CLI help | PASS | PASS | 原CLI参数保留；非法输入实际CLI退出1已回归 |
| Python语法 | PASS | PASS（导入/回归） | Windows31个受控Python文件AST检查；既有escape警告保留 |
| 六案例/42JSON/来源hash | PASS | PASS | 结构检查，不证明CVE事实或受影响版本 |
| flat/wrapped等价、未知与冲突 | PASS | PASS | 同路径/明确共享字段检查，不作自然语言语义推断 |
| JSON/schema/步骤/CVE失败阻断 | PASS | PASS | 解析/结构错误不作结构纠正重试 |
| 合格Single-shot Mock生成 | PASS | PASS | 原文件名与成功dict/源码返回接口继续可用 |
| 生成失败/静态失败独立状态 | PASS | PASS | 始终NOT_EXECUTED/NOT_VERIFIED |
| raw首尾空白/Unicode/CRLF精确保留 | PASS | PASS | 保存SDK文本content，不含HTTP envelope或usage元数据 |
| 重复调用/stale产物保护 | PASS | PASS | 当前报告与旧文件hash分开，无文件删除 |
| Git ignore/私有文件索引规则 | PASS | PASS | 原P0三项真实Git检查继续通过 |
| 文档例子/链接/whitespace/限定敏感规则 | PASS | 同一受控源码 | 按提交前审查；不输出密钥或原文内容 |
| 真实模型API/Tavily | NOT_CHECKED | NOT_CHECKED | 未调用；付费模型调用成本为0 |
| 真实RAG模型/索引/检索 | NOT_CHECKED | NOT_CHECKED | 只Mock查询接口，没有模型下载 |
| GPU、nvcc编译、PoC执行/CVE验证 | NOT_CHECKED | NOT_CHECKED | 未执行任何候选或CUDA实验 |
| CVE公告/根因/版本真实性 | NOT_CHECKED | NOT_CHECKED | 资料仍input_assertion/unverified |

107项构成：原35项（基线26、CLI6、Git hygiene3）、输入22、分析34、pipeline/direct入口/RAG查询16。输入覆盖Unicode数字ID、非有限数和128层边界；分析逐一测试必需字段、未知字段/空白/类型、数值范围、步骤顺序，以及原文保留；pipeline覆盖真正parser→专家→生成器Mock整链和CLI失败状态。

修改期间复核发现并修正了输入Unicode数字格式与模型ASCII格式不一致、过深JSON无法序列化manifest，以及公开专家/生成器入口未自动绑定目标CVE的缺口。组件短名与正式名称在真实数据中不同，保留两者而非修改样例或人为判成相同。最终回归没有失败项。

语法审查仍记录两处既有escape警告：`code_generator.py`的Prompt中`\d`、`env_probe.py:532`的`\w`。pytest是否显示取决于解释器和缓存；它们未被隐藏或为了消除警告修改Prompt。两个SYSTEM Prompt的解析后完整字符串与P0基线一致。

## 变更文件

- `src/models/normalized_input.py`（新增）、`src/data_loader.py`：归一化、来源、诊断与新加载入口；原load_inputs保留。
- `src/models/analysis.py`、`src/models/__init__.py`：严格模型、共享目标解析、错误接口与导出。
- `src/llm_client.py`、`src/core_expert.py`：严格文本解析、原文携带、同源schema和失败阻断。
- `src/models/generation.py`（新增）、`src/code_generator.py`：独立候选状态、侧文件与公开入口保护；原静态检查算法保留。
- `src/pipeline.py`：完整合同链、延迟组件初始化、manifest/raw/状态报告和旧产物处理。
- `tests/test_input_normalization.py`、`tests/test_analysis_contract.py`、`tests/test_p1_pipeline.py`（新增）、`tests/test_baseline.py`：离线回归与必要接口迁移。
- `README.md`、`docs/P1_A_CONTRACT.md`、本文件：真实能力、接口示例、迁移和验收。

确认未变：六套输入、知识源、CUDA辅助库、tools、env_probe、旧input字段视图、CLI参数实现、pyproject/requirements/constraints、.env.example、ignore、VS Code配置。真实`.env`未写入，测试中项目真实dotenv加载被禁用；只有临时假dotenv用例。没有改HeteroPoCLab、稳定标签或旧提交。

## 能力边界与P1-B建议

输入与分析通过表示结构和目标一致，不证明根因正确、PoC可执行或CVE已触发。自定义字段与自然语言资料不作事实认证；原文文件是模型文本诊断，不是执行证据。原v1仍会覆盖当前元数据，尚无不可变实验存档、运行授权策略、WSL执行后端或目标oracle。

建议P1-B先做候选质量与可审阅性：

1. 在保留AST科学含义的前提下，用安全fixture改进作用域、导入及步骤标记检查；明确哪些规则只是提示、哪些规则阻断。
2. 针对已定位ELF字段宽度/进程退出状态等高风险helper逐项修复并以固定fixture验证，继续不执行漏洞样本。
3. 将Windows开发环境与WSL目标配置拆开，去掉硬编码SM7.5和默认架构冒充实测值，保留unknown及来源。
4. 记录候选生成原文/请求配置及静态纠正历史，增加输入大小与token预算；在原链上支持可重复审阅，不引入自动执行或新框架。

P1-A交付后停止下一阶段开发，等待用户审查。
