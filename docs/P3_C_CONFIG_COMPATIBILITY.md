# P3-C 配置兼容性合同与差异审查

本说明对应 P3-C 基线 `8d33ae4c16285d15c7486ce2cfda2f9658f022a4`。
只审查模型服务配置语义，不进行真实 API 请求，也不宣称任何模型当前可用。

## 1. 开始时的实际差异

`config/default.yaml` 在开始时已有三项未提交修改。经操作者后续明确授权，
这三项不含凭证的配置修改可以纳入本阶段提交；实现过程中不改写其原始字节。

| 字段 | HEAD 中的值 | 工作区中的值 | 字段真正含义 |
|---|---|---|---|
| `llm.model_name` | `deepseek-flash` | `CPG_LLM_MODEL_NAME` | 模型名称字符串，不是密钥 |
| `llm.api_base` | `https://api.deepseek.com` | `CPG_LLM_API_BASE` | 模型服务 API 基础地址字符串 |
| `llm.api_key_env` | `DEEPSEEK_API_KEY` | `CPG_LLM_API_KEY_ENV` | **保存 API Key 的环境变量名称**，不是 API Key 本身 |

工作区配置原始 SHA-256：
`15ea1f636e9f2846b45a6769a1d3accc0a2f1d9fdc9916ae2f8e1546d556e119`。
其余字段未发生用户修改。实际 `.env` 及凭证不进入 Git，不在本报告披露。

旧实现的 YAML 普通字符串不做变量展开；只有显式设置对应的进程环境变量或
项目 `.env` 后，`_apply_env_overrides()` 才会替换字段。因此三项裸 `CPG_*`
字符串在正常 `.env` 覆盖下可能可以工作，在离线测试主动清空环境、禁用 `.env`
时会保留为字面量。

## 2. 七项既有失败的确切原因

修改前在实际工作区执行 `python -m pytest -q tests/test_baseline.py`：
Windows 为 **19 PASS / 7 FAILED**，没有真实请求。
旧测试文件未修改，断言未削弱。

| 旧测试标识（均位于 `tests/test_baseline.py`） | 失败语义 |
|---|---|
| `TestConfiguration::test_default_configuration_and_project_paths` | `api_base` 是字面量 `CPG_LLM_API_BASE`，与已发布默认地址不相等 |
| `TestLLMConfigurationAndRetry::test_canonical_key_takes_priority_over_legacy_alias` | 密钥选择器误指 `CPG_LLM_API_KEY_ENV`；测试只设置 `DEEPSEEK_API_KEY`/`DEEPSEEK_KEY`，初始化失败 |
| `TestLLMConfigurationAndRetry::test_legacy_deepseek_key_is_accepted` | 同上，未进入已知 `DEEPSEEK_KEY` 别名兼容分支 |
| `TestLLMConfigurationAndRetry::test_403_and_404_are_not_retried` | 同上，尚未到达 Mock 的 403/404 响应 |
| `TestLLMConfigurationAndRetry::test_429_is_retried_with_bounded_attempts` | 同上，尚未到达 Mock 的 429 响应 |
| `TestLLMConfigurationAndRetry::test_retry_budget_stops_without_sleeping_after_final_failure` | 同上，尚未验证重试预算 |
| `TestLLMConfigurationAndRetry::test_per_call_override_keeps_other_configured_generation_limits` | 同上，尚未执行单次参数覆盖 |

这些结果不能用于推断真实 API 鉴权、模型可用性或网络质量。

## 3. 兼容方案与优先级

加载顺序保持为：进程环境优先加载 `.env`（`override=False`）→ 读取 YAML →
应用既有 `CPG_*` 显式覆盖 → 解析下述有限引用 → 既有类型与范围检查。

### 普通值

```yaml
llm:
  model_name: "my-model"
  api_base: "https://service.example.invalid/v1"
  api_key_env: "MY_PROVIDER_KEY"
```

普通字符串保持原样。任意大写名称、`$NAME`、`${NAME}`、字符串拼接内容均不
进行变量插值；自定义模型和地址不会在环境缺失时回退成默认服务。

### 显式引用（新增、推荐）

仅在 `llm.model_name`、`llm.api_base`、`llm.api_key_env` 支持：

```yaml
llm:
  model_name: {env: MY_MODEL_SETTING, default: "my-model"}
  api_base: {env: MY_ENDPOINT_SETTING}
  api_key_env: {env: MY_KEY_SELECTOR, default: "MY_PROVIDER_KEY"}
```

环境变量名必须符合 `[A-Za-z_][A-Za-z0-9_]*`。引用目标未设置且无 `default`
时明确失败；目标已设置为空字符串时也失败，不用默认值掩盖空配置。
默认值和解析结果必须是非空字符串。拒绝未知键和错误类型。
不递归展开，不执行 shell。标准 `CPG_LLM_*` 覆盖优先于显式引用。

`api_key_env` 的解析结果仍然是**密钥变量名**：例如 `MY_KEY_SELECTOR=MY_PROVIDER_KEY`；
LLM 客户端随后读取 `MY_PROVIDER_KEY`。不要把真实 API Key 写入 YAML 或
`CPG_LLM_API_KEY_ENV`。

### 精确历史占位符兼容

只有上表三个**字段与同名占位符完全匹配**时启用兼容：若没有该字段的标准环境
覆盖，分别采用已发布默认值，并产生中文警告及可机器读取诊断
`LEGACY_PLACEHOLDER_DEFAULT`。例如把 `CPG_LLM_API_BASE` 放到 `model_name`
不会触发兼容。这不是任意环境变量名的隐式展开。

兼容行为不修改 YAML 文件；有 `CPG_LLM_*` 实际覆盖时保留覆盖值原样，
不会二次解释为引用。确需把某个兼容占位符作为普通字符串，可以显式写：

```yaml
llm:
  model_name: {literal: "CPG_LLM_MODEL_NAME"}
```

`ConfigLoader.configuration_diagnostics` 只记录 `field` 与 `code`，不记录配置值、
密钥、引用变量内容。现有 `ConfigLoader(config_path)`、属性和 `get()` 接口不变。

## 4. 自定义服务与迁移

最少迁移可以完全保留当前 YAML，继续在不跟踪的 `.env` 设置完整服务三元组：

```dotenv
CPG_LLM_MODEL_NAME=my-model
CPG_LLM_API_BASE=https://service.example.invalid/v1
CPG_LLM_API_KEY_ENV=MY_PROVIDER_KEY
MY_PROVIDER_KEY=replace-locally
```

进程变量仍优先于 `.env`。发布默认配置也兼容这组覆盖。
不要将示例凭证提交 Git。缺失实际密钥仍由 `LLMClient` 在请求前拒绝；本阶段不
改变供应商密钥隔离规则、不把第三方服务失败降级成其他供应商请求。
如后续希望消除兼容警告，可由操作者主动把 YAML 改为普通值或显式引用。

## 5. 离线验证与能力边界

新增 `tests/test_config_compatibility.py` 验证 37 项：精确兼容、普通字符串、
显式引用/默认值/缺失/空值/类型、优先级、不递归、无敏感值诊断、
工作区文件不改写、模拟自定义 `.env` 与 Mock 构造器。

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_baseline.py tests/test_config_compatibility.py
```

```bash
/home/pocdev/.venvs/cuda-poc-generator/bin/python -m pytest -q tests/test_baseline.py tests/test_config_compatibility.py
```

修复后 Windows 与 WSL 针对性回归各 **63 PASS / 0 FAILED**，其中旧测试 26 项、
新增 37 项；七个原失败均在实际工作区当前 YAML 上恢复通过。
另在 Windows 对实际用户 YAML 与实际 `.env` 进行不披露值的只读检查：
逐字段核对已设置的标准覆盖与最终配置相等，并在 Mock 构造器下核对模型、
地址及密钥缺失前置拒绝行为；**PASS，真实 API 请求为 0**。
双环境全量发布回归、实际配置回归与未检查项目分别记录于
[P3_C_VALIDATION.md](P3_C_VALIDATION.md)。

测试使用隔离环境及虚构凭证，`.env` 测试使用临时文件；Mock 不执行 `invoke`。
真实模型名称是否可用、真实请求鉴权与费用均为 **NOT_CHECKED**。
生产使用仍应明确确认所选服务和密钥归属。
