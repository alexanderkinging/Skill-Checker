# Skill Checker 架构文档

## 目录结构

```
src/
├── index.ts              # Public API 导出
├── cli.ts                # CLI 入口 (commander)
├── types.ts              # 核心类型、评分、策略映射、reduceSeverity()
├── parser.ts             # SKILL.md 解析 (frontmatter YAML + body + 目录枚举)
├── scanner.ts            # 扫描编排器 (加载 checks → 去重 → 评分)
├── config.ts             # .skillcheckerrc.yaml 配置加载
├── checks/
│   ├── index.ts          # Check 模块注册与运行
│   ├── structural.ts     # STRUCT: 结构有效性
│   ├── content.ts        # CONT: 内容质量
│   ├── injection.ts      # INJ: 注入检测（最核心）
│   ├── code-safety.ts    # CODE: 代码安全
│   ├── supply-chain.ts   # SUPPLY: 供应链
│   ├── ioc.ts            # IOC 威胁情报 (SUPPLY-008~010)
│   └── resource.ts       # RES: 资源滥用
├── ioc/
│   ├── index.ts          # IOC 数据库加载与合并
│   ├── indicators.ts     # 内嵌种子数据 (C2 IP/恶意哈希/typosquat)
│   └── matcher.ts        # IOC 匹配逻辑 (哈希/IP/编辑距离)
├── reporter/
│   ├── terminal.ts       # 终端彩色输出
│   └── json.ts           # JSON + Hook 响应输出
└── utils/
    ├── entropy.ts        # Shannon 熵、Base64/Hex 检测
    ├── unicode.ts        # 零宽字符、RTL 覆盖、同形字检测
    ├── context.ts        # 上下文感知 (代码块/文档/namespace URI 判断)
    └── levenshtein.ts    # Levenshtein 编辑距离 (typosquat 检测用)

hook/                     # 项目根目录
├── install.ts            # Hook 安装脚本
└── skill-gate.sh         # PreToolUse hook 脚本 (fail-closed 设计)
```

## 评分体系

起始 100 分，按发现扣分：

| 严重度 | 扣分 |
|--------|------|
| CRITICAL | -25 |
| HIGH | -10 |
| MEDIUM | -3 |
| LOW | -1 |

下限 0 分。

| 等级 | 分数 | 含义 |
|------|------|------|
| A | 90-100 | 安全 |
| B | 75-89 | 小问题 |
| C | 60-74 | 建议审查 |
| D | 40-59 | 显著风险 |
| F | 0-39 | 不建议安装 |

## 审批策略

三级策略通过 `.skillcheckerrc.yaml` 配置：

- **strict**: CRITICAL→deny, HIGH→deny, MEDIUM→ask
- **balanced** (默认): CRITICAL→deny, HIGH→ask, MEDIUM→report
- **permissive**: CRITICAL→ask, HIGH→report, MEDIUM→report

支持按规则 ID 覆盖严重度或忽略规则。

## 上下文感知检测 (utils/context.ts)

纯关键字匹配产生大量误报（OOXML namespace URI、PPT 术语 placeholder、安装文档中的 sudo）。解决方案是通过上下文判断模式是否在执行语境中：

- `isNamespaceOrSchemaURI()`: URL 结构特征（路径含年份段、无文件扩展名、无查询参数）+ 行上下文（xmlns/namespace/schema 关键字）
- `isInNetworkRequestContext()`: 检查同行是否有 fetch/curl/wget 等网络请求代码
- `isInDocumentationContext()`: 向上查找 15 行内是否有 install/setup/prerequisite/getting-started/quickstart 等章节标题（用于 SUPPLY-003 双重降级和 SUPPLY-006 跳过）
- `isInCodeBlock()`: 跟踪 markdown ``` 围栏状态
- `isLicenseFile()`: 识别 LICENSE/COPYING/NOTICE 等文件
- `isLocalhostURL()`: 识别 localhost/127.0.0.1/[::1]

## 上下文感知严重度降级

### 设计原则

参照 OWASP ASVS、NIST SP 800-53、Gitleaks、Semgrep、Bandit、SonarQube 等行业标准：

- 永不自动抑制发现，只调整严重度
- false negative 比 false positive 更危险
- fail-closed：不确定时当作不安全处理
- LLM Skill 特殊性：代码块中的模式仍可能被 LLM 模仿，只能降级不能抑制

### reduceSeverity() (types.ts)

降级映射: CRITICAL→HIGH, HIGH→MEDIUM, MEDIUM→LOW, LOW→LOW
安全下限: CRITICAL 来源永不低于 MEDIUM
返回: `{ severity, reducedFrom, annotation }` 三元组，message 追加 `[reduced: reason]`

### 代码块降级规则

仅 8 条规则在 markdown 代码块内降级:

| 规则 | 原始 | 降级后 |
|------|------|--------|
| CODE-003 (rm -rf) | CRITICAL | HIGH |
| CODE-004 (requests.get) | HIGH | MEDIUM |
| CODE-006 (process.env) | MEDIUM | LOW |
| CODE-016 (persistence) | HIGH | MEDIUM |
| SUPPLY-001 (MCP server ref) | HIGH | MEDIUM |
| SUPPLY-003 (npm/pip install) | HIGH | MEDIUM (or LOW in doc code block) |
| SUPPLY-004 (Non-HTTPS URL) | HIGH/MEDIUM | 降一级 |
| SUPPLY-006 (git clone) | MEDIUM | LOW |

SUPPLY-004 额外排除: LICENSE 文件 + localhost URL。

SUPPLY-003 支持双重上下文降级：当安装命令同时在代码块内且位于文档标题（install/setup/prerequisite/getting-started/quickstart）之下时，从 HIGH 直接降至 LOW。

SUPPLY-006 在文档上下文中直接跳过（不生成发现），在代码块内从 MEDIUM 降至 LOW。

### STRUCT-006 脚本 vs 二进制文件

脚本文件（.sh/.bash/.ps1/.bat/.cmd）为 LOW 严重度（内容已被 CODE/SUPPLY/INJ 规则扫描）。
二进制文件（.exe/.dll/.wasm 等）和安装程序（.com/.msi）保持 HIGH。

### 永不降级的规则

- CODE-001 (eval/exec), CODE-002 (shell execution) — LLM 可能模仿
- CODE-005 (file write) — 路径写入始终可疑
- CODE-007~015 — 编码/熵/混淆/凭证/反向 shell 等
- INJ-* 全部 — 注入检测零上下文豁免（含 INJ-010 社会工程学 4 子类）
- RES-* 全部 — 资源滥用与上下文无关
- IOC 匹配 — 二值判断

### 同文件同规则去重 (scanner.ts)

去重键: `ruleId + title + sourceFile`，保留组内最高严重度，设置 `occurrences` 计数。title 参与去重确保同 ID 不同子类（如 CODE-016 的 9 个持久化类型、CODE-013 的多种凭证类型）不会被错误合并。

## 特殊检测逻辑

### CODE-002 shell 执行检测

`platform.system()` 是 Python 只读系统信息查询，通过 `SHELL_EXEC_FALSE_POSITIVES` 列表排除。`subprocess.run()` 等实际 shell 执行仍正确标记为 CRITICAL。

### IOC 威胁情报 (ioc/)

内嵌种子数据 + 可选外部覆盖文件 (`~/.config/skill-checker/ioc-override.json`)：

- SUPPLY-007: 可疑域名检测（5 类分类 + 上下文感知严重度）
- SUPPLY-008: 已知恶意 skill 文件 SHA-256 哈希匹配
- SUPPLY-009: 已知 C2 服务器 IP 地址匹配（排除私有/保留地址）
- SUPPLY-010: Typosquat 名称检测（精确匹配 + Levenshtein 编辑距离 ≤ 2）

#### SUPPLY-007 域名分类与上下文感知

域名按威胁类型分为 5 类（`CategorizedDomains`）：
- `exfiltration`: 数据外泄服务 (webhook.site, requestbin.com 等)
- `tunnel`: 临时隧道/端口转发 (ngrok.io, serveo.net 等)
- `oast`: 安全测试/OAST (interact.sh, dnslog.cn 等)
- `paste`: 匿名粘贴/代码托管 (pastebin.com, ghostbin.com 等)
- `c2`: 已知 C2 基础设施 (evil.com, malware.com 等)

上下文感知严重度：

| 上下文 | 严重度 | 说明 |
|--------|--------|------|
| 与敏感操作组合 | CRITICAL | curl -d @file, pipe to shell, 敏感文件引用 |
| 普通提及 | HIGH | 默认严重度 |
| 代码块内 | MEDIUM | 可能是示例代码 |
| 文档上下文 | LOW | 安装/调试说明 |

### Parser 大文件处理

- ≤ 5MB: 全文读取
- \> 5MB: 头尾窗口扫描（各 512KB），中间用 `/* ... window gap ... */` 连接
- 所有大文件生成 warning，触发 STRUCT-008
- 哈希计算始终流式（64KB chunks）

## 扫描目标约束

Scanner 期望目标目录根部包含 `SKILL.md` 文件。当目标目录缺少 `SKILL.md` 时：

- Parser 返回空结构体（body 为空、frontmatter 缺失）
- STRUCT-001 触发 CRITICAL（fail-closed 设计）
- 非 skill 目录的扫描结果包含大量噪音，不具备参考价值

推荐用法：`skill-checker scan ./path/to/skill-directory/`
