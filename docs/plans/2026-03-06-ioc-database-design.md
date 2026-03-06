# IOC 威胁情报数据库设计

> REQ-006 实现方案，2026-03-06

## 目标

为 Skill Checker 添加 IOC (Indicators of Compromise) 威胁情报能力，通过已知恶意特征匹配检测已知威胁。

## 数据结构

```typescript
interface IOCDatabase {
  version: string;           // "2026.03.06"
  updated: string;           // ISO date
  c2_ips: string[];          // 已知 C2 服务器 IP
  c2_cidrs: string[];        // C2 IP 段 (可选)
  malicious_hashes: Record<string, string>;  // SHA-256 → 描述
  malicious_domains: string[];               // 恶意域名 (补充 SUPPLY-007)
  typosquat: {
    known_patterns: string[];    // 已知仿冒名 ["clawhub1", "cllawhub"]
    protected_names: string[];   // 知名 skill 名 ["clawhub", "secureclaw"]
  };
  malicious_publishers: string[];  // 已知恶意发布者
}
```

## 文件结构

```
src/
├── ioc/
│   ├── index.ts          # loadIOC(): 加载内嵌数据 + 合并外部文件
│   ├── indicators.ts     # 内嵌种子数据 (DEFAULT_IOC)
│   └── matcher.ts        # IP/hash/typosquat 匹配逻辑
├── checks/
│   ├── ioc.ts            # 第 7 个 CheckModule (SUPPLY-008/009/010)
│   └── index.ts          # 注册 iocChecks
└── utils/
    └── levenshtein.ts    # 编辑距离算法
```

## 新增规则

| 规则 | 严重度 | 检测逻辑 |
|------|--------|---------|
| SUPPLY-008 | CRITICAL | 计算 skill 目录下所有文件 SHA-256，匹配 IOC 恶意哈希库 |
| SUPPLY-009 | CRITICAL | 从内容提取 IP 地址，匹配 IOC C2 IP 列表 |
| SUPPLY-010 | HIGH/CRITICAL | skill name 编辑距离匹配 protected_names (≤2) + known_patterns 精确匹配 |

## IOC 加载流程

1. 模块初始化时加载内嵌 DEFAULT_IOC
2. 检查 `~/.config/skill-checker/ioc-override.json` 是否存在
3. 如有外部文件，追加合并（不覆盖内嵌数据）
4. run() 方法中直接使用已加载的 IOC 数据

## SUPPLY-008: 恶意哈希匹配

- 对 skill 目录下每个文件计算 SHA-256
- 与 IOC 数据库中的 malicious_hashes 精确匹配
- 匹配到则报 CRITICAL，附带恶意描述

## SUPPLY-009: C2 IP 匹配

- 从 skill 全文提取所有 IPv4 地址 (不限于 URL)
- 排除 localhost (127.0.0.1) 和私有地址 (10.x, 172.16-31.x, 192.168.x)
- 与 IOC c2_ips 列表精确匹配
- 不与 SUPPLY-005 冲突 (SUPPLY-005 检测"IP 替代域名"行为，SUPPLY-009 检测"已知恶意 IP")

## SUPPLY-010: Typosquat 检测

两层策略：
1. 精确匹配 known_patterns → CRITICAL
2. 编辑距离匹配 protected_names (距离 1-2，排除完全匹配) → HIGH

使用 Levenshtein 距离算法，零外部依赖。

## 种子数据来源

基于公开威胁情报收集：
- ClawHavoc 攻击数据 (C2 IP、恶意 skill 哈希)
- 已知恶意 skill 名称模式
- 社区报告的恶意发布者

## 测试计划

- IOC 加载与合并测试
- SHA-256 哈希匹配测试
- C2 IP 匹配测试 (含私有地址排除)
- Typosquat 编辑距离测试
- 外部 IOC 文件合并测试
- 完整扫描集成测试
