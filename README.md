# dsh-guardwall

DeepSeek Harness 的安全插件：**安装前体检 + 运行时护栏**，装前把关、装后看门、全程留痕。

- **安装前体检**：权限清单 · 静态风险扫描 · A–D 信任评分 · 安装门禁（D 级拒绝）
- **运行时拦截**：危险工具调用直接拦截（破坏性命令、凭据、SSRF、反向 shell）
- **输出审计**：密钥/内网 IP/数据库串泄露检测
- **篡改检测审计**：HMAC 链式哈希 + 尾部 checkpoint，内容修改与日志截断可检测
- **热加载**：自定义规则与阈值改完秒级生效，不用重启
- **零第三方运行时依赖**：仅使用 Node 内置模块，减少依赖供应链攻击面

## 安装

```bash
dsh plugin --profile web add dsh-guardwall
```

验证挂载：

```bash
dsh --profile web --dump-config | grep -A2 'id: guardwall'
```

> npm 尚未发布时可用 GitHub 通道：`dsh plugin --profile web add "github:iiiweiii/dsh-guardwall#main"`

## 第一层 · 安装前体检

**"装这个插件 = 给了它什么权限？"** —— 装之前先回答：

```bash
npx guardwall check <spec>              # 体检输出报告
npx guardwall add <spec> [--force]      # 体检 → 门禁通过才安装
# spec：本地路径 / npm 包名 / github:owner/repo
```

四步体检：

1. **真实制品落地** —— npm 包以 `--ignore-scripts` 安装到隔离临时目录，GitHub 引用检出精确 ref；拿不到源码就不做放行结论
2. **权限清单** —— 静态分析源码，列出插件访问的**文件路径**（~/.ssh、.env、云凭据）、**执行的命令**（rm、curl、sudo）、**连接的域名**（正常 API / SSRF 元数据 / 遥测端点）
3. **静态风险扫描** —— 依赖树 + 危险模式（eval、动态执行、密钥读取、SSRF 目标、无约束递归删除、混淆载荷、安装脚本）
4. **信任评分与门禁** —— 五维评分；D 级拒绝（`--force` 放行）、C 级警告、A/B 放行

对话里问 Agent"这个插件安全吗"会调用 `guard_check` 工具。HTTP 接口默认关闭，见下方安全配置。

### 批量压测：前 120 高星插件

按 stars 取 awesome-dsh-plugin 前 120 个插件全量体检，覆盖率 91%（110/120），
校准了评分阈值并修复多种误判（skill 类插件、提示注入、GitHub 元数据、源码未装依赖等）：

<img src="assets/batch-vetting-report.svg" alt="dsh-guardwall 对 120 个高星插件的批量体检结果" width="720">

批量工具：`node scripts/batch-vet.mjs`（读 plugins.json，输出 batch-result.jsonl），
体检汇总见 [docs/batch-vetting-report.md](docs/batch-vetting-report.md)、
评分校准记录见 [docs/scoring-calibration.md](docs/scoring-calibration.md)。

## 第二层 · 运行时护栏

在工具调用执行前拦截高危参数（输入侧 `tools/execute`），监听输出泄露（输出侧 `tools/result`）。
Agent 被诱导执行 `rm -rf /` 时，调用被替换为：

```
Error: dsh-guardwall 拦截了该调用（规则 SEC-001 · 风险 10/10）
原因：破坏性删除/格式化/磁盘写入
建议：禁止对根目录/家目录/系统盘执行删除或格式化；如确需清理，改用回收站或限定路径后二次确认
如需放行，请管理员显式启用 Agent 白名单，并限定规则、精确工具名与有效期。
```

> 与社区安全插件的差异：44/51 个是静态扫描（对运行时动态构造的命令全盲）；运行时拦截的 7 个依赖
> cordis/dsh-tools（与恶意插件同框架）。本插件零第三方运行时依赖，并使用 HMAC 链式审计日志。

## 热加载 · 改规则不用重启

- **自定义规则**：`~/.dsh/cache/dsh-guardwall/rules.d/*.json`，保存即生效

  ```json
  [
    { "id": "MY-001", "direction": "input", "risk": 8,
      "re": "internal\\.corp\\d+\\.com", "summary": "禁止访问内网域名", "advice": "确认授权后访问" }
  ]
  ```
- **热配置**：同目录 `config.json` 改阈值立即生效：`{ "blockThreshold": 6, "warnThreshold": 3 }`
- 工具：`guard_reload` 手动刷新 · `guard_rules` 查看生效规则

## 规则表

输入侧（可拦截）：

| ID | 风险 | 检测 |
|---|---|---|
| SEC-001 | 10 | 破坏性删除/格式化/磁盘写入（rm -rf /、format、mkfs、dd 到块设备） |
| SEC-002 | 9 | 访问凭据/密钥文件（~/.ssh、.aws、.env、.netrc 等） |
| SEC-003 | 9 | 参数中出现疑似明文凭据（password=、sk-、AKIA、ghp_） |
| SEC-004 | 9 | SSRF：云元数据端点（169.254.169.254 / metadata 域名） |
| SEC-005 | 10 | 反向 shell / 下载执行管道（bash -i、nc -e、/dev/tcp、curl\|sh） |
| SEC-006 | 8 | 命令链注入（;rm、&&rm、反引号执行） |
| SEC-007 | 8 | 提权/权限变更（sudo su、chmod 777 /） |
| SEC-008 | 9 | 系统关键文件/设备写入（/etc/passwd、/boot、SYSTEM32） |
| SEC-009 | 5 | 对外发布操作（git push / npm publish，默认放行但审计） |

输出侧（只读审计）：

| ID | 风险 | 检测 |
|---|---|---|
| OUT-001 | 10 | 密钥/私钥泄露（sk-、AKIA、Bearer、BEGIN PRIVATE KEY） |
| OUT-002 | 6 | 内网 IP 输出 |
| OUT-003 | 8 | 带口令数据库连接串 |
| OUT-004 | 8 | 环境变量密钥 dump |
| OUT-005 | 7 | 公钥/证书/私密材料 |

## 策略与配置

默认：`risk >= 7` 拦截、`risk >= 4` 告警、其余记录。可在 `cordis.patch.yml` 的 `config` 调整：

```yaml
- insert:
    - id: guardwall
      name: dsh-guardwall
      config:
        blockThreshold: 7
        warnThreshold: 4
        dataDir: ~/.dsh/cache/dsh-guardwall
        failMode: closed             # 护栏初始化/扫描异常时拒绝执行
        allowAgentWhitelist: false   # 默认禁止 Agent 自助放行
```

## 工具

| 工具 | 用途 |
|---|---|
| `guard_check` | 安装前体检（权限/风险/评分/门禁建议） |
| `guard_status` | 拦截/告警/记录统计、审计链完整性、白名单 |
| `guard_whitelist` | 临时放行某规则；默认关闭，只接受精确工具名和 1–60 分钟 |
| `guard_reload` | 手动重载热加载规则与配置 |
| `guard_rules` | 查看生效规则与热加载状态 |

HTTP 接口默认不注册。如确需使用，配置 `enableHttpApi: true` 与非空 `httpToken`，请求携带 `Authorization: Bearer <token>`；HTTP 体检默认禁止本地路径，可由 `allowHttpLocalVet` 显式开启。

## 审计

数据落在 `~/.dsh/cache/dsh-guardwall/`：`audit-YYYY-MM-DD.jsonl`（每条含 prevHash + HMAC hash）、
`checkpoint-YYYY-MM-DD.json`（尾部锚点）、`chain.key`（链密钥，0600 权限）。内容修改、并发链分叉或尾部截断会让 `verify()` 返回失败。
该机制用于检测意外损坏和未持有密钥的修改；与 Agent 插件同一 OS 用户、可读取 `chain.key` 的攻击者不在其不可伪造威胁模型内。本地读写、无遥测；安装前体检仅为获取 npm/GitHub 制品而联网。

## 兼容性

- 真机验证：`@deepseek-ai/dsh 0.1.0-rc.5`（web profile，拦截/审计/接口实测通过）
- `tools/execute`（可拦截）、`tools/result`（只读）为宿主标准事件；接口走 `webServer.register`
- 预览版 API 可能变动，若失效先看 `--dump-config` 与宿主升级日志

## 路线图

- [ ] 白名单按 agent/会话隔离
- [ ] 高敏操作二次确认（approval 集成）
- [ ] 审计导出 + 周报
- [ ] npm 发布（`dsh plugin add dsh-guardwall` 一键安装）

## License

MIT
