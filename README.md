# dsh-guardwall

DeepSeek Harness 的**运行时安全护栏** —— 给 Agent 装上边界，而不是事后检查。

- **输入侧拦截**：在工具调用执行前扫描参数，命中高危规则（破坏性命令、凭据路径、SSRF 云元数据、反向 shell、命令链注入、提权）**直接拦截**并返回结构化错误
- **输出侧审计**：监听工具结果，检测密钥/私钥泄露、内网 IP、带口令数据库串、环境变量 dump，记录审计并告警
- **防篡改审计**：所有事件写入 **HMAC 链式哈希**审计日志，任何一条被篡改整条链失配——可出示的合规证明
- **零运行时依赖**：仅用 Node 内置模块（crypto/fs/path），自身无供应链风险

> 与社区 51 个安全插件的差异（调研结论）：44 个是静态扫描（对运行时动态构造的命令全盲）；
> 运行时拦截的 7 个都依赖 cordis/dsh-tools（与恶意插件同框架）。本插件零依赖 +
> 密码学链式审计收据 + 标准 `tools/execute` / `tools/result` 事件接入。

## 安装

```bash
dsh plugin --profile web add dsh-guardwall
```

重启 `dsh web` 后生效。验证：

```bash
dsh --profile web --dump-config | grep -A2 'id: guardwall'
```

## 拦截示例

Agent 被诱导执行 `rm -rf /` 时，工具调用会被替换为：

```
Error: dsh-guardwall 拦截了该调用（规则 SEC-001 · 风险 10/10）
原因：破坏性删除/格式化/磁盘写入
建议：禁止对根目录/家目录/系统盘执行删除或格式化；如确需清理，改用回收站或限定路径后二次确认
如需放行，请用户明确确认后调用 guard_whitelist 临时放行（或调整策略阈值）。
```

## 规则表

输入侧（`tools/execute` 前检查，可拦截）：

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

输出侧（`tools/result` 后审计，只读观察）：

| ID | 风险 | 检测 |
|---|---|---|
| OUT-001 | 10 | 密钥/私钥泄露（sk-、AKIA、Bearer、BEGIN PRIVATE KEY） |
| OUT-002 | 6 | 内网 IP 输出 |
| OUT-003 | 8 | 带口令数据库连接串 |
| OUT-004 | 8 | 环境变量密钥 dump |
| OUT-005 | 7 | 公钥/证书/私密材料 |

## 策略

默认：`risk >= 7` 拦截（block）、`risk >= 4` 放行但告警（warn）、其余仅记录（record）。
可在 `cordis.patch.yml` 的 `config` 调整：

```yaml
- insert:
    - id: guardwall
      name: dsh-guardwall
      config:
        blockThreshold: 7
        warnThreshold: 4
        dataDir: ~/.dsh/cache/dsh-guardwall
```

## 工具

| 工具 | 用途 |
|---|---|
| `guard_status` | 今日拦截/告警/记录统计、最近事件、审计链完整性（防篡改证明）、白名单 |
| `guard_whitelist` | 临时放行某规则（rule + tool 模式 + 分钟数），用户明确确认误报时使用 |

审计接口：`GET /plugins/dsh-guardwall/audit`（JSON：统计 + 链完整性 + 最近 20 条）。

## 审计日志格式

数据落在 `~/.dsh/cache/dsh-guardwall/`：

```
audit-YYYY-MM-DD.jsonl   每日追加（每条含 prevHash + HMAC hash）
chain.key                链密钥（首次生成，0600 权限）
```

`verify()` 重新校验整条链：任何一条被篡改 → 返回 `{ok:false, brokenAt:n}`。
**篡改即暴露**，这就是"不可抵赖"的审计收据。

## 权限与数据

- 本地读写 `~/.dsh/cache/dsh-guardwall/`；无网络调用、无遥测
- 拦截动作只影响 Agent 的工具调用结果，不修改宿主配置

## 兼容性

- 真机验证：`@deepseek-ai/dsh 0.1.0-rc.5`（web profile，拦截/审计/接口实测通过）
- `tools/execute`（可拦截）、`tools/result`（只读）为宿主标准事件，见
  `packages/core/tools/src/index.ts`；接口走 `webServer.register`（与 dshmarket 同款）
- 预览版 API 可能变动，若失效先看 `--dump-config` 与宿主升级日志

## 路线图

- [ ] 白名单按 agent/会话隔离
- [ ] 自定义规则（用户 YAML 规则表）
- [ ] 高敏操作二次确认（approval 集成）
- [ ] 审计导出 + 周报

## License

MIT
