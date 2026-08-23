// dsh-guardwall · DeepSeek Harness 运行时安全护栏 + 篡改检测审计
//
// 定位：给 Agent 装"护栏"，不是记账本。
//   输入侧：tools/execute 钩子，扫描工具参数（SEC 规则），命中高危 → 直接拦截
//   输出侧：tools/result 监听，扫描工具结果（OUT 规则），泄露 → 审计 + 告警
//   审计：HMAC 链式哈希 + checkpoint，内容修改/尾部截断可检测
//
// 与社区既有安全插件的差异（调研结论）：
//   - 44/51 个安全插件是静态扫描（对运行时动态构造的命令全盲）
//   - 运行时拦截的 7 个依赖 cordis/dsh-tools（与恶意插件同框架）
//   - 本插件零 npm 依赖（仅 node:crypto/fs/path），自身供应链风险最小
//   - 密码学链式审计收据（在 chain.key 未泄露的威胁模型下检测篡改）
//
// 兼容性声明：基于 @deepseek-ai/dsh 0.1.0-rc.7（2026-08-19）；
// 真机验证于 0.1.0-rc.5。tools/execute / tools/result 为宿主标准事件
// （见 packages/core/tools/src/index.ts）。

import { AuditChain, summarize } from './lib/audit.js'
import { Policy, blockedResult } from './lib/policy.js'
import { scanArguments, scanOutput } from './lib/rules.js'
import { vet, gateMessage } from './lib/vet/index.js'
import { HotLoader } from './lib/hot.js'
import { timingSafeEqual } from 'node:crypto'

export const name = 'dsh-guardwall'
export const inject = ['tools']

const DEFAULTS = {
  blockThreshold: 7,
  warnThreshold: 4,
  dataDir: '~/.dsh/cache/dsh-guardwall',
  failMode: 'closed',
  allowAgentWhitelist: false,
  enableHttpApi: false,
  httpToken: null,
  allowHttpLocalVet: false,
}

export function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...(config || {}) }
  const log = (level, msg) => {
    try { ctx.logger?.[level]?.('[dsh-guardwall] ' + msg) } catch { /* ignore */ }
  }

  // —— 组装核心模块 ——
  const audit = new AuditChain(cfg.dataDir)
  const policy = new Policy({ blockThreshold: cfg.blockThreshold, warnThreshold: cfg.warnThreshold })
  // 热加载：rules.d/*.json 自定义规则 + config.json 热阈值（改完秒级生效，不用重启）
  const hot = new HotLoader(cfg.dataDir, {
    onReload: ({ config, errors }) => {
      try {
        policy.setThresholds(config.blockThreshold, config.warnThreshold)
      } catch { /* 阈值非法时保持旧值 */ }
      if (errors.length) log('warn', 'hot-reload partial: ' + errors.join('; '))
      else log('info', 'hot-reload ok: ' + hot.statusInfo().customRules + ' custom rules')
    },
  })
  let ready = false
  let initError = null

  const initPromise = (async () => {
    await audit.init()
    // Whitelists are intentionally process-local until the host provides an
    // approval-bound state store; persisting an Agent-granted bypass is unsafe.
    await policy.load(null)
    await hot.init()
    ready = true
    log('info', 'ready, audit dir: ' + audit.dir + ' | hot rules: ' + hot.statusInfo().customRules)
  })()
  void initPromise.catch((e) => {
    initError = e
    log('warn', 'init failed: ' + e.message)
  })

  const appendAudit = async (entry) => {
    try {
      await audit.append(entry)
      return true
    } catch (e) {
      log('warn', 'audit write failed: ' + e.message)
      return false
    }
  }

  const unavailable = (reason) => blockedResult({
    id: 'GUARD-UNAVAILABLE', risk: 10,
    summary: '安全护栏未就绪，已按 fail-closed 策略拒绝执行',
    advice: reason || '检查 dsh-guardwall 日志与数据目录权限后重试',
  })

  // —— 输入侧拦截（tools/execute）—— 使用热规则集
  ctx.on('tools/execute', async (exec, next) => {
    if (!ready) {
      try { await initPromise } catch { /* handled below */ }
      if (!ready) {
        if (cfg.failMode === 'open') return next()
        return unavailable(initError?.message)
      }
    }
    try {
      const hits = scanArguments(exec.arguments, hot.rules().input)
      if (!hits.length) return next()
      const top = hits[0]
      const action = policy.decide(top.risk, top.id, exec.name)
      if (action === 'block') {
        await appendAudit({
          action, rule: top.id, risk: top.risk, tool: exec.name,
          agent: exec.agent?.id ?? null,
          sample: top.sample,
          detail: { summary: top.summary, advice: top.advice, hits: hits.map((h) => h.id) },
        })
        log('warn', `BLOCK ${exec.name} ← ${top.id} (${top.summary})`)
        return blockedResult(top)
      }
      // warn / record：放行但审计
      await appendAudit({
        action, rule: top.id, risk: top.risk, tool: exec.name,
        agent: exec.agent?.id ?? null,
        sample: top.sample,
        detail: { summary: top.summary, hits: hits.map((h) => h.id) },
      })
      if (action === 'warn') log('warn', `WARN ${exec.name} ← ${top.id} (${top.summary})`)
      return next()
    } catch (e) {
      log('warn', 'input-scan error: ' + e.message)
      return cfg.failMode === 'open' ? next() : unavailable(e.message)
    }
  })

  // —— 输出侧审计（tools/result，只读观察）—— 使用热规则集
  ctx.on('tools/result', (exec, result) => {
    if (!ready) return
    try {
      const hits = scanOutput(result, hot.rules().output)
      if (!hits.length) return
      const top = hits[0]
      void appendAudit({
        action: 'warn', rule: top.id, risk: top.risk, tool: exec.name,
        agent: exec.agent?.id ?? null,
        sample: top.sample,
        detail: { summary: top.summary, hits: hits.map((h) => h.id) },
      }).then((written) => {
        if (!written) return
        log('warn', `OUT ${exec.name} → ${top.id} (${top.summary})`)
      })
    } catch (e) { /* 审计失败不影响结果 */ }
  })

  // —— 工具：guard_status / guard_whitelist ——
  const register = (tool) => {
    try { ctx.tools?.register?.(tool) } catch (e) { log('warn', 'tool register failed: ' + e.message) }
  }

  register({
    name: 'guard_status',
    description:
      '查看 dsh-guardwall 安全护栏状态：今日拦截/告警/记录统计、最近审计事件、' +
      '审计链完整性校验（篡改/截断检测）、当前白名单。当用户问"安全护栏运行得怎么样""拦截了什么"时调用。',
    parameters: {},
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute() {
      const records = await audit.readToday()
      const integrity = await audit.verify()
      return {
        stats: audit.summary(),
        integrity,
        recent: records.slice(-8).map(summarize),
        whitelist: policy.listWhitelist(),
        config: policy.config(),
      }
    },
  })

  register({
    name: 'guard_whitelist',
    description:
      '临时放行 dsh-guardwall 的某条规则（如 SEC-002）对某个工具（如 read_file）的拦截。' +
      '默认关闭，只有管理员显式开启后才能调用；每次只能放行一个精确工具名。',
    parameters: {
      rule: { type: 'string', description: '规则 ID，如 SEC-002（用 guard_status 查看）' },
      tool: { type: 'string', description: '精确工具名，不允许 *' },
      minutes: { type: 'number', default: 30, description: '放行时长（1-60 分钟）' },
    },
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      if (!cfg.allowAgentWhitelist) {
        return { ok: false, error: 'Agent 白名单默认关闭；需由管理员在插件配置中显式启用 allowAgentWhitelist' }
      }
      if (!args?.rule) return { ok: false, error: '需要 rule 参数' }
      const tool = args.tool
      const minutes = args.minutes ?? 30
      const rule = hot.rules().input.find((item) => item.id === args.rule)
      if (!rule) return { ok: false, error: '未知或非输入侧规则: ' + args.rule }
      try {
        await policy.whitelistRule(args.rule, tool, minutes)
      } catch (e) {
        return { ok: false, error: e.message }
      }
      await appendAudit({
        action: 'record', rule: 'WHITELIST', risk: rule.risk, tool,
        agent: null, sample: null,
        detail: { summary: `临时放行 ${args.rule} 对 ${tool} ${minutes} 分钟` },
      })
      return { ok: true, added: { rule: args.rule, tool, minutes }, whitelist: policy.listWhitelist() }
    },
  })

  // —— 工具：guard_check（安装前体检）——
  register({
    name: 'guard_check',
    description:
      '对第三方 DSH 插件做安装前体检：权限清单（文件/命令/网络）、静态风险扫描（危险模式/依赖树）、' +
      '信任评分（A-D）与门禁建议。当用户想安装新插件、或问"这个插件安不安全""装它有什么权限"时调用。' +
      '参数 spec 支持：本地路径、npm 包名、github:owner/repo。',
    parameters: {
      spec: { type: 'string', description: '插件标识：本地路径 / npm 包名 / github:owner/repo' },
    },
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      if (!args?.spec) return { ok: false, error: '需要 spec 参数（本地路径 / npm 包名 / github:owner/repo）' }
      try {
        const v = await vet(args.spec)
        await audit.append({
          action: 'record', rule: 'VET', risk: 0, tool: 'guard_check',
          agent: null, sample: args.spec.slice(0, 120),
          detail: { summary: `体检 ${v.manifest.name} → ${v.score.grade}（${v.score.score}）`, gate: v.gate },
        })
        return {
          ok: true,
          spec: args.spec,
          package: v.manifest,
          gate: v.gate,
          verdict: gateMessage(v),
          score: { score: v.score.score, grade: v.score.grade, dimensions: v.score.dimensions },
          permissions: { maxSeverity: v.permissions.maxSeverity, human: v.permissions.human, files: v.permissions.files.slice(0, 8), commands: v.permissions.commands.slice(0, 8), network: v.permissions.network.slice(0, 8) },
          staticScan: { findingCount: v.staticScan.findingCount, maxSeverity: v.staticScan.maxSeverity, audit: v.staticScan.audit, topFindings: v.staticScan.findings.slice(0, 10) },
          sourceFiles: v.sourceFiles,
        }
      } catch (e) {
        return { ok: false, error: e.message }
      }
    },
  })

  // —— 工具：guard_reload / guard_rules（热加载配套）——
  register({
    name: 'guard_reload',
    description:
      '手动重载 dsh-guardwall 的热加载规则与配置（rules.d/*.json 自定义规则 + config.json 阈值）。' +
      '当用户说"重新加载规则""应用自定义规则"时调用；文件保存后通常已自动生效，此工具用于强制刷新与查看状态。',
    parameters: {},
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute() {
      const r = await hot.reload()
      await audit.append({
        action: 'record', rule: 'HOT', risk: 0, tool: 'guard_reload',
        agent: null, sample: null,
        detail: { summary: `热重载: ${r.customRules} 条自定义规则${r.errors.length ? '，部分失败' : ''}` },
      })
      return { ok: r.ok, errors: r.errors, status: hot.statusInfo(), config: hot.config() }
    },
  })

  register({
    name: 'guard_rules',
    description:
      '查看 dsh-guardwall 当前生效的检测规则（内置 + 自定义热加载规则）与热加载状态。' +
      '当用户问"现在有哪些规则在生效""自定义规则加载了吗"时调用。',
    parameters: {},
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute() {
      const rules = hot.rules()
      return {
        status: hot.statusInfo(),
        config: hot.config(),
        input: rules.input.map((r) => ({ id: r.id, risk: r.risk, summary: r.summary, custom: r.custom || false })),
        output: rules.output.map((r) => ({ id: r.id, risk: r.risk, summary: r.summary, custom: r.custom || false })),
      }
    },
  })

  // —— 可选 HTTP 接口：默认关闭，启用时必须配置 bearer token ——
  if (cfg.enableHttpApi && cfg.httpToken) try {
    const json = (response, code, data) => {
      response.writeHead(code, { 'content-type': 'application/json; charset=utf-8' })
      response.end(JSON.stringify(data))
    }
    const authorized = (request) => {
      const supplied = String(request.headers?.authorization || '').replace(/^Bearer\s+/i, '')
      const expected = String(cfg.httpToken)
      const a = Buffer.from(supplied)
      const b = Buffer.from(expected)
      return a.length === b.length && timingSafeEqual(a, b)
    }
    const registerRoute = (hostCtx) => {
      hostCtx.webServer.register({
        kind: 'exact',
        path: '/plugins/dsh-guardwall/audit',
        handler: async (request, response) => {
          if (!authorized(request)) return json(response, 401, { error: 'unauthorized' })
          if (request.method !== 'GET') { response.writeHead(405, { allow: 'GET' }); response.end(); return }
          const records = await audit.readToday()
          const integrity = await audit.verify()
          json(response, 200, { stats: audit.summary(), integrity, recent: records.slice(-20).map(summarize) })
        },
      })
      hostCtx.webServer.register({
        kind: 'exact',
        path: '/plugins/dsh-guardwall/vet',
        handler: async (request, response) => {
          if (!authorized(request)) return json(response, 401, { error: 'unauthorized' })
          if (request.method !== 'GET') { response.writeHead(405, { allow: 'GET' }); response.end(); return }
          try {
            const url = new URL(request.url, 'http://localhost')
            const spec = url.searchParams.get('spec')
            if (!spec) return json(response, 400, { error: 'missing spec' })
            if (!cfg.allowHttpLocalVet && (/^(?:\.|\/|~)/.test(spec) || /^[A-Za-z]:[\\/]/.test(spec))) {
              return json(response, 403, { error: 'local path vetting is disabled over HTTP' })
            }
            const v = await vet(spec)
            json(response, 200, v)
          } catch (e) {
            json(response, 400, { error: e.message })
          }
        },
      })
    }
    if (typeof ctx.inject === 'function') {
      ctx.inject(['webServer'], registerRoute)
    } else {
      ctx.webServer?.register?.({
        kind: 'exact', path: '/plugins/dsh-guardwall/audit',
        handler: async (request, response) => {
          if (!authorized(request)) return json(response, 401, { error: 'unauthorized' })
          return json(response, 200, { stats: audit.summary() })
        },
      })
    }
  } catch (e) {
    log('warn', 'HTTP API registration failed: ' + e.message)
  }
  else if (cfg.enableHttpApi) {
    log('warn', 'HTTP API not registered: httpToken is required')
  }

  return { audit, policy, hot }
}
