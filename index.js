// dsh-guardwall · DeepSeek Harness 运行时安全护栏 + 防篡改审计
//
// 定位：给 Agent 装"护栏"，不是记账本。
//   输入侧：tools/execute 钩子，扫描工具参数（SEC 规则），命中高危 → 直接拦截
//   输出侧：tools/result 监听，扫描工具结果（OUT 规则），泄露 → 审计 + 告警
//   审计：HMAC 链式哈希，任何一条被篡改整条链失配，可证明性审计
//
// 与社区既有安全插件的差异（调研结论）：
//   - 44/51 个安全插件是静态扫描（对运行时动态构造的命令全盲）
//   - 运行时拦截的 7 个依赖 cordis/dsh-tools（与恶意插件同框架）
//   - 本插件零 npm 依赖（仅 node:crypto/fs/path），自身供应链风险最小
//   - 密码学链式审计收据（防篡改），合规场景可出示
//
// 兼容性声明：基于 @deepseek-ai/dsh 0.1.0-rc.7（2026-08-19）；
// 真机验证于 0.1.0-rc.5。tools/execute / tools/result 为宿主标准事件
// （见 packages/core/tools/src/index.ts）。

import { AuditChain, summarize } from './lib/audit.js'
import { Policy, blockedResult } from './lib/policy.js'
import { INPUT_RULES, OUTPUT_RULES, scanArguments, scanOutput } from './lib/rules.js'

export const name = 'dsh-guardwall'
export const inject = ['tools']

const DEFAULTS = {
  blockThreshold: 7,
  warnThreshold: 4,
  dataDir: '~/.dsh/cache/dsh-guardwall',
}

export function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...(config || {}) }

  // —— 组装核心模块 ——
  const audit = new AuditChain(cfg.dataDir)
  const policy = new Policy({ blockThreshold: cfg.blockThreshold, warnThreshold: cfg.warnThreshold })
  let ready = false

  void (async () => {
    try {
      await audit.init()
      await policy.load({ save: () => policy._state?.save?.() })
      ready = true
      ctx.logger?.info?.('[dsh-guardwall] ready, audit dir: ' + audit.dir)
    } catch (e) {
      ctx.logger?.warn?.('[dsh-guardwall] init failed: ' + e.message)
    }
  })()

  const log = (level, msg) => {
    try { ctx.logger?.[level]?.('[dsh-guardwall] ' + msg) } catch { /* ignore */ }
  }

  // —— 输入侧拦截（tools/execute）——
  ctx.on('tools/execute', async (exec, next) => {
    if (!ready) return next()
    try {
      const hits = scanArguments(exec.arguments)
      if (!hits.length) return next()
      const top = hits[0]
      const action = policy.decide(top.risk, top.id, exec.name)
      if (action === 'block') {
        await audit.append({
          action, rule: top.id, risk: top.risk, tool: exec.name,
          agent: exec.agent?.id ?? null,
          sample: top.sample,
          detail: { summary: top.summary, advice: top.advice, hits: hits.map((h) => h.id) },
        })
        log('warn', `BLOCK ${exec.name} ← ${top.id} (${top.summary})`)
        return blockedResult(top)
      }
      // warn / record：放行但审计
      await audit.append({
        action, rule: top.id, risk: top.risk, tool: exec.name,
        agent: exec.agent?.id ?? null,
        sample: top.sample,
        detail: { summary: top.summary, hits: hits.map((h) => h.id) },
      })
      if (action === 'warn') log('warn', `WARN ${exec.name} ← ${top.id} (${top.summary})`)
      return next()
    } catch (e) {
      log('warn', 'input-scan error: ' + e.message)
      return next()
    }
  })

  // —— 输出侧审计（tools/result，只读观察）——
  ctx.on('tools/result', (exec, result) => {
    if (!ready) return
    try {
      const hits = scanOutput(result)
      if (!hits.length) return
      const top = hits[0]
      void audit.append({
        action: 'warn', rule: top.id, risk: top.risk, tool: exec.name,
        agent: exec.agent?.id ?? null,
        sample: top.sample,
        detail: { summary: top.summary, hits: hits.map((h) => h.id) },
      }).then(() => {
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
      '审计链完整性校验（防篡改证明）、当前白名单。当用户问"安全护栏运行得怎么样""拦截了什么"时调用。',
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
      '当用户明确确认某次拦截是误报、需要放行时调用。tool 可用 * 匹配全部工具。',
    parameters: {
      rule: { type: 'string', description: '规则 ID，如 SEC-002（用 guard_status 查看）' },
      tool: { type: 'string', default: '*', description: '工具名模式，* 匹配全部' },
      minutes: { type: 'number', default: 30, description: '放行时长（分钟）' },
    },
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      if (!args?.rule) return { ok: false, error: '需要 rule 参数' }
      await policy.whitelistRule(args.rule, args.tool || '*', args.minutes || 30)
      return { ok: true, added: { rule: args.rule, tool: args.tool || '*', minutes: args.minutes || 30 }, whitelist: policy.listWhitelist() }
    },
  })

  // —— 审计接口（webServer，参照 dshmarket 验证过的真实 API）——
  try {
    const json = (response, code, data) => {
      response.writeHead(code, { 'content-type': 'application/json; charset=utf-8' })
      response.end(JSON.stringify(data))
    }
    const registerRoute = (hostCtx) => {
      hostCtx.webServer.register({
        kind: 'exact',
        path: '/plugins/dsh-guardwall/audit',
        handler: async (request, response) => {
          if (request.method !== 'GET') { response.writeHead(405, { allow: 'GET' }); response.end(); return }
          const records = await audit.readToday()
          const integrity = await audit.verify()
          json(response, 200, { stats: audit.summary(), integrity, recent: records.slice(-20).map(summarize) })
        },
      })
    }
    if (typeof ctx.inject === 'function') {
      ctx.inject(['webServer'], registerRoute)
    } else {
      ctx.webServer?.register?.({
        kind: 'exact', path: '/plugins/dsh-guardwall/audit',
        handler: async (request, response) => json(response, 200, { stats: audit.summary() }),
      })
    }
  } catch { /* 路由可选 */ }

  return { audit, policy }
}
