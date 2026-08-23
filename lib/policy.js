// dsh-guardwall · 策略引擎
// 风险分 → 动作映射：
//   risk >= blockThreshold  → block（拦截，返回 isError）
//   risk >= warnThreshold   → warn（放行 + 日志警告 + 审计）
//   else                    → record（只审计）
// 白名单：按 (ruleId + 精确工具名) 临时放行；默认仅当前进程有效。

export class Policy {
  constructor(opts = {}) {
    this.blockThreshold = 7
    this.warnThreshold = 4
    this.setThresholds(opts.blockThreshold ?? 7, opts.warnThreshold ?? 4)
    this.whitelist = new Map() // key: `${ruleId}::${toolPattern}` -> { until }
    this._state = null
  }

  async load(state) {
    this._state = state
    if (Array.isArray(state?.whitelist)) {
      const now = Date.now()
      for (const w of state.whitelist) {
        if (w.until > now) this.whitelist.set(`${w.rule}::${w.tool}`, w)
      }
    }
    return this
  }

  /** 是否命中白名单（rule + tool 都匹配，且未过期） */
  isWhitelisted(ruleId, tool) {
    const now = Date.now()
    for (const [key, w] of this.whitelist) {
      if (now > w.until) { this.whitelist.delete(key); continue }
      if (w.rule === ruleId && (w.tool === '*' || w.tool === tool)) return true
    }
    return false
  }

  /** 决定动作 */
  decide(risk, ruleId, tool) {
    if (this.isWhitelisted(ruleId, tool)) return 'record'
    if (risk >= this.blockThreshold) return 'block'
    if (risk >= this.warnThreshold) return 'warn'
    return 'record'
  }

  /** 加入白名单；仅在宿主显式提供可信 state store 时持久化。 */
  async whitelistRule(ruleId, tool, minutes) {
    if (typeof ruleId !== 'string' || !/^[A-Z][A-Z0-9_-]{1,31}$/.test(ruleId)) {
      throw new Error('invalid whitelist rule id')
    }
    if (typeof tool !== 'string' || !tool.trim() || tool === '*') {
      throw new Error('whitelist requires one exact tool name; wildcard is not allowed')
    }
    if (!Number.isFinite(minutes) || minutes < 1 || minutes > 60) {
      throw new Error('whitelist duration must be between 1 and 60 minutes')
    }
    const until = Date.now() + minutes * 60_000
    this.whitelist.set(`${ruleId}::${tool}`, { rule: ruleId, tool, until })
    if (this._state) {
      this._state.whitelist = [...this.whitelist.values()]
      await this._state.save()
    }
  }

  listWhitelist() {
    return [...this.whitelist.values()].map((w) => ({ ...w, until: new Date(w.until).toISOString() }))
  }

  config() {
    return { blockThreshold: this.blockThreshold, warnThreshold: this.warnThreshold }
  }

  /** 热更新阈值（热加载 config.json 时调用，不重启） */
  setThresholds(block, warn) {
    if (!Number.isFinite(block) || !Number.isFinite(warn) || block < 1 || block > 10 || warn < 1 || warn > 10) {
      throw new Error('thresholds must be finite numbers between 1 and 10')
    }
    if (warn > block) throw new Error('warnThreshold must be less than or equal to blockThreshold')
    this.blockThreshold = block
    this.warnThreshold = warn
    return this.config()
  }
}

/** 构造被拦截的工具结果（isError），附规则说明 */
export function blockedResult(hit) {
  return {
    content: [{
      type: 'text',
      text: `Error: dsh-guardwall 拦截了该调用（规则 ${hit.id} · 风险 ${hit.risk}/10）\n` +
        `原因：${hit.summary}\n` +
        `建议：${hit.advice}\n` +
        `如需放行，请用户明确确认后调用 guard_whitelist 临时放行（或调整策略阈值）。`,
    }],
    isError: true,
    error: { message: `blocked by dsh-guardwall rule ${hit.id}`, info: { name: 'GuardwallBlock', rule: hit.id, risk: hit.risk } },
  }
}
