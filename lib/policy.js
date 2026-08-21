// dsh-guardwall · 策略引擎
// 风险分 → 动作映射：
//   risk >= blockThreshold  → block（拦截，返回 isError）
//   risk >= warnThreshold   → warn（放行 + 日志警告 + 审计）
//   else                    → record（只审计）
// 白名单：按 (ruleId + tool 模式) 临时放行，持久化在 state.json。

export class Policy {
  constructor(opts = {}) {
    this.blockThreshold = opts.blockThreshold ?? 7
    this.warnThreshold = opts.warnThreshold ?? 4
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

  /** 加入白名单（持久化） */
  async whitelistRule(ruleId, tool, minutes) {
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
