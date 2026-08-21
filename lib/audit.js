// dsh-guardwall · 密码学审计日志
// HMAC 链式哈希防篡改：
//   每条记录 hash = HMAC-SHA256(chainKey, prevHash + canonical(record))
//   篡改任何一条 → 其后所有 hash 失配 → verify() 返回 false
// 链密钥首次生成后持久化在 ~/.dsh/cache/dsh-guardwall/chain.key（0600）
// 全部数据只落本机，零遥测。

import { createHmac, createHash, randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import os from 'node:os'

function expandHome(p) {
  if (!p) return p
  if (p === '~') return os.homedir()
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(os.homedir(), p.slice(2))
  return p
}

export class AuditChain {
  constructor(dataDir) {
    this.dir = expandHome(dataDir) || path.join(os.homedir(), '.dsh', 'cache', 'dsh-guardwall')
    this.key = null
    this._prevHash = null
    this.stats = { block: 0, warn: 0, record: 0 }
  }

  async init() {
    await fs.mkdir(this.dir, { recursive: true })
    const keyFile = path.join(this.dir, 'chain.key')
    try {
      this.key = await fs.readFile(keyFile)
    } catch {
      this.key = randomBytes(32)
      await fs.writeFile(keyFile, this.key, { mode: 0o600 })
    }
    // 启动时读取今天文件最后一条的 hash 作为链尾，续接
    const last = await this._lastRecord()
    this._prevHash = last?.hash || null
    return this
  }

  _dayFile(date = new Date()) {
    const y = date.getFullYear()
    const m = String(date.getMonth() + 1).padStart(2, '0')
    const d = String(date.getDate()).padStart(2, '0')
    return path.join(this.dir, `audit-${y}-${m}-${d}.jsonl`)
  }

  /** 链式 HMAC：prevHash + body 规范化 → 新 hash */
  _hash(prevHash, body) {
    const payload = `${prevHash ?? ''}${body}`
    return createHmac('sha256', this.key).update(payload, 'utf8').digest('hex')
  }

  /**
   * 追加一条审计记录。
   * @param {object} entry { ts, action, rule, risk, tool, agent, sample, detail }
   * @returns 写入的记录（含 hash）
   */
  async append(entry, date = new Date()) {
    const body = JSON.stringify({
      ts: entry.ts || new Date().toISOString(),
      action: entry.action,          // block | warn | record
      rule: entry.rule || null,      // SEC-xxx / OUT-xxx
      risk: entry.risk ?? 0,
      tool: entry.tool || null,
      agent: entry.agent || null,
      sample: entry.sample || null,
      detail: entry.detail || null,
    })
    const hash = this._hash(this._prevHash, body)
    const record = JSON.parse(body)
    record.hash = hash
    record.prevHash = this._prevHash
    await fs.appendFile(this._dayFile(date), JSON.stringify(record) + '\n', 'utf8')
    this._prevHash = hash
    this.stats[entry.action] = (this.stats[entry.action] || 0) + 1
    return record
  }

  async _lastRecord() {
    try {
      const raw = await fs.readFile(this._dayFile(), 'utf8')
      const lines = raw.split('\n').filter(Boolean)
      if (!lines.length) return null
      return JSON.parse(lines[lines.length - 1])
    } catch {
      return null
    }
  }

  /** 读取今天全部记录 */
  async readToday() {
    try {
      const raw = await fs.readFile(this._dayFile(), 'utf8')
      return raw.split('\n').filter(Boolean).map((l) => {
        try { return JSON.parse(l) } catch { return null }
      }).filter(Boolean)
    } catch {
      return []
    }
  }

  /**
   * 校验链完整性（防篡改证明）。
   * @returns { ok, brokenAt, total } brokenAt = 第一条失配记录的 index（-1 表示完好）
   */
  async verify() {
    const records = await this.readToday()
    let prev = null
    for (let i = 0; i < records.length; i++) {
      const r = records[i]
      const body = JSON.stringify({
        ts: r.ts, action: r.action, rule: r.rule ?? null,
        risk: r.risk ?? 0, tool: r.tool ?? null, agent: r.agent ?? null,
        sample: r.sample ?? null, detail: r.detail ?? null,
      })
      const expected = this._hash(prev?.hash ?? null, body)
      if (r.hash !== expected || r.prevHash !== (prev?.hash ?? null)) {
        return { ok: false, brokenAt: i, total: records.length }
      }
      prev = r
    }
    return { ok: true, brokenAt: -1, total: records.length }
  }

  summary() {
    return { ...this.stats, chainKey: this.key ? 'active' : 'missing' }
  }
}

/** 记录条目的规范化摘要（用于工具/接口展示，不含原始敏感内容） */
export function summarize(record) {
  return {
    ts: record.ts,
    action: record.action,
    rule: record.rule,
    risk: record.risk,
    tool: record.tool,
    summary: record.detail?.summary || null,
    sample: record.sample ? record.sample.replace(/[A-Za-z0-9]{20,}/g, (s) => s.slice(0, 8) + '…') : null,
  }
}
