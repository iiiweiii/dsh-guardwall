// dsh-guardwall · 密码学审计日志
// HMAC 链式哈希篡改检测：
//   每条记录 hash = HMAC-SHA256(chainKey, prevHash + canonical(record))
//   篡改任何一条 → 其后所有 hash 失配 → verify() 返回 false
// 链密钥首次生成后持久化在 ~/.dsh/cache/dsh-guardwall/chain.key（0600）
// 全部数据只落本机，零遥测。

import { createHmac, randomBytes } from 'node:crypto'
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
    this._day = null
    this._count = 0
    // All appends must observe the hash produced by the previous append.
    // fs.appendFile() is asynchronous, so concurrent tool events would
    // otherwise fork the chain by hashing the same parent.
    this._writeTail = Promise.resolve()
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
    // 启动时读取今天文件最后一条的 hash 作为链尾，续接，并与
    // 独立 checkpoint 对照以检测日志尾部截断/整文件删除。
    this._day = this._dayKey()
    const records = await this._readRecords()
    const last = records.at(-1)
    this._prevHash = last?.hash || null
    this._count = records.length
    const checkpoint = await this._readCheckpoint()
    if (checkpoint && (checkpoint.count !== this._count || checkpoint.lastHash !== this._prevHash)) {
      throw new Error('audit checkpoint mismatch: log may have been truncated or deleted')
    }
    if (!checkpoint && records.length) await this._writeCheckpoint()
    return this
  }

  _dayKey(date = new Date()) {
    const y = date.getFullYear()
    const m = String(date.getMonth() + 1).padStart(2, '0')
    const d = String(date.getDate()).padStart(2, '0')
    return `${y}-${m}-${d}`
  }

  _dayFile(date = new Date()) {
    return path.join(this.dir, `audit-${this._dayKey(date)}.jsonl`)
  }

  _checkpointFile(date = new Date()) {
    return path.join(this.dir, `checkpoint-${this._dayKey(date)}.json`)
  }

  _checkpointMac(day, count, lastHash) {
    return createHmac('sha256', this.key).update(JSON.stringify({ day, count, lastHash })).digest('hex')
  }

  async _readCheckpoint(date = new Date()) {
    try {
      const value = JSON.parse(await fs.readFile(this._checkpointFile(date), 'utf8'))
      const mac = this._checkpointMac(value.day, value.count, value.lastHash)
      if (mac !== value.mac) throw new Error('audit checkpoint authentication failed')
      return value
    } catch (e) {
      if (e?.code === 'ENOENT') return null
      throw e
    }
  }

  async _writeCheckpoint(date = new Date()) {
    const day = this._dayKey(date)
    const value = { day, count: this._count, lastHash: this._prevHash }
    value.mac = this._checkpointMac(value.day, value.count, value.lastHash)
    const target = this._checkpointFile(date)
    const temp = `${target}.${process.pid}.tmp`
    await fs.writeFile(temp, JSON.stringify(value) + '\n', { encoding: 'utf8', mode: 0o600 })
    await fs.rename(temp, target)
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
  append(entry, date = new Date()) {
    const operation = this._writeTail.then(() => this._append(entry, date))
    // Keep the queue usable after one failed write while still propagating the
    // failure to the caller that submitted that record.
    this._writeTail = operation.catch(() => {})
    return operation
  }

  async _append(entry, date) {
    const day = this._dayKey(date)
    if (day !== this._day) {
      this._day = day
      this._prevHash = null
      this._count = 0
    }
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
    this._count++
    await this._writeCheckpoint(date)
    this.stats[entry.action] = (this.stats[entry.action] || 0) + 1
    return record
  }

  async _readRecords(date = new Date()) {
    try {
      const raw = await fs.readFile(this._dayFile(date), 'utf8')
      return raw.split('\n').filter(Boolean).map((l) => {
        try { return JSON.parse(l) } catch { return null }
      }).filter(Boolean)
    } catch {
      return []
    }
  }

  /** 读取今天全部记录 */
  async readToday() {
    await this._writeTail
    return this._readRecords()
  }

  /**
   * 校验链完整性（篡改/截断检测）。
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
    let checkpoint
    try {
      checkpoint = await this._readCheckpoint()
    } catch (e) {
      return { ok: false, brokenAt: records.length, total: records.length, reason: e.message }
    }
    if (!checkpoint && records.length) {
      return { ok: false, brokenAt: records.length, total: records.length, reason: 'checkpoint missing' }
    }
    if (checkpoint && (checkpoint.count !== records.length || checkpoint.lastHash !== (prev?.hash ?? null))) {
      return { ok: false, brokenAt: records.length, total: records.length, reason: 'checkpoint mismatch' }
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
