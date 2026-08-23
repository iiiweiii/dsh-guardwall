// dsh-guardwall · 热加载引擎
// 让"经常改的东西"改完秒级生效，不用重启 dsh：
//   rules.d/*.json   自定义检测规则（热加载）
//   config.json      热配置（blockThreshold / warnThreshold / whitelist 扩展）
// 实现：fs.watch 监听 + debounce 重载；全部零依赖，只读本机目录。
//
// 用法：
//   const hot = new HotLoader(dataDir, { onReload })
//   await hot.init()            // 读初始状态
//   hot.rules()                 // 当前生效规则集 { input, output }
//   hot.config()                // 当前热配置
//   hot.reload()                // 手动重载（guard_reload 工具调用）

import { promises as fs } from 'node:fs'
import { watch as fsWatch } from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { buildRuleSet, parseCustomRule } from './rules.js'

function expandHome(p) {
  if (!p) return p
  if (p === '~') return os.homedir()
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(os.homedir(), p.slice(2))
  return p
}

const HOT_CONFIG_DEFAULTS = {
  blockThreshold: 7,
  warnThreshold: 4,
}

export class HotLoader {
  constructor(dataDir, opts = {}) {
    this.dir = expandHome(dataDir) || path.join(os.homedir(), '.dsh', 'cache', 'dsh-guardwall')
    this.rulesDir = path.join(this.dir, 'rules.d')
    this.configFile = path.join(this.dir, 'config.json')
    this.onReload = opts.onReload || (() => {})
    this._rules = buildRuleSet()
    this._config = { ...HOT_CONFIG_DEFAULTS }
    this._watchers = []
    this._debounce = null
    this.status = { watching: false, lastReload: null, lastError: null, customRules: 0 }
  }

  async init() {
    await fs.mkdir(this.rulesDir, { recursive: true })
    // 确保 config.json 存在（watcher 需要目标文件存在才能监听）
    try {
      await fs.access(this.configFile)
    } catch {
      await fs.writeFile(this.configFile, '{}\n', 'utf8')
    }
    await this.reload()
    this._startWatching()
    return this
  }

  rules() { return this._rules }
  config() { return this._config }
  statusInfo() { return { ...this.status, dir: this.dir, rulesDir: this.rulesDir } }

  /** 重载规则与热配置（手动或 watch 触发共用） */
  async reload() {
    const errors = []
    const customInput = []
    const customOutput = []

    // 1) rules.d/*.json
    let files = []
    try { files = await fs.readdir(this.rulesDir) } catch { /* 目录不存在忽略 */ }
    const jsonFiles = files.filter((f) => f.endsWith('.json')).sort()
    for (const f of jsonFiles) {
      try {
        const raw = JSON.parse(await fs.readFile(path.join(this.rulesDir, f), 'utf8'))
        const arr = Array.isArray(raw) ? raw : [raw]
        for (const item of arr) {
          const rule = parseCustomRule(item)
          if (rule.direction === 'input') customInput.push(rule)
          else customOutput.push(rule)
        }
      } catch (e) {
        errors.push(`${f}: ${e.message}`)
      }
    }

    // 2) config.json（热阈值）. Build a complete candidate snapshot first;
    // editors commonly expose a partially-written file to fs.watch.
    let cfg = null
    try {
      const raw = JSON.parse(await fs.readFile(this.configFile, 'utf8'))
      cfg = {
        blockThreshold: raw.blockThreshold ?? HOT_CONFIG_DEFAULTS.blockThreshold,
        warnThreshold: raw.warnThreshold ?? HOT_CONFIG_DEFAULTS.warnThreshold,
      }
      if (!Number.isFinite(cfg.blockThreshold) || !Number.isFinite(cfg.warnThreshold) ||
          cfg.blockThreshold < 1 || cfg.blockThreshold > 10 ||
          cfg.warnThreshold < 1 || cfg.warnThreshold > 10 ||
          cfg.warnThreshold > cfg.blockThreshold) {
        throw new Error('thresholds must be 1-10 and warnThreshold <= blockThreshold')
      }
    } catch (e) {
      errors.push(`config.json: ${e.message}`)
    }

    // Last-known-good semantics: one malformed rule/config must never replace
    // the active protection set with defaults or a partial snapshot.
    if (errors.length === 0) {
      this._rules = buildRuleSet(customInput, customOutput)
      this._config = cfg
    }
    this.status = {
      watching: this.status.watching,
      lastReload: new Date().toISOString(),
      lastError: errors.length ? errors.join('; ') : null,
      customRules: errors.length ? this.status.customRules : customInput.length + customOutput.length,
      files: jsonFiles.length,
    }
    this.onReload({ rules: this._rules, config: this._config, errors })
    return { ok: errors.length === 0, errors, customRules: this.status.customRules }
  }

  /** 启动 fs.watch 监听（rules.d 目录 + config.json），Windows 兼容 */
  _startWatching() {
    const schedule = () => {
      clearTimeout(this._debounce)
      this._debounce = setTimeout(() => {
        void this.reload()
      }, 300)
    }
    try {
      const w1 = fsWatch(this.rulesDir, schedule)
      w1.on('error', () => { /* 忽略 */ })
      this._watchers.push(w1)
    } catch { /* 目录不可监听时忽略 */ }
    try {
      const w2 = fsWatch(this.configFile, schedule)
      w2.on('error', () => { /* 忽略 */ })
      this._watchers.push(w2)
    } catch { /* config.json 尚不存在时忽略（reload 后可能创建） */ }
    this.status.watching = this._watchers.length > 0
  }

  /** 卸载时关闭 watcher（Cordis 可逆 effect） */
  dispose() {
    clearTimeout(this._debounce)
    this._debounce = null
    for (const w of this._watchers) {
      try { w.close() } catch { /* 忽略 */ }
    }
    this._watchers = []
    this.status.watching = false
  }
}
