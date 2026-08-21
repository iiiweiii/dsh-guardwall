// dsh-guardwall · 热加载冒烟测试（改规则/配置秒级生效，不重启）
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { HotLoader } from '../lib/hot.js'
import { parseCustomRule, buildRuleSet } from '../lib/rules.js'
import { Policy } from '../lib/policy.js'

let pass = 0, fail = 0
function ok(cond, msg) {
  if (cond) { pass++; console.log('  PASS', msg) }
  else { fail++; console.log('  FAIL', msg) }
}

console.log('--- parseCustomRule ---')
const r = parseCustomRule({ id: 'MY-001', direction: 'input', risk: 8, re: 'evil\\.com', summary: '自定义测试规则' })
ok(r.id === 'MY-001' && r.direction === 'input' && r.re instanceof RegExp && r.custom === true, '自定义规则编译成功')
ok(r.re.test('http://evil.com/x'), '正则生效（命中 evil.com）')
let threw = false
try { parseCustomRule({ id: 'X', direction: 'bad', risk: 5, re: 'a' }) } catch { threw = true }
ok(threw, '非法 direction 抛错')
ok(buildRuleSet([r], []).input.length >= 1, 'buildRuleSet 合并自定义规则')

console.log('--- HotLoader：文件热重载 ---')
const dir = mkdtempSync(path.join(tmpdir(), 'gw-hot-'))
const rulesDir = path.join(dir, 'rules.d')
const configFile = path.join(dir, 'config.json')
const { mkdirSync } = await import('node:fs')
mkdirSync(rulesDir, { recursive: true })

let reloadCount = 0
const hot = new HotLoader(dir, { onReload: () => { reloadCount++ } })
await hot.init()
ok(hot.rules().input.some((x) => x.id === 'SEC-001'), '初始加载内置规则')
ok(hot.config().blockThreshold === 7, '默认热阈值 7')
ok(hot.status.watching === true, 'watcher 已启动')

// 写入自定义规则文件 → 等 watcher 触发
writeFileSync(path.join(rulesDir, 'my.json'), JSON.stringify([
  { id: 'MY-001', direction: 'input', risk: 8, re: 'evil\\.com', summary: '自定义', advice: '勿访问' },
  { id: 'MY-OUT', direction: 'output', risk: 6, re: 'leak-\\d+', summary: '输出泄露' },
]), 'utf8')

// 等待 debounce(300ms) + watcher 触发
await new Promise((res) => setTimeout(res, 900))
ok(hot.status.customRules === 2, `热加载 2 条自定义规则（实际 ${hot.status.customRules}）`)
ok(hot.rules().input.some((x) => x.id === 'MY-001'), '自定义 input 规则已生效')
ok(hot.rules().output.some((x) => x.id === 'MY-OUT'), '自定义 output 规则已生效')
ok(reloadCount >= 1, `watcher 触发重载（${reloadCount} 次）`)

// 热配置：改 config.json → 阈值生效
writeFileSync(configFile, JSON.stringify({ blockThreshold: 6, warnThreshold: 3 }), 'utf8')
await new Promise((res) => setTimeout(res, 900))
ok(hot.config().blockThreshold === 6, '热配置 blockThreshold 6 生效')
const policy = new Policy()
policy.setThresholds(hot.config().blockThreshold, hot.config().warnThreshold)
ok(policy.config().blockThreshold === 6, 'policy.setThresholds 同步热阈值')

// 手动 reload + 错误处理
const bad = path.join(rulesDir, 'bad.json')
writeFileSync(bad, '{ invalid json', 'utf8')
await new Promise((res) => setTimeout(res, 900))
ok(hot.status.lastError && hot.status.lastError.includes('bad.json'), '坏文件被记录不崩溃')
rmSync(bad)
const res2 = await hot.reload()
ok(res2.ok === true && res2.customRules === 2, '手动 reload 恢复正常')

hot.dispose()
ok(hot.status.watching === false, 'dispose 后 watcher 关闭')

rmSync(dir, { recursive: true, force: true })
console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail ? 1 : 0)
