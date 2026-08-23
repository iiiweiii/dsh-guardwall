// Runtime boundary regression tests with a minimal DSH context mock.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { apply } from '../index.js'

let pass = 0, fail = 0
function ok(cond, msg) {
  if (cond) { pass++; console.log('  PASS', msg) }
  else { fail++; console.log('  FAIL', msg) }
}

function mockContext() {
  const handlers = new Map()
  const tools = new Map()
  return {
    handlers,
    registered: tools,
    logger: { info() {}, warn() {} },
    on(event, handler) { handlers.set(event, handler) },
    tools: { register(tool) { tools.set(tool.name, tool) } },
  }
}

console.log('--- fail-closed enforcement ---')
const dir = mkdtempSync(path.join(tmpdir(), 'guardwall-runtime-'))
const ctx = mockContext()
const state = apply(ctx, { dataDir: dir })
const execute = ctx.handlers.get('tools/execute')
let executed = false
let result = await execute({ name: 'run_shell', arguments: { command: 'rm -rf /' } }, () => {
  executed = true
  return { ok: true }
})
ok(result?.isError === true && executed === false, '危险调用被拦截')

state.audit.append = async () => { throw new Error('disk full') }
executed = false
result = await execute({ name: 'run_shell', arguments: { command: 'rm -rf /' } }, () => {
  executed = true
  return { ok: true }
})
ok(result?.isError === true && executed === false, '审计写失败时仍保持拦截')

const badRoot = path.join(dir, 'not-a-directory')
writeFileSync(badRoot, 'x', 'utf8')
const brokenCtx = mockContext()
apply(brokenCtx, { dataDir: badRoot })
executed = false
result = await brokenCtx.handlers.get('tools/execute')({ name: 'safe_tool', arguments: {} }, () => {
  executed = true
  return { ok: true }
})
ok(result?.isError === true && executed === false, '初始化失败时默认 fail-closed')

console.log('--- whitelist boundary ---')
const whitelist = ctx.registered.get('guard_whitelist')
const disabled = await whitelist.execute({ rule: 'SEC-001', tool: 'run_shell', minutes: 5 })
ok(disabled.ok === false, 'Agent 白名单默认关闭')

let threw = false
try { await state.policy.whitelistRule('SEC-001', '*', 30) } catch { threw = true }
ok(threw, '拒绝全工具通配白名单')
threw = false
try { state.policy.setThresholds(4, 7) } catch { threw = true }
ok(threw, '拒绝 warnThreshold 高于 blockThreshold')

state.hot.dispose()
rmSync(dir, { recursive: true, force: true })
console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail ? 1 : 0)
