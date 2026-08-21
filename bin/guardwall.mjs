#!/usr/bin/env node
// dsh-guardwall · 安装前门禁 CLI
// 用法：
//   guardwall check <spec>           体检并输出报告（本地路径 / npm 包名 / github:owner/repo）
//   guardwall add  <spec> [--force]  体检 → 门禁通过才执行 dsh plugin add，D 级拒绝（除非 --force）
//   guardwall add  <spec> --dsh <cmd> 指定 dsh 命令（默认从 PATH 找，找不到则尝试仓库路径）
//
// 零依赖：仅 node 内置模块。

import { promises as fs } from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { vet, gateMessage } from '../lib/vet/index.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(await fs.readFile(path.join(__dirname, '..', 'package.json'), 'utf8'))

function printReport(v) {
  const line = '─'.repeat(56)
  console.log(line)
  console.log(`  dsh-guardwall 体检报告  v${pkg.version}`)
  console.log(line)
  console.log(`  包: ${v.manifest.name}@${v.manifest.version}`)
  console.log(`  来源: ${v.location.kind}  ${v.location.value}`)
  console.log(`  License: ${v.manifest.license}   依赖: ${v.manifest.depCount}   源码文件: ${v.sourceFiles}`)
  console.log(`  信任评分: ${v.score.score}/100  等级: ${v.score.grade}`)
  console.log(line)
  console.log('  [权限清单]')
  console.log(indent(v.permissions.human))
  if (v.staticScan.findingCount) {
    console.log(`  [静态风险] ${v.staticScan.findingCount} 项发现（最高风险 ${v.staticScan.maxSeverity}/10）`)
    for (const f of v.staticScan.findings.slice(0, 8)) {
      console.log(`    - [${f.severity}/10] ${f.id} ${f.title}  @${f.file}:${f.line ?? ''}`)
    }
    if (v.staticScan.findings.length > 8) console.log(`    ... 还有 ${v.staticScan.findings.length - 8} 项`)
  } else {
    console.log('  [静态风险] 无危险模式命中')
  }
  if (v.staticScan.audit) {
    console.log(`  [npm audit] critical:${v.staticScan.audit.critical} high:${v.staticScan.audit.high} moderate:${v.staticScan.audit.moderate} low:${v.staticScan.audit.low} info:${v.staticScan.audit.info}`)
  }
  console.log(line)
  console.log(`  门禁判定: ${v.gate === 'deny' ? 'DENY 拒绝安装' : v.gate === 'warn' ? 'WARN 建议复核' : 'ALLOW 放行'}  →  ${gateMessage(v)}`)
  console.log(line)
}

function indent(text) {
  return text.split('\n').map((l) => '    ' + l).join('\n')
}

function findDshCommand() {
  // 1) PATH
  return new Promise((resolve) => {
    execFile(process.platform === 'win32' ? 'where' : 'which', ['dsh'], { windowsHide: true }, (err) => {
      if (!err) return resolve('dsh')
      // 2) 已知源码仓库路径
      for (const p of [path.join(os.homedir(), 'apps', 'deepseek-harness'), 'C:\\apps\\deepseek-harness']) {
        if (p) return resolve(`${p}/apps/cli/lib/bin.js`)
      }
      resolve(null)
    })
  })
}

async function main() {
  const [cmd, spec, ...rest] = process.argv.slice(2)
  const force = rest.includes('--force')
  const dshCmd = rest.find((a) => a.startsWith('--dsh='))?.slice(6) || (await findDshCommand())

  if (cmd === 'check' && spec) {
    const v = await vet(spec)
    printReport(v)
    process.exit(v.gate === 'deny' ? 1 : 0)
  }

  if (cmd === 'add' && spec) {
    const v = await vet(spec)
    printReport(v)
    if (v.gate === 'deny' && !force) {
      console.log('\n  ✗ 门禁拒绝：信任等级低于阈值。确系可信来源请加 --force 显式放行。')
      process.exit(2)
    }
    if (v.gate === 'warn') {
      console.log('\n  ⚠ 等级为 C，仍将安装（人工复核建议：权限清单/静态发现）。')
    }
    if (!dshCmd) {
      console.error('\n  未找到 dsh 命令，请用 --dsh=<路径> 指定（例如 node C:\\apps\\deepseek-harness\\apps\\cli\\lib\\bin.js）。')
      process.exit(3)
    }
    console.log(`\n  执行安装: dsh plugin add ${spec} ...`)
    const args = dshCmd.endsWith('.js')
      ? [dshCmd, 'plugin', 'add', spec]
      : ['plugin', 'add', spec]
    execFile(dshCmd.endsWith('.js') ? process.execPath : dshCmd, args, { stdio: 'inherit' }, (err) => {
      process.exit(err ? 1 : 0)
    })
    return
  }

  console.log(`dsh-guardwall v${pkg.version} · 安装前门禁 CLI`)
  console.log('用法:')
  console.log('  guardwall check <spec>            体检并输出报告')
  console.log('  guardwall add  <spec> [--force]   体检 → 门禁通过才安装')
  console.log('  spec: 本地路径 / npm 包名 / github:owner/repo')
}

main().catch((e) => {
  console.error('guardwall error:', e.message)
  process.exit(1)
})
