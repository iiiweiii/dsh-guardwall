// Run npm without a shell. On Windows, spawning npm.cmd directly is not
// portable across Node versions and shell:true would make an untrusted package
// spec vulnerable to command interpretation.
import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import path from 'node:path'

let cachedInvocation = null

function exec(command, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(command, args, {
      cwd: opts.cwd,
      timeout: opts.timeout ?? 120000,
      windowsHide: true,
      maxBuffer: 5 * 1024 * 1024,
    }, (error, stdout, stderr) => {
      const result = { error, stdout: String(stdout || ''), stderr: String(stderr || '') }
      if (error && !opts.allowNonZero) {
        return reject(new Error(`npm failed: ${(result.stderr || error.message).trim()}`))
      }
      resolve(result)
    })
  })
}

async function resolveInvocation() {
  if (cachedInvocation) return cachedInvocation
  if (process.platform !== 'win32') {
    cachedInvocation = { command: 'npm', prefix: [] }
    return cachedInvocation
  }

  const where = await new Promise((resolve, reject) => {
    execFile('where.exe', ['npm.cmd'], { windowsHide: true }, (error, stdout) => {
      if (error || !stdout) return reject(new Error('npm.cmd not found on PATH'))
      resolve(String(stdout).split(/\r?\n/).find(Boolean))
    })
  })
  const npmDir = path.dirname(where)
  const npmCli = path.join(npmDir, 'node_modules', 'npm', 'bin', 'npm-cli.js')
  const nodeExe = path.join(npmDir, 'node.exe')
  await fs.access(npmCli)
  cachedInvocation = {
    command: await fs.access(nodeExe).then(() => nodeExe, () => process.execPath),
    prefix: [npmCli],
  }
  return cachedInvocation
}

export async function runNpm(args, opts = {}) {
  const invocation = await resolveInvocation()
  return exec(invocation.command, [...invocation.prefix, ...args], opts)
}
