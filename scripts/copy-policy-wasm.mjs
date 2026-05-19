import { cpSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'

const source = join(process.cwd(), 'src', 'policy', 'bundle', 'policy.wasm')
const destination = join(process.cwd(), 'dist', 'policy', 'bundle', 'policy.wasm')

if (!existsSync(source)) {
  throw new Error(`Missing source wasm file at ${source}. Run build:policy:wasm first.`)
}

mkdirSync(dirname(destination), { recursive: true })
cpSync(source, destination)
