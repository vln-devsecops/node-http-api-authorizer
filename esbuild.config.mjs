// esbuild bundle configuration.
//
// The handler is bundled into a single self-contained CommonJS file at
// dist/handler.js, with dist/shared/* inlined -- same shape as
// node-vlinder-auth's lambda-src bundling (see that repo's
// esbuild.config.mjs), so any consumer's Terraform archive_file/handler
// reference just points at "handler.handler".
//
// Format is CommonJS: Node treats .js as CJS unconditionally when a
// package.json with "type": "commonjs" is present in the same directory. We
// write dist/package.json ourselves so the CJS bundle is loaded correctly
// even though the source package has "type": "module".
import * as esbuild from 'esbuild'
import { rmSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))

rmSync(resolve(__dirname, 'dist'), { recursive: true, force: true })

await esbuild.build({
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'cjs',
  sourcemap: true,
  minify: false,
  logLevel: 'info',
  entryPoints: [resolve(__dirname, 'src/handler.ts')],
  outfile: resolve(__dirname, 'dist/handler.js'),
})

writeFileSync(
  resolve(__dirname, 'dist/package.json'),
  JSON.stringify({ type: 'commonjs' }, null, 2) + '\n',
)
