// rollup -i server.js -o test.js -f cjs -p @rollup/plugin-node-resolve -p @rollup/plugin-commonjs -p @rollup/plugin-json -p @rollup/plugin-terser

import { nodeResolve } from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import terser from '@rollup/plugin-terser'
import hashbang from 'rollup-plugin-shebang-bin'

export default {
  input: 'src/server.mjs',
  output: {
    format: 'cjs',
    dir: 'dist',
    entryFileNames: '[name].js',
  },
  plugins: [
    commonjs(),
    nodeResolve(),
    json(),
    terser(),
    hashbang(),
  ],
};
