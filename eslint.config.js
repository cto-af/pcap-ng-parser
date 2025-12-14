import {defineConfig, globalIgnores} from 'eslint/config';
import es6 from '@cto.af/eslint-config/es6.js';
import jsdoc from '@cto.af/eslint-config/jsdoc.js';
import json from '@cto.af/eslint-config/json.js';
import jts from '@cto.af/eslint-config/jsdoc_ts.js';
import markdown from '@cto.af/eslint-config/markdown.js';
import mocha from '@cto.af/eslint-config/mocha.js';
import ts from '@cto.af/eslint-config/ts.js';

// Figure out when and how to do this programmatically in @cto.af/eslint-config
ts[1].settings.n.typescriptExtensionMap = [
  ['.js', '.js'],
  ['.ts', '.ts'],
];

export default defineConfig(
  globalIgnores(['doc/**', 'lib/**', 'README.md/*.ts']),
  es6,
  ts,
  jsdoc,
  json,
  jts,
  mocha,
  markdown,
  {
    files: ['test/**/*.ts'],
    rules: {
      '@stylistic/array-element-newline': 'off',
    },
  },
  {
    files: ['examples/*.js'],
    rules: {
      'no-console': 'off',
    },
  },
  {
    files: ['examples/bun.js'],
    languageOptions: {
      globals: {
        Bun: false,
      },
    },
  },
  {
    files: ['examples/deno.js'],
    languageOptions: {
      globals: {
        Deno: false,
      },
    },
  }
);
