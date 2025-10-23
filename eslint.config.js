import es6 from '@cto.af/eslint-config/es6.js';
import jsdoc from '@cto.af/eslint-config/jsdoc.js';
import json from '@cto.af/eslint-config/json.js';
import markdown from '@cto.af/eslint-config/markdown.js';
import mocha from '@cto.af/eslint-config/mocha.js';

export default [
  {
    ignores: [
      'types/**',
      'doc/**',
    ],
  },
  ...es6,
  ...jsdoc,
  ...json,
  ...markdown,
  ...mocha,
  {
    files: ['examples/**'],
    rules: {
      'no-console': 'off',
    },
  },
  {
    files: ['src/PCAPNGParser.js'],
    rules: {
      'jsdoc/require-returns-type': 'off',
      'jsdoc/require-description': 'off',
      'jsdoc/require-returns-description': 'off',
      'jsdoc/require-param-description': 'off',
      'jsdoc/require-property-description': 'off',
    },
  },
];
