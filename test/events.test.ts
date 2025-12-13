import {assert, test} from 'vitest';
import {ErrorEventPolyfill} from '../src/events.ts';

test('ErrorEventPolyfill', () => {
  const ee = new ErrorEventPolyfill('foo');
  assert(ee);
  assert.equal(ee.type, 'foo');
  assert.equal(ee.message, '');
  assert.equal(ee.filename, '');
  assert.equal(ee.lineno, 0);
  assert.equal(ee.colno, 0);
  assert.equal(ee.error, undefined);

  const error = new Error('blah');
  const ef = new ErrorEventPolyfill('bar', {
    colno: 4,
    error,
    filename: import.meta.url,
    lineno: 13,
    message: 'Hi',
  });
  assert(ef);
  assert.equal(ef.type, 'bar');
  assert.equal(ef.message, 'Hi');
  assert.equal(ef.filename, import.meta.url);
  assert.equal(ef.lineno, 13);
  assert.equal(ef.colno, 4);
  assert.equal(ef.error, error);
});
