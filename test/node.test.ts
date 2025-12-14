import {type TestOptions, parseHex} from './utils.ts';
import {assert, describe, it} from 'vitest';
import fs from 'node:fs/promises';

/**
 * These tests are for node.js only.  They will fail in the browser.  They
 * happen to work in bun, but not in deno at the moment due to a bug.
 *
 * @module
 * @see https://github.com/denoland/deno/issues/25554
 */

async function fileStream(name: string): Promise<ReadableStream<Uint8Array>> {
  const u = new URL(name, import.meta.url);
  const handle = await fs.open(u);
  return (
    handle.readableWebStream({autoClose: true}) as ReadableStream<Uint8Array>
  );
}

async function parseFile(name: string, opts: TestOptions = {}): Promise<void> {
  const f = await fileStream(name);
  return new Promise((resolve, reject) => {
    parseHex(f, {...opts, resolve, reject});
  });
}

describe('Reading files in node', () => {
  describe(".on('data')", () => {
    it('should return an object with properties interfaceId, timestamp, data & ethernet', async () => {
      await parseFile('./buffer/buffer0', {
        dataTests(parsedPacket) {
          assert.isObject(parsedPacket, 'parsedPacket is an object');
          assert.property(parsedPacket, 'interfaceId', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestamp', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'data', 'parsedPacket has property interfaceId');
        },
      });

      await parseFile('./buffer/buffer1', {
        dataTests(parsedPacket) {
          assert.isObject(parsedPacket, 'parsedPacket is an object');
          assert.property(parsedPacket, 'interfaceId', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestamp', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'data', 'parsedPacket has property interfaceId');
        },
      });
    });

    it('handles the old format', async () => {
      await parseFile('./buffer/buffer4', {count: 6});
    });
  });

  describe(".on('interface')", () => {
    it('should return an object given a Buffer Stream', async () => {
      await parseFile('./buffer/buffer0', {
        interfaceTests(i) {
          assert.isObject(i, 'i is an object');
          assert.property(i, 'linkType', 'i has property linkType');
          assert.property(i, 'snapLen', 'i has property snapLen');
          assert.property(i, 'name', 'i has property name');
        },
      });

      await parseFile('./buffer/buffer1', {
        interfaceTests(i) {
          assert.isObject(i, 'i is an object');
          assert.property(i, 'linkType', 'i has property linkType');
          assert.property(i, 'snapLen', 'i has property snapLen');
          assert.property(i, 'name', 'i has property name');
        },
      });
    });

    it('handles wireshark output', async () => {
      await parseFile('./buffer/buffer3', {
        count: 6,
        closeTests(parser) {
          assert.equal(parser.ng, true);
        },
        interfaceTests(i) {
          assert.property(i, 'linkType', 'i has property linkType');
          assert.property(i, 'snapLen', 'i has property snapLen');
        },
      });
    });
  });
});
