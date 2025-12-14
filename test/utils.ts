import {
  type CustomBlock,
  type DecryptionSecrets,
  type Interface,
  type InterfaceStatistics,
  type NameResolution,
  PCAPNGParser,
  type Packet,
  type ParseEvents,
  type ParserOptions,
  type SectionHeader,
} from '../src/index.ts';
import {assert} from 'vitest';

/**
 * Convert hex string to bytes.
 *
 * @param str String.
 * @returns Buffer.
 */
export function hexToU8(str: string): Uint8Array {
  str = str.replace(/\s/g, '');
  let len = Math.ceil(str.length / 2);
  const res = new Uint8Array(len);
  len--;
  for (let end = str.length, start = end - 2;
    end >= 0;
    end = start, start -= 2, len--
  ) {
    res[len] = parseInt(str.substring(start, end), 16);
  }

  return res;
}

/**
 * Convert bytes to hex string.
 * @param u8 Bytes.
 * @returns Hex.
 */
export function u8toHex(u8: Uint8Array): string {
  return u8.reduce((t, v) => t + v.toString(16).padStart(2, '0'), '');
}

export type Hex = string | Uint8Array | Promise<string> | Promise<Uint8Array>;

export interface TestOptions {
  count?: number;
  resolve?(): void;
  reject?(reason: any): void;
  interfaceTests?(i: Interface, p: PCAPNGParser): void;
  dataTests?(pkt: Packet, p: PCAPNGParser): void;
  closeTests?(p: PCAPNGParser): void;
  errorTests?(reason: any, p: PCAPNGParser): void;
  sectionTests?(s: SectionHeader, p: PCAPNGParser): void;

  namesTests?(names: NameResolution, p: PCAPNGParser): void;
  statsTests?(starts: InterfaceStatistics, p: PCAPNGParser): void;
  secretsTests?(secrets: DecryptionSecrets, p: PCAPNGParser): void;
  customTests?(block: CustomBlock, p: PCAPNGParser): void;
}

/**
 * Return a parser for the given data, with event handlers pre-attached
 * in such a way that we can catch errors in the event handlers, bubbling
 * them back out to a reject function.
 *
 * @param hex Hex strings, Uint8Array's, or an Array thereof.  Could also be a
 *   promises of any of those, or a stream to read from.
 * @param opts Test options.
 * @param popts Parser options.
 * @returns Parser instance.
 */
export function parseHex(
  hex: Hex | Hex[] | ReadableStream,
  opts: TestOptions = {},
  popts: ParserOptions = {}
): PCAPNGParser {
  let waitingFor = opts.count ?? Infinity;
  const parser = new PCAPNGParser(popts);
  const got = new Set();
  const expected = new Set();
  if (opts.errorTests) {
    expected.add('error');
  }
  if (opts.dataTests) {
    expected.add('data');
  }
  const {resolve, reject} = opts;
  if (resolve && reject) {
    parser
      .on('error', er => {
        got.add('error');
        if (opts.errorTests) {
          try {
            opts.errorTests(er, parser);
          } catch (e) {
            reject(e);
          }
        } else {
          reject(er);
        }
      })
      .on('close', () => {
        for (const e in expected) {
          if (!got.has(e)) {
            reject(new Error(`Expected ${e}`));
            return;
          }
        }
        try {
          if (Number.isFinite(waitingFor)) {
            assert.equal(waitingFor, 0, `Expected ${opts.count}, still waiting for ${waitingFor} packets`);
          }
          opts.closeTests?.(parser);
          resolve();
        } catch (er) {
          reject(er);
        }
      })
      .on('data', pkt => {
        got.add('data');
        waitingFor--;
        try {
          opts.dataTests?.(pkt, parser);
        } catch (er) {
          reject(er);
        }
      });
    const tests = {
      custom: opts.customTests,
      interface: opts.interfaceTests,
      names: opts.namesTests,
      secrets: opts.secretsTests,
      section: opts.sectionTests,
      stats: opts.statsTests,
    };
    for (const [k, v] of Object.entries(tests)) {
      if (v) {
        expected.add(k);
        parser.on(k as keyof ParseEvents, r => {
          got.add(k);
          try {
            v(r as any, parser);
          } catch (er) {
            reject(er);
          }
        });
      }
    }
  }
  if (hex instanceof ReadableStream) {
    hex.pipeTo(parser);
  } else {
    if (!Array.isArray(hex)) {
      hex = [hex];
    }
    Promise.all(hex).then(hx => {
      const w = parser.getWriter();
      for (const h of hx) {
        w.write((typeof h === 'string') ? hexToU8(h) : h);
      }
      w.close();
    }, reject);
  }
  return parser;
}
