import {Buffer} from 'node:buffer';
import PCAPNGParser from '../src/PCAPNGParser.js';
import {assert} from 'chai';
import fs from 'node:fs';

const pcapNgParser = new PCAPNGParser();

function parseHex(hex, opts) {
  const parser = new PCAPNGParser(opts);
  const buf = Buffer.from(hex.replace(/\s/g, ''), 'hex');
  parser.end(buf);
  return parser;
}

describe('PCAPNGParser', () => {
  describe(".on('data')", () => {
    it('should return an object given a Buffer Stream', () => {
      const bufferStream0 = fs.createReadStream('./test/buffer/buffer0');
      const bufferStream1 = fs.createReadStream('./test/buffer/buffer1');
      bufferStream0
        .pipe(pcapNgParser, {end: false})
        .on('data', parsedPacket => {
          assert.isObject(parsedPacket, 'parsedPacket is an object');
        });
      bufferStream1
        .pipe(pcapNgParser, {end: false})
        .on('data', parsedPacket => {
          assert.isObject(parsedPacket, 'parsedPacket is an object');
        });
    });

    it('should return an object with properties interfaceId, timestampHigh, timestampLow, data & ethernet', () => {
      const bufferStream0 = fs.createReadStream('./test/buffer/buffer0');
      const bufferStream1 = fs.createReadStream('./test/buffer/buffer1');
      bufferStream0
        .pipe(pcapNgParser, {end: false})
        .on('data', parsedPacket => {
          assert.property(parsedPacket, 'interfaceId', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestampHigh', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestampLow', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'data', 'parsedPacket has property interfaceId');
        });
      bufferStream1
        .pipe(pcapNgParser, {end: false})
        .on('data', parsedPacket => {
          assert.property(parsedPacket, 'interfaceId', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestampHigh', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestampLow', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'data', 'parsedPacket has property interfaceId');
        });
    });
  });

  describe(".once('interface')", () => {
    it('should return an object given a Buffer Stream', () => {
      const bufferStream0 = fs.createReadStream('./test/buffer/buffer0');
      const bufferStream1 = fs.createReadStream('./test/buffer/buffer1');
      bufferStream0
        .pipe(pcapNgParser, {end: false})
        .once('interface', i => {
          assert.isObject(i, 'i is an object');
        });
      bufferStream1
        .pipe(pcapNgParser, {end: false})
        .once('interface', i => {
          assert.isObject(i, 'i is an object');
        });
    });

    it('should return an object with properties linkType, snapLen & name', () => {
      const bufferStream0 = fs.createReadStream('./test/buffer/buffer0');
      const bufferStream1 = fs.createReadStream('./test/buffer/buffer1');
      bufferStream0
        .pipe(pcapNgParser, {end: false})
        .once('interface', i => {
          assert.property(i, 'linkType', 'i has property linkType');
          assert.property(i, 'snapLen', 'i has property snapLen');
          assert.property(i, 'name', 'i has property name');
        });
      bufferStream1
        .pipe(pcapNgParser, {end: false})
        .once('interface', i => {
          assert.property(i, 'linkType', 'i has property linkType');
          assert.property(i, 'snapLen', 'i has property snapLen');
          assert.property(i, 'name', 'i has property name');
        });
    });

    it('handles wireshark output', () => new Promise((resolve, reject) => {
      const parser = new PCAPNGParser();
      const bufferStream3 = fs.createReadStream('./test/buffer/buffer3');
      let count = 0;
      bufferStream3
        .pipe(parser)
        .on('data', _d => {
          // Needed to make close happen.
          count++;
        })
        .on('close', () => {
          try {
            assert.equal(count, 6);
            resolve();
          } catch (er) {
            reject(er);
          }
        })
        .on('error', reject)
        .once('interface', i => {
          try {
            assert.property(i, 'linkType', 'i has property linkType');
            assert.property(i, 'snapLen', 'i has property snapLen');
          } catch (er) {
            reject(er);
          }
        });
    }));

    it('handles PEN options', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 00000026 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF
  0BAC 0007 00007ed9 61620000
00000026`)
        .on('data', reject)
        .on('section', s => {
          try {
            assert.deepEqual(s.options, [
              {optionType: 2988, name: 'opt_custom', pen: 32473, str: 'ab'},
            ]);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));
  });

  describe('edge cases', () => {
    it('detects bad blockTypes', () => new Promise((resolve, reject) => {
      parseHex('01010101 1C000000 4D3C2B1A 0001 0000 FFFFFFFFFFFFFFFF 1C000000')
        .on('data', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid first block/);
            resolve();
          } catch {
            reject(er);
          }
        })
        .on('close', reject);
    }));

    it('detects bad trailing blockLengths', () => new Promise((resolve, reject) => {
      parseHex('0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001D')
        .on('data', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Length mismatch/);
            resolve();
          } catch {
            reject(er);
          }
        })
        .on('close', reject);
    }));

    it('handles unknown blockTypes', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF  0000001C
01010102 00000010 01020304 00000010`)
        .on('data', reject)
        .on('error', reject)
        .on('blockType', bt => {
          try {
            assert.equal(bt, 0x01010102);
            resolve();
          } catch (er) {
            reject(er);
          }
        });
    }));

    it('handles bigendian', () => new Promise((resolve, reject) => {
      parseHex('0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF  0000001C')
        .on('data', reject)
        .on('error', reject)
        .on('end', resolve);
    }));

    it('handles bad endianess', () => new Promise((resolve, reject) => {
      parseHex('0A0D0D0A 10000000 1A2B3C4E 10000000')
        .on('error', er => {
          try {
            assert.match(er.message, /Unable to determine endian from/);
            resolve();
          } catch (e) {
            reject(e);
          }
        })
        .on('data', reject)
        .on('close', reject);
    }));

    it('ends when there is no input', () => new Promise((resolve, reject) => {
      const parser = new PCAPNGParser();
      parser.addListener('data', reject);
      parser.on('error', er => {
        try {
          assert.match(er.message, /At least one Section Header required/);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
      parser.on('close', reject);
      parser.end();
    }));

    it('ends when there is null input', () => new Promise((resolve, reject) => {
      parseHex('')
        .on('error', er => {
          try {
            assert.match(er.message, /At least one Section Header required/);
            resolve();
          } catch (e) {
            reject(e);
          }
        })
        .on('data', reject)
        .on('close', reject);
    }));

    it('rejects invalid writes', () => {
      const parser = new PCAPNGParser();
      assert.throws(() => parser.write(12), /argument must be of type string or an instance of Buffer/);
    });

    it('handles AbortSignals', () => new Promise((resolve, reject) => {
      const ac = new AbortController();
      parseHex('0A0D', {signal: ac.signal})
        .on('error', er => {
          try {
            assert.match(er.message, /aborted/);
            resolve();
          } catch (e) {
            reject(e);
          }
        })
        .on('data', reject)
        .on('close', reject);
      ac.abort();
    }));

    it('has typesafe events', () => {
      const parser = new PCAPNGParser();
      const packets = [];
      const foo = d => packets.push(d);
      parser.prependOnceListener('data', foo);
      parser.removeListener('data', foo);
    });
  });
});
