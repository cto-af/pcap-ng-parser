import {
  CUSTOM_COPY,
  CUSTOM_NOCOPY,
  DECRYPTION_SECRETS,
  ENHANCED_PACKET,
  INTERFACE_DESCRIPTION,
  INTERFACE_STATISTICS,
  NAME_RESOLUTION,
  SECTION_HEADER,
} from '../src/options.js';
import {Buffer} from 'node:buffer';
import {NoFilter} from 'nofilter';
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

function hexBlock(blockType, hex) {
  const buf = Buffer.from(hex.replace(/\s/g, ''), 'hex');
  const nof = new NoFilter();
  nof.writeUInt32BE(blockType);
  nof.writeUInt32BE(buf.length + 12);
  nof.write(buf);
  nof.writeUInt32BE(buf.length + 12);
  const h = nof.toString('hex');
  return h;
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

    it('should return an object with properties interfaceId, timestamp, data & ethernet', () => {
      const bufferStream0 = fs.createReadStream('./test/buffer/buffer0');
      const bufferStream1 = fs.createReadStream('./test/buffer/buffer1');
      bufferStream0
        .pipe(pcapNgParser, {end: false})
        .on('data', parsedPacket => {
          assert.property(parsedPacket, 'interfaceId', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestamp', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'data', 'parsedPacket has property interfaceId');
        });
      bufferStream1
        .pipe(pcapNgParser, {end: false})
        .on('data', parsedPacket => {
          assert.property(parsedPacket, 'interfaceId', 'parsedPacket has property interfaceId');
          assert.property(parsedPacket, 'timestamp', 'parsedPacket has property interfaceId');
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

    it('handles flags', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, '0001 0000 0000FFFF')}
${hexBlock(ENHANCED_PACKET, `
00000000 00000000 00000000 00000000 00000000
0002 0004 00FF0E65
0006 0004 00000003
  `)}`)
        .on('data', pkt => {
          try {
            assert.deepEqual(pkt.options, [
              {optionType: 2, name: 'epb_flags', data: Buffer.from('00ff0e65', 'hex')},
              {optionType: 6, name: 'epb_queue', bigint: 3n},
            ]);
            assert.deepEqual(pkt.flags, {
              direction: 'inbound',
              reception: 'unicast',
              FCSlen: 3,
              noChecksum: true,
              checksumValid: true,
              TCPsegmentationOfflad: true,
              linkLayerErrors: [
                'symbol',
                'preamble',
                'startFrameDelimiter',
                'unalignedFrame',
                'wrongInterFrameGap',
                'packetTooShort',
                'packetTooLong',
                'CRC',
              ],
            });
            resolve();
          } catch (e) {
            reject(e);
          }
        })
        .on('error', reject)
        .on('close', reject);
    }));

    it('handles decimal timestamp offsets', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0009 0001 05 000000
  000E 0008 0000000010000000
`)}
${hexBlock(ENHANCED_PACKET, `
00000000 00000001 00000000 00000000 00000000
  `)}`)
        .on('data', pkt => {
          try {
            assert.deepEqual(pkt.timestamp, new Date(268478405672));
            resolve();
          } catch (er) {
            reject(er);
          }
        })
        .on('interface', int => {
          try {
            assert.equal(int.tsresol, 100n);
            assert.equal(int.tsoffset, 0x0000000010000000n * 1000n);
          } catch (er) {
            reject(er);
          }
        })
        .on('error', reject)
        .on('close', reject);
    }));

    it('handles binary timestamp offsets', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0009 0001 8A 000000
  000E 0008 0000000010000000
`)}
${hexBlock(ENHANCED_PACKET, `
00000000 00000001 00000000 00000000 00000000
  `)}`)
        .on('data', pkt => {
          try {
            assert.deepEqual(pkt.timestamp, new Date('1978-08-23T14:27:03.296Z'));
            resolve();
          } catch (er) {
            reject(er);
          }
        })
        .on('interface', int => {
          try {
            assert.equal(int.tsresol, 1n);
            assert.equal(int.tsoffset, 0x0000000010000000n * 1000n);
          } catch (er) {
            reject(er);
          }
        })
        .on('error', reject)
        .on('close', reject);
    }));

    it('handles typed options', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0004 0008 7f000001 FF000000
  0005 0011 20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44 40 000000
  0006 0006 010203040506 0000
  0007 0008 0102030405060708
  0010 0008 0000000000000001
  0011 0008 0000000000000001
`)}`)
        .on('interface', int => {
          try {
            assert.deepEqual(int.options, [
              {optionType: 4, name: 'if_IPv4addr', str: '127.0.0.1/255.0.0.0'},
              {optionType: 5, name: 'if_IPv6addr', str: '2001:db8:85a3:8d3:1319:8a2e:370:7344/64'},
              {optionType: 6, name: 'if_MACaddr', str: '01:02:03:04:05:06'},
              {optionType: 7, name: 'if_EUIaddr', str: '01:02:03:04:05:06:07:08'},
              {optionType: 16, name: 'if_txspeed', bigint: 1n},
              {optionType: 17, name: 'if_rxspeed', bigint: 1n},
            ]);
            resolve();
          } catch (er) {
            reject(er);
          }
        })
        .on('close', reject)
        .on('error', reject);
    }));

    it('handles invalid ipv4mask options', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0004 0007 7f000001 FF000000
`)}`)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid ipv4mask option/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));

    it('handles invalid ipv6mask options', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0005 0007 7f000001 FF000000
`)}`)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid ipv6prefix option/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));

    it('handles invalid timestamp options', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_STATISTICS, `
00000001 000641D5 948441C5
  0002 0008 0000200000000000
`)}`)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid interface id: 1/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));
  });

  describe('simple packet', () => {
    it('errors if no interface', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
00000003 00000014 00000003 01020300 00000014`)
        .on('data', reject)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /No interface for simple packet/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));

    it('handles simple packets', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
00000001 00000014 0001 0000 00000010 00000014
00000003 00000014 00000003 01020300 00000014`)
        .on('close', reject)
        .on('error', reject)
        .on('interface', i => {
          assert.equal(i.snapLen, 16);
        })
        .on('data', p => {
          try {
            assert.equal(p.originalPacketLength, 3);
            assert.deepEqual(p.data, Buffer.from('010203', 'hex'));
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));
  });

  describe('name resolution', () => {
    it('handles name resolution packets', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
${hexBlock(NAME_RESOLUTION, `
  0001 000E 7F000001 6c6f63616c686f737400 0000
  0002 001a 00000000000000000000000000000001 6c6f63616c686f737400 0000
  0003 0010 010203040506 6c6f63616c686f737400
  0004 0012 0102030405060708 6c6f63616c686f737400 0000
  0000 0000
  0001 0004 616200 00
  0002 0004 616200 00
  0003 0004 7f000001
  0004 0010 00000000000000000000000000000001
  0000 0000
  0000 0000`)}`)
        .on('data', reject)
        .on('close', reject)
        .on('names', n => {
          try {
            assert.deepEqual(n, {
              records: [
                {
                  name: 'nrb_record_ipv4',
                  ipv4: '127.0.0.1',
                  entries: ['localhost'],
                },
                {
                  name: 'nrb_record_ipv6',
                  ipv6: '::1',
                  entries: ['localhost'],
                },
                {
                  name: 'nrb_record_eui48',
                  eui48: '01:02:03:04:05:06',
                  entries: ['localhost'],
                },
                {
                  name: 'nrb_record_eui64',
                  eui64: '01:02:03:04:05:06:07:08',
                  entries: ['localhost'],
                },
              ],
              options: [
                {
                  name: 'opt_comment',
                  optionType: 1,
                  str: 'ab',
                },
                {
                  name: 'ns_dnsname',
                  optionType: 2,
                  str: 'ab',
                },
                {
                  name: 'ns_dnsIP4addr',
                  optionType: 3,
                  str: '127.0.0.1',
                },
                {
                  name: 'ns_dnsIP6addr',
                  optionType: 4,
                  str: '::1',
                },
              ],
            });
            resolve();
          } catch (er) {
            reject(er);
          }
        });
    }));

    it('handles short nrb_record_ipv4 records', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
${hexBlock(NAME_RESOLUTION, '0001 0004 7F000001')}`)
        .on('data', reject)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er, /Invalid nrb_record_ipv4 record/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));

    it('handles short nrb_record_ipv6 records', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
${hexBlock(NAME_RESOLUTION, '0002 0010 00000000000000000000000000000001')}`)
        .on('data', reject)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er, /Invalid nrb_record_ipv6 record/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));

    it('handles short nrb_record_eui48 records', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
${hexBlock(NAME_RESOLUTION, '0003 0006 010203040506 0000')}`)
        .on('data', reject)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er, /Invalid nrb_record_eui48 record/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));

    it('handles short nrb_record_eui64 records', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
${hexBlock(NAME_RESOLUTION, '0004 0008 0102030405060708')}`)
        .on('data', reject)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er, /Invalid nrb_record_eui64 record/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));
  });

  describe('interface statistics', () => {
    it('handles Interface Statistic blocks', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, '0001 0000 0000FFFF')}
${hexBlock(INTERFACE_STATISTICS, `
00000000 000641D5 948441C5
  0002 0008 0000200000000000
  0003 0008 0000300000000000
  0004 0008 0000000000000004
  0005 0008 0000000000000005
  0006 0008 0000000000000006
  0007 0008 0000000000000007
  0008 0008 0000000000000008
`)}`)
        .on('data', reject)
        .on('close', reject)
        .on('stats', stats => {
          try {
            assert.deepEqual(stats, {
              interfaceId: 0,
              timestamp: new Date('2025-10-23T16:03:55.798Z'),
              options: [
                {
                  optionType: 2,
                  name: 'isb_starttime',
                  date: new Date('1971-02-12T05:26:12.088Z'),
                },
                {
                  optionType: 3,
                  name: 'isb_endtime',
                  date: new Date('1971-09-03T20:09:18.133Z'),
                },
                {
                  optionType: 4,
                  name: 'isb_ifrecv',
                  bigint: 4n,
                },
                {
                  optionType: 5,
                  name: 'isb_ifdrop',
                  bigint: 5n,
                },
                {
                  optionType: 6,
                  name: 'isb_filteraccept',
                  bigint: 6n,
                },
                {
                  optionType: 7,
                  name: 'isb_osdrop',
                  bigint: 7n,
                },
                {
                  optionType: 8,
                  name: 'isb_usrdeliv',
                  bigint: 8n,
                },
              ],
            });
            resolve();
          } catch (er) {
            reject(er);
          }
        });
    }));

    it('catches an invalid interface ID', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_STATISTICS, '00000000 11111111 22222222')}`)
        .on('data', reject)
        .on('close', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid interface/);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    }));
  });

  describe('decryption secrets', () => {
    it('has initial support for decryption secrets', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(INTERFACE_DESCRIPTION, '0001 0000 0000FFFF')}
${hexBlock(DECRYPTION_SECRETS, `
5353484b 00000003 616200 00
`)}`)
        .on('data', reject)
        .on('close', reject)
        .on('secrets', secrets => {
          try {
            assert.deepEqual(secrets, {
              secretsType: 0x5353484b,
              data: Buffer.from('ab\0'),
              options: [],
            });
            resolve();
          } catch (er) {
            reject(er);
          }
        });
    }));
  });

  describe('custom blocks', () => {
    it('handles copyable custom blocks', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(CUSTOM_COPY, '00007ed9 00000000')}`)
        .on('data', reject)
        .on('close', reject)
        .on('custom', custom => {
          try {
            assert.deepEqual(custom, {
              pen: 32473,
              data: Buffer.from('00000000', 'hex'),
              copy: true,
            });
            resolve();
          } catch (er) {
            reject(er);
          }
        });
    }));

    it('handles non-copyable custom blocks', () => new Promise((resolve, reject) => {
      parseHex(`
${hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')}
${hexBlock(CUSTOM_NOCOPY, '00007ed9 00000000')}`)
        .on('data', reject)
        .on('close', reject)
        .on('custom', custom => {
          try {
            assert.deepEqual(custom, {
              pen: 32473,
              data: Buffer.from('00000000', 'hex'),
              copy: false,
            });
            resolve();
          } catch (er) {
            reject(er);
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
            assert.match(er.message, /File not in pcapng format/);
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

    it('errors on bad interface ID in EPB', () => new Promise((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF  0000001C
00000006 00000020
  00000000 0000000000000000 00000000 00000000
00000020
`)
        .on('data', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid interface ID/);
            resolve();
          } catch (e) {
            reject(e);
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
            assert.match(er.message, /Stream finished before 4 bytes/);
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
      const parser = new PCAPNGParser({signal: ac.signal})
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
      const hex = hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF');
      parser.write(Buffer.from(hex, 'hex'), () => {
        ac.abort();
      });
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
