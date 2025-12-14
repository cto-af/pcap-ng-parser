import {
  CUSTOM_COPY,
  CUSTOM_NOCOPY,
  DECRYPTION_SECRETS,
  ENHANCED_PACKET,
  INTERFACE_DESCRIPTION,
  INTERFACE_STATISTICS,
  NAME_RESOLUTION,
  SECTION_HEADER,
} from '../src/options.ts';
import {type Hex, type TestOptions, hexToU8, parseHex} from './utils.ts';
import {
  PCAPNGParser,
  type Packet,
  type ParserOptions,
  RecoverableError,
} from '../src/index.ts';
import {assert, describe, expect, it} from 'vitest';
import {DataViewReadableStream} from 'dataview-stream';

const TE = new TextEncoder();

function parseBytes(
  bytes: Hex | Hex[],
  opts: TestOptions = {},
  popts: ParserOptions = {}
): Promise<void> {
  return new Promise((resolve, reject) => {
    parseHex(bytes, {...opts, resolve, reject}, popts);
  });
}

async function hexBlock(blockType: number, hex: string): Promise<Uint8Array> {
  const buf = hexToU8(hex);
  const nof = await DataViewReadableStream.create();
  nof.u32(blockType);
  nof.u32(buf.length + 12);
  nof.bytes(buf);
  nof.u32(buf.length + 12);
  nof.end();
  return nof.read();
}

describe('PCAPNGParser', () => {
  describe('invalid format', () => {
    it('Does not want pcapng', async () => {
      await expect(parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
      ], {}, {
        rejectNG: true,
      })).rejects.toThrow('PCAPng format detected and rejected');
    });

    it('Does not want old format', async () => {
      await expect(parseBytes(`
A1B2C3D4 0002 0004 00000000 00000000 0000FFFF 0000FFFF`, {}, {
        rejectOld: true,
      })).rejects.toThrow('Old PCAP format detected and rejected');
    });
  });

  describe(".on('data')", () => {
    it('handles flags', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, '0001 0000 0000FFFF'),
        hexBlock(ENHANCED_PACKET, `
00000000 00000000 00000000 00000000 00000000
0002 0004 00FF0E65
0006 0004 00000003`),
      ], {
        dataTests(pkt) {
          assert.deepEqual(pkt.options, [
            {optionType: 2, name: 'epb_flags', data: hexToU8('00ff0e65')},
            {optionType: 6, name: 'epb_queue', bigint: 3n},
          ]);
          assert.deepEqual(pkt.flags, {
            direction: 'inbound',
            reception: 'unicast',
            FCSlen: 3,
            noChecksum: true,
            checksumValid: true,
            TCPsegmentationOffload: true,
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
        },
      });
    });
  });

  describe(".on('section')", () => {
    it('handles PEN options', async () => {
      await parseBytes(hexBlock(SECTION_HEADER, `
1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF
  0BAC 0007 00007ed9 61620000`), {
        dataTests() {
          throw new Error('Unexpected data');
        },
        sectionTests(s) {
          assert.deepEqual(s.options, [
            {optionType: 2988, name: 'opt_custom', pen: 32473, str: 'ab'},
          ]);
        },
      });
    });
  });

  describe('timestamps', () => {
    it('handles decimal timestamp offsets', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0009 0001 05 000000
  000E 0008 0000000010000000
`),
        hexBlock(ENHANCED_PACKET,
          '00000000 00000001 00000000 00000000 00000000'),
      ], {
        dataTests(pkt) {
          assert.deepEqual(pkt.timestamp, new Date(268478405672));
        },
        interfaceTests(int) {
          assert.equal(int.tsresol, 100n);
          assert.equal(int.tsoffset, 0x0000000010000000n * 1000n);
        },
      });
    });

    it('handles binary timestamp offsets', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0009 0001 8A 000000
  000E 0008 0000000010000000`),
        hexBlock(ENHANCED_PACKET, '00000000 00000001 00000000 00000000 00000000'),
      ], {
        dataTests(pkt) {
          assert.deepEqual(pkt.timestamp, new Date('1978-08-23T14:27:03.296Z'));
        },
        interfaceTests(int) {
          assert.equal(int.tsresol, 1n);
          assert.equal(int.tsoffset, 0x0000000010000000n * 1000n);
        },
      });
    });
  });

  describe('options', () => {
    it('handles typed options', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0004 0008 7f000001 FF000000
  0005 0011 20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44 40 000000
  0006 0006 010203040506 0000
  0007 0008 0102030405060708
  0010 0008 0000000000000001
  0011 0008 0000000000000001`),
      ], {
        interfaceTests(int) {
          assert.deepEqual(int.options, [
            {optionType: 4, name: 'if_IPv4addr', str: '127.0.0.1/255.0.0.0'},
            {optionType: 5, name: 'if_IPv6addr', str: '2001:db8:85a3:8d3:1319:8a2e:370:7344/64'},
            {optionType: 6, name: 'if_MACaddr', str: '01:02:03:04:05:06'},
            {optionType: 7, name: 'if_EUIaddr', str: '01:02:03:04:05:06:07:08'},
            {optionType: 16, name: 'if_txspeed', bigint: 1n},
            {optionType: 17, name: 'if_rxspeed', bigint: 1n},
          ]);
        },
      });
    });

    it('handles invalid ipv4mask options', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0004 0007 7f000001 FF000000`),
      ], {
        errorTests(er) {
          assert.match(er.message, /Invalid ipv4mask option/);
        },
      });
    });

    it('handles invalid ipv6mask options', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, `
0001 0000 0000FFFF
  0005 0007 7f000001 FF000000`),
      ], {
        errorTests(er) {
          assert.match(er.message, /Invalid ipv6prefix option/);
        },
      });
    });

    it('handles invalid timestamp options', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_STATISTICS, `
00000001 000641D5 948441C5
  0002 0008 0000200000000000`),
      ], {
        errorTests(er) {
          assert.match(er.message, /Invalid interface id: 1/);
        },
      });
    });
  });

  describe('simple packet', () => {
    it('errors if no interface', async () => {
      await parseBytes(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
00000003 00000014 00000003 01020300 00000014`, {
        errorTests(er) {
          assert.match(er.message, /No interface for simple packet/);
        },
      });
    });

    it('handles simple packets', async () => {
      await parseBytes(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
00000001 00000014 0001 0000 00000010 00000014
00000003 00000014 00000003 01020300 00000014`, {
        count: 1,
        interfaceTests(i) {
          assert.equal(i.snapLen, 16);
        },
        dataTests(p) {
          assert.equal(p.originalPacketLength, 3);
          assert.deepEqual(p.data, hexToU8('010203'));
        },
      });
    });

    it('handles empty simple packets', async () => {
      await parseBytes(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001C
00000001 00000014 0001 0000 00000010 00000014
00000003 00000010 00000000 00000010`, {
        count: 1,
        interfaceTests(i) {
          assert.equal(i.snapLen, 16);
        },
        dataTests(p) {
          assert.equal(p.originalPacketLength, 0);
        },
      });
    });
  });

  describe('name resolution', () => {
    it('handles name resolution packets', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(NAME_RESOLUTION, `
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
0000 0000`),
      ], {
        namesTests(n) {
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
        },
      });
    });

    it('handles short nrb_record_ipv4 records', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(NAME_RESOLUTION, '0001 0004 7F000001'),
      ], {
        errorTests(er) {
          assert.match(er, /Invalid nrb_record_ipv4 record/);
        },
      });
    });

    it('handles short nrb_record_ipv6 records', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(NAME_RESOLUTION, '0002 0010 00000000000000000000000000000001'),
      ], {
        errorTests(er) {
          assert.match(er, /Invalid nrb_record_ipv6 record/);
        },
      });
    });

    it('handles short nrb_record_eui48 records', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(NAME_RESOLUTION, '0003 0006 010203040506 0000'),
      ], {
        errorTests(er) {
          assert.match(er, /Invalid nrb_record_eui48 record/);
        },
      });
    });

    it('handles short nrb_record_eui64 records', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(NAME_RESOLUTION, '0004 0008 0102030405060708'),
      ], {
        errorTests(er) {
          assert.match(er, /Invalid nrb_record_eui64 record/);
        },
      });
    });
  });

  describe('interface statistics', () => {
    it('handles Interface Statistic blocks', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, '0001 0000 0000FFFF'),
        hexBlock(INTERFACE_STATISTICS, `
00000000 000641D5 948441C5
  0002 0008 0000200000000000
  0003 0008 0000300000000000
  0004 0008 0000000000000004
  0005 0008 0000000000000005
  0006 0008 0000000000000006
  0007 0008 0000000000000007
  0008 0008 0000000000000008`),
      ], {
        statsTests(stats) {
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
        },
      });
    });

    it('catches an invalid interface ID', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_STATISTICS, '00000000 11111111 22222222'),
      ], {
        errorTests(er) {
          assert.match(er.message, /Invalid interface/);
        },
      });
    });
  });

  describe('decryption secrets', () => {
    it('has initial support for decryption secrets', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, '0001 0000 0000FFFF'),
        hexBlock(DECRYPTION_SECRETS, '5353484b 00000003 616200 00'),
      ], {
        secretsTests(s) {
          assert.deepEqual(s, {
            secretsType: 0x5353484b,
            data: TE.encode('ab\0'),
            options: [],
          });
        },
      });
    });
  });

  describe('custom blocks', () => {
    it('handles copyable custom blocks', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(CUSTOM_COPY, '00007ed9 00000000'),
      ], {
        customTests(custom) {
          assert.deepEqual(custom, {
            pen: 32473,
            data: hexToU8('00000000'),
            copy: true,
          });
        },
      });
    });

    it('handles non-copyable custom blocks', async () => {
      await parseBytes([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(CUSTOM_NOCOPY, '00007ed9 00000000'),
      ], {
        customTests(custom) {
          assert.deepEqual(custom, {
            pen: 32473,
            data: hexToU8('00000000'),
            copy: false,
          });
        },
      });
    });
  });

  describe('edge cases', () => {
    it('detects bad blockTypes', () => new Promise<void>((resolve, reject) => {
      parseHex(hexBlock(0x01010101, '4D3C2B1A 0001 0000 FFFFFFFFFFFFFFFF'))
        .on('data', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid file format/);
            resolve();
          } catch (e) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(e);
          }
        })
        .on('close', reject);
    }));

    it('detects bad trailing blockLengths', () => new Promise<void>((resolve, reject) => {
      parseHex('0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF 0000001D')
        .on('data', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Length mismatch/);
            resolve();
          } catch (e) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(e);
          }
        })
        .on('close', reject);
    }));

    it('handles unknown blockTypes', () => new Promise<void>((resolve, reject) => {
      parseHex(`
0A0D0D0A 0000001C 1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF  0000001C
01010102 00000010 01020304 00000010`)
        .on('data', reject)
        .on('error', reject)
        .on('unknown', bt => {
          try {
            assert.equal(bt, 0x01010102);
            resolve();
          } catch (er) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(er);
          }
        });
    }));

    it('errors on bad interface ID in EPB', () => new Promise<void>((resolve, reject) => {
      parseHex([
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(6, '00000000 0000000000000000 00000000 00000000'),
      ])
        .on('data', reject)
        .on('error', er => {
          try {
            assert.match(er.message, /Invalid interface ID/);
            resolve();
          } catch (e) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(e);
          }
        });
    }));

    it('handles bigendian', () => new Promise((resolve, reject) => {
      parseHex(hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'))
        .on('data', reject)
        .on('error', reject)
        .on('close', resolve);
    }));

    it('handles bad endianess', () => new Promise<void>((resolve, reject) => {
      parseHex('0A0D0D0A 10000000 1A2B3C4E 10000000')
        .on('error', er => {
          try {
            assert.match(er.message, /Unable to determine endian from/);
            resolve();
          } catch (e) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(e);
          }
        })
        .on('data', reject)
        .on('close', reject);
    }));

    it('ends when there is no input', () => new Promise<void>((resolve, reject) => {
      const parser = new PCAPNGParser();
      parser.on('data', reject);
      parser.on('error', er => {
        try {
          assert.match(er.message, /Message truncated/);
          resolve();
        } catch (e) {
          // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
          reject(e);
        }
      });
      parser.on('close', reject);
      parser.getWriter().close();
    }));

    it('ends when there is null input', () => new Promise<void>((resolve, reject) => {
      parseHex('')
        .on('error', er => {
          try {
            assert.match(er.message, /Message truncated/);
            resolve();
          } catch (e) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(e);
          }
        })
        .on('data', reject)
        .on('close', reject);
    }));

    it('rejects invalid writes', async () => {
      const parser = new PCAPNGParser();
      // @ts-expect-error Intential wrong type
      await expect(parser.getWriter().write('12')).rejects.toThrow(
        'size'
      );
    });

    it('handles AbortSignals', () => new Promise<void>((resolve, reject) => {
      const parser = new PCAPNGParser()
        .on('error', er => {
          try {
            assert.match(er.message, /Expected test error/);
            resolve();
          } catch (e) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(e);
          }
        })
        .on('data', reject)
        .on('close', reject);
      hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF')
        .then(async hex => {
          const w = parser.getWriter();
          await w.write(hex);
          w.abort(new Error('Expected test error'));
        });
    }));

    it('has typesafe events', async () => {
      const reader = await DataViewReadableStream.create();
      const parser = parseHex(reader);
      const packets: Packet[] = [];
      const foo = (d: Packet): void => {
        packets.push(d);
      };
      parser.once('data', foo);
      parser.off('data', foo);
      assert.throws(() => parser.off('data', foo));
      parser.once('data', foo);
      const closed = new Promise<void>(resolve => {
        parser.once('close', resolve);
      });
      const errored = new Promise(resolve => {
        parser.once('error', resolve);
      });

      for (const buf of [
        hexBlock(SECTION_HEADER, '1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF'),
        hexBlock(INTERFACE_DESCRIPTION, '0001 0000 0000FFFF'),
        hexBlock(ENHANCED_PACKET,
          '00000000 00000001 00000000 00000000 00000000'),
        hexBlock(ENHANCED_PACKET,
          '00000000 00000001 00000000 00000000 00000000'),
        hexBlock(ENHANCED_PACKET,
          '00000001 00000001 00000000 00000000 00000000'),
      ]) {
        reader.bytes(await buf);
      }
      reader.end();
      await closed;
      assert.equal(packets.length, 1);
      const er = await errored;
      assert(er instanceof RecoverableError);
      assert.match(er.message, /Invalid interface ID/);
    });
  });

  describe('old PCAP format', () => {
    it('handles BE micro', async () => {
      await parseBytes(`
A1B2C3D4 0002 0004 00000000 00000000 0000FFFF 0000FFFF
00000000 000003e8 00000001 00000001 61`, {
        count: 1,
        dataTests(pkt) {
          assert.deepEqual(pkt.data, TE.encode('a'));
          assert.deepEqual(pkt.timestamp, new Date('1970-01-01T00:00:00.001Z'));
        },
        interfaceTests(i) {
          assert.equal(i.linkType, 0xffff);
        },
      });
    });

    it('handles BE nano', () => new Promise<void>((resolve, reject) => {
      parseHex(`
A1B23C4D 0002 0004 00000000 00000000 0000FFFF 00000001
00000000 000f4240 00000001 00000001 61`, {
        resolve,
        reject,
        count: 1,
        dataTests(pkt) {
          assert.deepEqual(pkt.data, TE.encode('a'));
          assert.deepEqual(pkt.timestamp, new Date('1970-01-01T00:00:00.001Z'));
        },
      });
    }));

    it('handles LE micro', () => new Promise<void>((resolve, reject) => {
      parseHex(`
D4C3B2A1 0200 0400 00000000 00000000 FFFF0000 01000000
00000000 e8030000 01000000 01000000 61`, {
        resolve,
        reject,
        count: 1,
        dataTests(pkt) {
          assert.deepEqual(pkt.data, TE.encode('a'));
          assert.deepEqual(pkt.timestamp, new Date('1970-01-01T00:00:00.001Z'));
        },
      });
    }));

    it('handles LE nano', () => new Promise<void>((resolve, reject) => {
      parseHex(`
4D3CB2A1 0200 0400 00000000 00000000 FFFF0000 01000000
00000000 40420f00 01000000 01000000 61`, {
        resolve,
        reject,
        count: 1,
        dataTests(pkt) {
          assert.deepEqual(pkt.data, TE.encode('a'));
          assert.deepEqual(pkt.timestamp, new Date('1970-01-01T00:00:00.001Z'));
        },
      });
    }));

    it('handles FCS', () => new Promise<void>((resolve, reject) => {
      parseHex(`
A1B2C3D4 0002 0004 00000000 00000000 0000FFFF 24000001
00000000 000003e8 00000001 00000001 61`, {
        resolve,
        reject,
        count: 1,
        interfaceTests(int) {
          assert.deepEqual(int.options, [{
            optionType: 13,
            name: 'if_fcslen',
            data: new Uint8Array([32]),
          }]);
        },
      });
    }));

    it('handles empty data in old format', () => new Promise<void>((resolve, reject) => {
      parseHex(`
A1B2C3D4 0002 0004 00000000 00000000 0000FFFF 24000001
00000000 000003e8 00000000 00000000`, {
        resolve,
        reject,
        count: 1,
        dataTests(pkt) {
          assert.deepEqual(pkt.data, new Uint8Array(0));
        },
      });
    }));

    it('handles AbortSignals in old format', () => new Promise<void>((resolve, reject) => {
      const parser = new PCAPNGParser();
      const w = parser.getWriter();
      parser
        .on('error', er => {
          try {
            assert.match(er.message, /Expected test error/);
            resolve();
          } catch (e) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(e);
          }
        })
        .on('interface', inter => {
          try {
            assert.deepEqual(inter, {
              linkType: 1,
              linkTypeName: 'ETHERNET',
              snapLen: 65535,
              tsresol: 1000000n,
              tsoffset: 0n,
              options: [],
            });
            setTimeout(() => w.abort(new Error('Expected test error')), 10);
          } catch (er) {
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(er);
          }
        })
        .on('data', reject)
        .on('close', reject);

      w.write(hexToU8('4D3CB2A1020004000000000000000000FFFF000001000000'));
    }));
  });

  describe('errors', () => {
    it('RecoverableError', () => {
      const r = new RecoverableError('foo');
      assert.equal(r.message, 'Recoverable Error');
      assert.equal(r.cause, 'foo');
    });
  });
});
