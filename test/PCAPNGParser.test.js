import {Buffer} from 'node:buffer';
import PCAPNGParser from '../src/PCAPNGParser.js';
import {assert} from 'chai';
import fs from 'node:fs';
import stream from 'node:stream';

const pcapNgParser = new PCAPNGParser();

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
      bufferStream3
        .pipe(parser, {end: true})
        .on('data', _d => {
          // Ignored, but needed to make close happen.
        })
        .on('close', resolve)
        .on('error', reject)
        .once('interface', i => {
          assert.property(i, 'linkType', 'i has property linkType');
          assert.property(i, 'snapLen', 'i has property snapLen');
          // No name
        });
    }));
  });

  describe('edge cases', () => {
    it('detects bad blockTypes', () => new Promise((resolve, reject) => {
      const parser = new PCAPNGParser();
      const bs = stream.Readable.from(Buffer.from('01010101', 'hex'));
      parser.on('error', er => {
        assert.match(er.message, /Invalid file, block type/);
        resolve();
      });
      parser.on('close', reject);
      bs.pipe(parser);
    }));

    it('handles bigendian', () => new Promise((resolve, reject) => {
      const parser = new PCAPNGParser();
      const bs = stream.Readable.from(Buffer.from('0A0D0D0A000000001A2B3C4D', 'hex'));
      parser.on('error', er => {
        assert.match(er.message, /The value of "offset" is out of range/);
        resolve();
      });
      parser.on('close', reject);
      bs.pipe(parser);
    }));

    it('handles bad endianess', () => new Promise((resolve, reject) => {
      const parser = new PCAPNGParser();
      const bs = stream.Readable.from(Buffer.from('0A0D0D0A000000001A2B3C4E', 'hex'));
      parser.on('error', er => {
        assert.match(er.message, /Unable to determine endian from/);
        resolve();
      });
      parser.on('close', reject);
      bs.pipe(parser);
    }));
  });
});
