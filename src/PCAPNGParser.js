import * as BlockConfig from './BlockConfig.js';
import {
  CUSTOM_COPY,
  CUSTOM_NOCOPY,
  DECRYPTION_SECRETS,
  ENHANCED_PACKET,
  INTERFACE_DESCRIPTION,
  INTERFACE_STATISTICS,
  NAME_RESOLUTION,
  OPTION_NAMES,
  SECTION_HEADER,
  SIMPLE_PACKET,
} from './options.js';
import {NoFilter, TruncationError} from 'nofilter';
import {Buffer} from 'node:buffer';
import {LINK_TYPE_NAMES} from './linkTypes.js';
import {Transform} from 'node:stream';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

const PCAP_MAGIC_MICRO = 0xA1B2C3D4;
const PCAP_MAGIC_NANO = 0xA1B23C4D;
const PCAP_MAGIC_MICRO_LE = 0xD4C3B2A1;
const PCAP_MAGIC_NANO_LE = 0x4D3CB2A1;

/** @import {Readable, TransformCallback} from 'node:stream' */
/** @import {OptionType} from './options.js' */

const EPB_FLAGS_DIRECTIONS = /** @type {const} */([
  'notAvailable',
  'inbound',
  'outbound',
  'invalid',
]);

const EPB_FLAGS_RECEPTION = /** @type {const} */([
  'notSpecified',
  'unicast',
  'multicast',
  'broadcast',
  'promiscuous',
  'invalid',
  'invalid',
  'invalid',
]);

const EPB_FLAGS_LINK_LAYER_ERRORS = /** @type {const} */([
  'symbol',
  'preamble',
  'startFrameDelimiter',
  'unalignedFrame',
  'wrongInterFrameGap',
  'packetTooShort',
  'packetTooLong',
  'CRC',
  'invalid',
  'invalid',
  'invalid',
  'invalid',
  'invalid',
  'invalid',
  'invalid',
  'invalid',
]);

// #region Utility methods

/**
 * @param {number} n
 * @returns {number}
 */
function pad4(n) {
  return (Math.ceil(n / 4) * 4) - n;
}

/**
 * @param {number} byteOrderMagic
 * @returns {Endianess}
 * @throws {Error} On invalid endianess.
 */
function processByteOrderMagic(byteOrderMagic) {
  if (byteOrderMagic === 0x1A2B3C4D) {
    return 'BE';
  } else if (byteOrderMagic === 0x4D3C2B1A) {
    return 'LE';
  }
  throw new Error(`Unable to determine endian from ${byteOrderMagic.toString(16)}`);
}

/**
 * Convert buffer to hex string with colon separators (e.g. Ethernet address).
 *
 * @param {Buffer} buf
 * @returns {string}
 */
function colons(buf) {
  return Array.from(buf)
    .map(x => x.toString(16).padStart(2, '0'))
    .join(':');
}

// #endregion Utility methods
// #region Types

/**
 * @typedef {object} Interface
 * @property {number} linkType See https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcaplinktype for info.
 * @property {string} [linkTypeName]
 * @property {number} snapLen Capture length.
 * @property {string} [name] Interface name.
 * @property {bigint} tsoffset Offset, in MS, applied to each timestamp.
 * @property {bigint} tsresol Timestamp resolution in MS.
 * @property {Option[]} options All interface options.
 */

/**
 * @typedef {object} IPv4ResolutionRecord
 * @property {'nrb_record_ipv4'} name
 * @property {string} ipv4
 * @property {string[]} entries
 */

/**
 * @typedef {object} IPv6ResolutionRecord
 * @property {'nrb_record_ipv6'} name
 * @property {string} ipv6
 * @property {string[]} entries
 */

/**
 * @typedef {object} EUI48ResolutionRecord
 * @property {'nrb_record_eui48'} name
 * @property {string} eui48
 * @property {string[]} entries
 */

/**
 * @typedef {object} EUI64ResolutionRecord
 * @property {'nrb_record_eui64'} name
 * @property {string} eui64
 * @property {string[]} entries
 */

/**
 * @typedef {IPv4ResolutionRecord | IPv6ResolutionRecord |
 *   EUI48ResolutionRecord | EUI64ResolutionRecord} NameResolutionRecord
 */

/**
 * @typedef {object} NameResolution
 * @property {NameResolutionRecord[]} records
 * @property {Option[]} options NameResolution options.
 */

/**
 * @typedef {object} PacketFlags
 * @property {typeof EPB_FLAGS_DIRECTIONS[number]} [direction]
 * @property {typeof EPB_FLAGS_RECEPTION[number]} [reception]
 * @property {number} FCSlen
 * @property {boolean} [noChecksum]
 * @property {boolean} [checksumValid]
 * @property {boolean} [TCPsegmentationOfflad]
 * @property {typeof EPB_FLAGS_LINK_LAYER_ERRORS[number][]} [linkLayerErrors]
 */

/**
 * @typedef {object} Packet
 * @property {number} interfaceId
 * @property {Date} [timestamp]
 * @property {PacketFlags} [flags]
 * @property {number} originalPacketLength
 * @property {Buffer} data
 * @property {Option[]} options
 */

/**
 * @typedef {object} InterfaceStatistics
 * @property {number} interfaceId
 * @property {Date} timestamp
 * @property {Option[]} options
 */

/**
 * @typedef {object} DecryptionSecrets
 * @property {number} secretsType
 * @property {Buffer} data
 * @property {Option[]} options
 */

/**
 * @typedef {object} CustomBlock
 * @property {number} pen
 * @property {Buffer} data
 * @property {boolean} copy
 */

/**
 * @typedef {object} BlockConfig
 * @property {number} blockType
 * @property {number} blockTotalLength
 */

/**
 * @typedef {object} Data
 * @property {NoFilter} data
 */

/**
 * @typedef {BlockConfig & Data} Block
 */

/**
 * @typedef {object} GenericOption
 * @property {number} optionType
 * @property {number} [dataLength]
 * @property {Buffer} [data]
 * @property {string} [str]
 * @property {bigint} [bigint]
 * @property {Date} [date]
 * @property {string} [name]
 * @property {boolean} [private]
 */

/**
 * @typedef {object} PrivateEnterpriseNumber
 * @property {number} [pen]
 */

/** @typedef {GenericOption & PrivateEnterpriseNumber} Option */

/** @typedef {"BE" | "LE"} Endianess */

/**
 * @typedef {object} SectionHeader
 * @property {Endianess} endianess
 * @property {number} majorVersion
 * @property {number} minorVersion
 * @property {number} sectionLength
 * @property {Option[]} [options]
 */

/**
 * @typedef {object} ParseEvents
 * @property {[number]} blockType Unknown block type received.
 * @property {[]} close Both ends of the stream have closed.
 * @property {[CustomBlock]} custom A Custom block was read.
 * @property {[Packet]} data A Simple or Extended Packet was read.
 * @property {[]} drain If a call to stream.write(chunk) returns false, the
 *   'drain' event will be emitted when it is appropriate to resume writing
 *   data to the stream.
 * @property {[]} end There is no more data to be consumed from the stream.
 * @property {[unknown]} error Error in parsing.
 * @property {[]} finish The input to the parse stream has ended.
 * @property {[Interface]} interface An Interface record was read.
 * @property {[NameResolution]} names A NameResolution record was read.
 * @property {[]} pause `stream.pause()` was called.
 * @property {[Readable]} pipe Output of stream was redirect.
 * @property {[SectionHeader]} section A new Section has started. Always emitted
 *   before other parse events in a valid file.
 * @property {[]} readable Data is available to be read from the stream.
 * @property {[]} resume `stream.resume()` was called.
 * @property {[DecryptionSecrets]} secrets A Decryption Secrets block was read.
 * @property {[InterfaceStatistics]} stats Interface Statistics block was read.
 * @property {[Readable]} unpipe `stream.unpipe()` was called.
 */

/**
 * @typedef {object} ParserOptions
 * @property {AbortSignal} [signal]
 */
// # endregion Types

export class PCAPNGParser extends Transform {
  /** @type {Interface[]} */
  interfaces = [];

  /** @import {BlockDescriptor} from './BlockConfig.js' */

  /**
   * @typedef {Record<string, number>} Numbers
   */

  /** @type {Endianess} */
  #endianess = 'LE';

  /** @type {SectionHeader | undefined} */
  #sectionHeader = undefined;

  /** @type {NoFilter | undefined} */
  #nof = undefined;

  /** @type {Promise<void> | undefined} */
  #reading = undefined;

  /** @type {AbortSignal | undefined} */
  #signal = undefined;

  /** Is this the -ng format, or the older format? */
  #ng = true;

  // #region Transform

  /**
   * @param {ParserOptions} opts
   */
  constructor(opts = {}) {
    const {signal} = opts;

    // The magic bit to allow objects
    super({
      readableObjectMode: true,
      signal,
    });
    this.#signal = signal;
  }

  /**
   * Is this file in the pcap-ng format?
   *
   * @returns If false, in the old pcap format.
   */
  get ng() {
    return this.#ng;
  }

  /**
   * Transform chunks of data into packets and interface events.
   * DO NOT call directly.
   *
   * @param {Buffer} chunk Data to process.
   * @param {string} _encoding Ignored.
   * @param {TransformCallback} callback Called when finished with chunk.
   */
  _transform(chunk, _encoding, callback) {
    if (!this.#nof) {
      this.#nof = new NoFilter({
        signal: this.#signal,
        objectMode: false,
        watchPipe: false,
      });
      this.#reading = this.#readFile(this.#nof);
    }
    this.#nof.write(chunk, callback);
  }

  /**
   * Finished writing.
   * DO NOT call directly.
   *
   * @param {TransformCallback} cb
   */
  _flush(cb) {
    this.#nof?.end();
    if (this.#reading) {
      this.#reading.then(() => cb(), cb);
    } else {
      // Never started writing data.
      cb(new Error('At least one Section Header required'));
    }
  }
  // #endregion Transform

  // #region Read

  /**
   * Read the whole file, once data has started to flow.
   *
   * @param {NoFilter} nof
   */
  async #readFile(nof) {
    try {
      await nof.waitFor(4);
      const magic = /** @type {Buffer} */(nof.slice(0, 4)).readUint32BE(0);
      if (magic === SECTION_HEADER) {
        while (true) {
          const block = await this.#readBlock(nof);
          if (!block) {
            break;
          }
          switch (block.blockType) {
            case SECTION_HEADER:
              await this.#processSectionHeader(block);
              break;
            case INTERFACE_DESCRIPTION:
              await this.#processInterface(block);
              break;
            case SIMPLE_PACKET:
              await this.#processSimplePacket(block);
              break;
            case NAME_RESOLUTION:
              await this.#processNameResolution(block);
              break;
            case INTERFACE_STATISTICS:
              await this.#processInterfaceStatistics(block);
              break;
            case ENHANCED_PACKET:
              await this.#processEnhancedPacket(block);
              break;
            case DECRYPTION_SECRETS:
              await this.#processDecryptionSecrets(block);
              break;
            case CUSTOM_COPY:
            case CUSTOM_NOCOPY:
              await this.#processCustom(block);
              break;
            default:
              if (block.blockType >= 0) {
                this.emit('blockType', block.blockType);
              }
              break;
          }
        }
      } else if (magic === PCAP_MAGIC_MICRO) {
        await this.#readPCAP(nof, 'BE', false);
      } else if (magic === PCAP_MAGIC_MICRO_LE) {
        await this.#readPCAP(nof, 'LE', false);
      } else if (magic === PCAP_MAGIC_NANO) {
        await this.#readPCAP(nof, 'BE', true);
      } else if (magic === PCAP_MAGIC_NANO_LE) {
        await this.#readPCAP(nof, 'LE', true);
      } else {
        throw new Error(`Invalid file format: magic = ${magic}`);
      }
    } catch (er) {
      this.emit('error', er);
    }
  }

  /**
   * Read an old-style PCAP file.
   *
   * @param {NoFilter} nof
   * @param {Endianess} endian
   * @param {boolean} nano
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-06.html
   */
  async #readPCAP(nof, endian, nano) {
    this.#endianess = endian;
    this.#ng = false;
    const {linkType, snapLen} = await this.#readNumbers(
      nof, BlockConfig.pcapHeaderFormat
    );
    const tsresol = nano ? 1000000n : 1000n;

    /** @type {Interface} */
    const int = {
      linkType: linkType & 0xffff,
      snapLen,
      tsresol,
      tsoffset: 0n,
      options: [],
    };
    const ltName = LINK_TYPE_NAMES.get(int.linkType);
    if (ltName) {
      int.linkTypeName = ltName;
    }
    const fcsPresent = Boolean(linkType & 0x04000000);
    if (fcsPresent) {
      const FCSlen = linkType >> 28; // 16 bit words
      int.options.push({
        optionType: 13,
        name: 'if_fcslen',
        data: Buffer.from([FCSlen * 16]), // Bits
      });
    }
    this.interfaces.push(int);
    this.emit('interface', int);

    while (true) {
      try {
        await nof.waitFor(4);
      } catch (er) {
        if (er instanceof TruncationError && er.size === 4) {
          return;
        }
        throw er;
      }
      const {
        timestampHigh, timestampLow, capturedPacketLength, originalPacketLength,
      } = await this.#readNumbers(nof, BlockConfig.pcapPacketFormat);

      const data = capturedPacketLength ?
        /** @type {Buffer} */(await nof.readFull(capturedPacketLength)) :
        Buffer.alloc(0);

      /** @type {Packet} */
      const pkt = {
        interfaceId: 0,
        timestamp: new Date(
          (timestampHigh * 1000) + (timestampLow / Number(tsresol))
        ),
        originalPacketLength,
        data,
        options: [],
      };
      this.push(pkt);
    }
  }

  /**
   * Read a block.
   *
   * @param {NoFilter} nof
   * @returns {Promise<Block | undefined>}
   */
  async #readBlock(nof) {
    let bt = undefined;
    try {
      const {blockType} = await this.#readNumbers(
        nof, BlockConfig.blockType
      );
      bt = blockType;
    } catch (er) {
      if ((er instanceof TruncationError) && (er.size === 4)) {
        // Done.  OK to be done at the start of a block.
        return undefined;
      }
      throw er;
    }

    if (bt === SECTION_HEADER) {
      // Peek at the byte order first.
      await nof.waitFor(8);
      const bom = /** @type {Buffer} */(nof.slice(4, 8)).readUint32BE(0);
      this.#endianess = processByteOrderMagic(bom);
    }

    const {blockTotalLength} = await this.#readNumbers(
      nof, BlockConfig.blockTotalLength
    );

    const dataLen = blockTotalLength - 12;
    const block = {
      blockType: bt,
      blockTotalLength,
      data: new NoFilter(await nof.readFull(dataLen)),
    };
    // Padding
    await nof.readFull(pad4(dataLen));

    const {endTotalLength} = await this.#readNumbers(
      nof, BlockConfig.endLength
    );
    if (endTotalLength !== blockTotalLength) {
      throw new Error(`Length mismatch, ${endTotalLength} != ${blockTotalLength}`);
    }
    return block;
  }

  /**
   * @param {Block} block
   * @param {number} [interfaceId]
   * @returns {Promise<Option[]>}
   */
  async #readOptions(block, interfaceId) {
    let foundEndOption = false;

    /** @type {Option[]} */
    const options = [];
    while (block.data.length && !foundEndOption) {
      const rb = await this.#readNumbers(
        block.data, BlockConfig.optionBlock
      );
      if (rb.optionType === 0) {
        foundEndOption = true;
      } else {
        /** @type {PrivateEnterpriseNumber | undefined} */
        let pen = undefined;
        let name = undefined;

        /** @type {OptionType} */
        let typ = undefined;

        const desc = OPTION_NAMES.get(block.blockType)?.get(rb.optionType);
        if (desc) {
          name = {name: desc[0]};
          // eslint-disable-next-line prefer-destructuring
          typ = desc[1];
          if (desc[2]) {
            pen = await this.#readNumbers(
              block.data, BlockConfig.privateEnterpriseNumber
            );
          }
        }

        /** @type {Option} */
        const opt = {
          ...rb,
          ...name,
          ...pen,
          data: /** @type {Buffer} */ (block.data.read(rb.dataLength)),
        };

        if (rb.optionType & 0x8000) {
          opt.private = true;
        }
        switch (typ) {
          case 'string':
            opt.str = /** @type {Buffer} */(opt.data).toString('utf-8')
              .replaceAll('\0', '')
              .trim();
            delete opt.data;
            break;
          case 'ipv4':
          case 'ipv6':
            opt.str = ipDecode(/** @type {Buffer}*/(opt.data));
            delete opt.data;
            break;
          case 'ipv4mask':
            if (!opt.data || (opt.data.length !== 8)) {
              throw new Error('Invalid ipv4mask option');
            }
            opt.str = `${ipDecode(opt.data.subarray(0, 4))}/${ipDecode(opt.data.subarray(4, 8))}`;
            delete opt.data;
            break;
          case 'ipv6prefix':
            if (!opt.data || (opt.data.length !== 17)) {
              throw new Error('Invalid ipv6prefix option');
            }
            opt.str = `${ipDecode(opt.data.subarray(0, 16))}/${opt.data[16]}`;
            delete opt.data;
            break;
          case 'eui':
            opt.str = colons(/** @type {Buffer} */ (opt.data));
            delete opt.data;
            break;
          case 'u32': {
            const {u32} = await this.#readNumbers(
              new NoFilter(opt.data), BlockConfig.u32Format
            );
            opt.bigint = BigInt(u32);
            delete opt.data;
            break;
          }
          case 'u64': {
            const {u64} = await this.#readNumbers(
              new NoFilter(opt.data), BlockConfig.u64Format
            );
            opt.bigint = BigInt(u64);
            delete opt.data;
            break;
          }
          case 'timestamp': {
            const {timestampHigh, timestampLow} = await this.#readNumbers(
              new NoFilter(opt.data),
              BlockConfig.timestampFormat
            );
            opt.date = this.#timestamp(
              timestampHigh, timestampLow, /** @type {number} */(interfaceId)
            );
            delete opt.data;
          }
        }
        delete opt.dataLength;

        // Skip padding
        block.data.read(pad4(rb.dataLength));
        options.push(opt);
      }
    }
    return options;
  }

  /**
   * Read a set of numbers from the given input.
   *
   * @template {BlockDescriptor} T Describe the name/length pairs.
   * @param {NoFilter} nof
   * @param {T} blockDescriptor
   * @returns {Promise<Record<keyof T, number>>}
   */
  async #readNumbers(nof, blockDescriptor) {
    /** @type {Partial<Record<keyof T, number>>} */
    const props = {};
    for (const [prop, {size, signed}] of Object.entries(blockDescriptor)) {
      const buf = await nof.readFull(size);
      const readMethod = `read${(size === 8) ? 'Big' : ''}${signed ? '' : 'U'}Int${size * 8}${this.#endianess}`;
      // @ts-expect-error readMethod hides type
      props[prop] = buf[readMethod](0);
    }
    return /** @type {Record<keyof T, number>} */(props);
  }

  // #endregion Read
  // #region utilities

  /**
   * Convert the given timestamp to real clock time.
   *
   * @param {number} stampHigh
   * @param {number} stampLow
   * @param {number} interfaceId Known valid.
   * @returns {Date}
   * @throws {Error} On invalid interface ID.
   */
  #timestamp(stampHigh, stampLow, interfaceId) {
    // Don't read as bigint, since each half could be LE.
    const stamp = (BigInt(stampHigh) << 32n) | BigInt(stampLow);
    const int = this.interfaces[interfaceId];

    const off = int.tsoffset + (stamp / int.tsresol);
    return new Date(Number(off));
  }

  // #endregion
  // #region Process Blocks

  /**
   * @param {Block} block
   */
  async #processSectionHeader(block) {
    // Byte order magic handled in #readBlock proactively
    const hdr = await this.#readNumbers(
      block.data,
      BlockConfig.sectionHeaderBlock
    );

    this.#sectionHeader = {
      ...hdr,
      endianess: this.#endianess,
      options: await this.#readOptions(block),
    };

    this.interfaces = []; // Reset interfaces in each section.
    this.emit('section', this.#sectionHeader);
  }

  /**
   * Interface Description Block.
   *
   * @param {Block} block
   * @returns {Promise<void>}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-interface-description-block
   */
  async #processInterface(block) {
    // Interface definition
    const idRes = await this.#readNumbers(
      block.data,
      BlockConfig.interfaceDescriptionBlockFormat
    );

    /** @type {Interface} */
    const iData = {
      linkType: idRes.linkType,
      snapLen: idRes.snapLen,
      tsoffset: 0n,
      tsresol: 1000n,
      options: await this.#readOptions(block),
    };
    for (const opt of iData.options) {
      switch (opt.optionType) {
        case 2:
          iData.name = /** @type {string} */ (opt.str);
          break;
        case 14: {
          iData.tsoffset = /** @type {bigint} */(opt.bigint) * 1000n;
          break;
        }
        case 9: {
          const [tsresol] = /** @type {Buffer} */(opt.data);
          if (tsresol & 0x80) {
            // This is going to lose precision.  Hope nobody does this in
            // practice.
            iData.tsresol = (1n << BigInt(tsresol & 0x7F)) / 1000n;
          } else {
            iData.tsresol = 10n ** (BigInt(tsresol) - 3n);
          }
          break;
        }
      }
    }

    this.interfaces.push(iData);

    // Notify listeners we got a new interface
    this.emit('interface', iData);
  }

  /**
   * Simple Packet Block.
   *
   * @param {Block} block
   * @returns {Promise<void>}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-simple-packet-block
   */
  async #processSimplePacket(block) {
    if (!this.interfaces.length) {
      throw new Error('No interface for simple packet');
    }
    const [int] = this.interfaces;
    const {originalPacketLength} = await this.#readNumbers(
      block.data, BlockConfig.simplePacketFormat
    );
    const len = Math.min(originalPacketLength, int.snapLen);

    const data = len ?
      /** @type {Buffer} */(await block.data.read(len)) :
      Buffer.alloc(0);

    /** @type {Packet} */
    const pkt = {
      interfaceId: 0,
      originalPacketLength,
      data,
      options: [],
    };
    // Skip dealing with padding
    this.push(pkt);
  }

  /**
   * Name Resolution Block.
   *
   * @param {Block} block
   * @returns {Promise<void>}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-name-resolution-block
   */
  async #processNameResolution(block) {
    /** @type {NameResolution} */
    const res = {
      records: [],
      options: [],
    };
    while (true) {
      const {recordType, recordValueLength} = await this.#readNumbers(
        block.data, BlockConfig.nameResolutionFormat
      );
      if (recordType === 0) {
        break;
      }
      const val = /** @type {Buffer} */ (block.data.read(recordValueLength));
      block.data.read(pad4(recordValueLength));
      switch (recordType) {
        case 0x0001:
          if (recordValueLength < 6) {
            throw new Error('Invalid nrb_record_ipv4 record');
          }
          res.records.push({
            name: 'nrb_record_ipv4',
            ipv4: ipDecode(val.subarray(0, 4)),
            entries: val.subarray(4)
              .toString()
              .split('\x00')
              .slice(0, -1),
          });
          break;
        case 0x0002:
          if (recordValueLength < 18) {
            throw new Error('Invalid nrb_record_ipv6 record');
          }
          res.records.push({
            name: 'nrb_record_ipv6',
            ipv6: ipDecode(val.subarray(0, 16)),
            entries: val.subarray(16)
              .toString()
              .split('\x00')
              .slice(0, -1),
          });
          break;
        case 0x0003:
          if (recordValueLength < 8) {
            throw new Error('Invalid nrb_record_eui48 record');
          }
          res.records.push({
            name: 'nrb_record_eui48',
            eui48: colons(val.subarray(0, 6)),
            entries: val.subarray(6)
              .toString()
              .split('\x00')
              .slice(0, -1),
          });
          break;
        case 0x0004:
          if (recordValueLength < 10) {
            throw new Error('Invalid nrb_record_eui64 record');
          }
          res.records.push({
            name: 'nrb_record_eui64',
            eui64: colons(val.subarray(0, 8)),
            entries: val.subarray(8)
              .toString()
              .split('\x00')
              .slice(0, -1),
          });
          break;
      }
    }
    res.options = await this.#readOptions(block);
    this.emit('names', res);
  }

  /**
   * Interface Statistics block.
   *
   * @param {Block} block
   * @returns {Promise<void>}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-interface-statistics-block
   */
  async #processInterfaceStatistics(block) {
    const {interfaceId, timestampHigh, timestampLow} = await this.#readNumbers(
      block.data,
      BlockConfig.interfaceStatisticsFormat
    );
    if (interfaceId >= this.interfaces.length) {
      throw new Error(`Invalid interface id: ${interfaceId}`);
    }

    /** @type {InterfaceStatistics} */
    const stats = {
      interfaceId,
      timestamp: this.#timestamp(timestampHigh, timestampLow, interfaceId),
      options: await this.#readOptions(block, interfaceId),
    };
    this.emit('stats', stats);
  }

  /**
   * Enhanced Packet Block.
   *
   * @param {Block} block
   * @returns {Promise<void>}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-enhanced-packet-block
   */
  async #processEnhancedPacket(block) {
    const {
      interfaceId,
      timestampHigh,
      timestampLow,
      capturedPacketLength,
      originalPacketLength,
    } = await this.#readNumbers(
      block.data, BlockConfig.enhancedPacketBlockFormat
    );

    if (interfaceId >= this.interfaces.length) {
      throw new Error(`Invalid interface ID: ${interfaceId} >= ${this.interfaces.length}`);
    }

    const data = capturedPacketLength ?
      /** @type {Buffer} */(block.data.read(capturedPacketLength)) :
      Buffer.alloc(0);

    /** @type {Packet} */
    const pkt = {
      interfaceId,
      timestamp: this.#timestamp(timestampHigh, timestampLow, interfaceId),
      originalPacketLength,
      data,
      options: [],
    };

    block.data.read(pad4(capturedPacketLength));
    pkt.options = await this.#readOptions(block, interfaceId);
    for (const o of pkt.options) {
      if (o.optionType === 2) { // Type epb_flags
        let {flags} = await this.#readNumbers(
          new NoFilter(o.data), BlockConfig.epbFlagsFormat
        );
        pkt.flags = {
          direction: EPB_FLAGS_DIRECTIONS[flags & 0x3],
          reception: EPB_FLAGS_RECEPTION[(flags >> 2) & 0x7],
          FCSlen: (flags >> 5) & 0xF,
          noChecksum: Boolean((flags >> 9) & 0x1),
          checksumValid: Boolean((flags >> 10) & 0x1),
          TCPsegmentationOfflad: Boolean((flags >> 11) & 0x1),
          linkLayerErrors: [],
        };
        flags >>= 16;
        for (let i = 0; i < 8; i++) {
          if (flags & 0x1) {
            pkt.flags.linkLayerErrors?.push(EPB_FLAGS_LINK_LAYER_ERRORS[i]);
          }
          flags >>= 1;
        }
      }
    }
    this.push(pkt);
  }

  /**
   * Decryption Secrets block.
   *
   * @param {Block} block
   * @returns {Promise<void>}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-decryption-secrets-block
   */
  async #processDecryptionSecrets(block) {
    // TODO(@hildjj): parse the keying information for each of the spec'd
    // secret types.
    const {secretsType, secretsLength} =
      await this.#readNumbers(
        block.data,
        BlockConfig.decryptionSecretsFormat
      );

    /** @type {DecryptionSecrets} */
    const secrets = {
      secretsType,
      data: /** @type {Buffer} */(await block.data.read(secretsLength)),
      options: [],
    };
    block.data.read(pad4(secretsLength));
    secrets.options = await this.#readOptions(block);
    this.emit('secrets', secrets);
  }

  /**
   * Custom block.
   * @param {Block} block
   * @returns {Promise<void>}
   */
  async #processCustom(block) {
    const {pen} = await this.#readNumbers(
      block.data, BlockConfig.privateEnterpriseNumber
    );

    // For options, see:
    // https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap/issues/125
    const custom = {
      pen,
      data: /** @type {Buffer} */(block.data.read()),
      copy: (block.blockType === CUSTOM_COPY),
    };
    this.emit('custom', custom);
  }
  // #endregion Process Blocks

  // #region EventEmitter
  // The following overrides of EventEmitter are here to make event code type
  // safe, including the new events added by this class.

  /**
   * @template {keyof ParseEvents} K Event name.
   * @param {K} eventName
   * @param {ParseEvents[K]} args
   * @returns {boolean}
   */
  emit(eventName, ...args) {
    return super.emit(eventName, ...args);
  }

  /**
   * @template {keyof ParseEvents} K Event name.
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  addListener(eventName, listener) {
    super.addListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K Event name.
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  prependListener(eventName, listener) {
    super.prependListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K Event name.
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  prependOnceListener(eventName, listener) {
    super.prependOnceListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K Event name.
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  removeListener(eventName, listener) {
    super.removeListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K Event name.
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  on(eventName, listener) {
    super.on(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K Event name.
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  once(eventName, listener) {
    super.once(eventName, listener);
    return this;
  }
  // #endregion EventEmitter
}

export default PCAPNGParser;
