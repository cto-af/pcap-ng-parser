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
import {Transform} from 'node:stream';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

/** @import {Readable, TransformCallback} from 'node:stream' */

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
 * @property {number} snapLen Capture length.
 * @property {string} [name] Interface name.
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
 * @property {typeof EPB_FLAGS_DIRECTIONS[number]} direction
 * @property {typeof EPB_FLAGS_RECEPTION[number]} reception
 * @property {number} FCSlen
 * @property {boolean} noChecksum
 * @property {boolean} checksumValid
 * @property {boolean} TCPsegmentationOfflad
 * @property {typeof EPB_FLAGS_LINK_LAYER_ERRORS[number][]} linkLayerErrors
 */

/**
 * @typedef {object} Packet
 * @property {number} interfaceId
 * @property {number} [timestampHigh]
 * @property {number} [timestampLow]
 * @property {PacketFlags} [flags]
 * @property {number} originalPacketLength
 * @property {Buffer} data
 * @property {Option[]} options
 */

/**
 * @typedef {object} InterfaceStatistics
 * @property {number} interfaceId
 * @property {number} timestampHigh
 * @property {number} timestampLow
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
      const magic = /** @type {Buffer} */(await nof.slice(0, 4));
      if (magic.readUint32BE(0) !== SECTION_HEADER) {
        throw new Error('File not in pcapng format');
      }
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
    } catch (er) {
      this.emit('error', er);
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
   * @returns {Promise<Option[]>}
   */
  async #readOptions(block) {
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
        let str = false;

        const desc = OPTION_NAMES.get(block.blockType)?.get(rb.optionType);
        if (desc) {
          name = {name: desc[0]};
          str = Boolean(desc[1]);
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
        if (str) {
          opt.str = /** @type {Buffer} */(opt.data).toString('utf-8')
            .replaceAll('\0', '')
            .trim();
          delete opt.data;
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
   * @template {BlockDescriptor} T
   * @param {NoFilter} nof
   * @param {T} blockDescriptor
   * @returns {Promise<Record<keyof T, number>>}
   */
  async #readNumbers(nof, blockDescriptor) {
    /** @type {Partial<Record<keyof T, number>>} */
    const props = {};
    for (const [prop, {size, signed, big}] of Object.entries(blockDescriptor)) {
      const buf = await nof.readFull(size);
      const readMethod = `read${big ? 'Big' : ''}${signed ? '' : 'U'}Int${size * 8}${this.#endianess}`;
      // @ts-expect-error readMethod hides type
      props[prop] = buf[readMethod](0);
    }
    return /** @type {Record<keyof T, number>} */(props);
  }

  // #endregion Read
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
      options: await this.#readOptions(block),
    };
    iData.options.forEach(opt => {
      if (opt.optionType === 2) {
        iData.name = /** @type {string} */ (opt.str);
      }
    });

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

    /** @type {Packet} */
    const pkt = {
      interfaceId: 0,
      originalPacketLength,
      data: /** @type {Buffer} */(await block.data.read(len)),
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
    for (const o of res.options) {
      if (o.data && ((o.optionType === 3) || (o.optionType === 4))) {
        o.str = ipDecode(o.data);
        delete o.data;
      }
    }
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
    const stats = {
      interfaceId,
      timestampHigh,
      timestampLow,
      options: await this.#readOptions(block),
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
    const {capturedPacketLength, ...id} =
      await this.#readNumbers(
        block.data,
        BlockConfig.enhancedPacketBlockFormat
      );

    if (id.interfaceId >= this.interfaces.length) {
      throw new Error(`Invalid interface ID: ${id.interfaceId} >= ${this.interfaces.length}`);
    }

    /** @type {Packet} */
    const pkt = {
      ...id,
      data: /** @type {Buffer} */(block.data.read(capturedPacketLength)),
      options: [],
    };

    block.data.read(pad4(capturedPacketLength));
    pkt.options = await this.#readOptions(block);
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
            pkt.flags.linkLayerErrors.push(EPB_FLAGS_LINK_LAYER_ERRORS[i]);
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
   * @template {keyof ParseEvents} K
   * @param {K} eventName
   * @param {ParseEvents[K]} args
   * @returns {boolean}
   */
  emit(eventName, ...args) {
    return super.emit(eventName, ...args);
  }

  /**
   * @template {keyof ParseEvents} K
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  addListener(eventName, listener) {
    super.addListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  prependListener(eventName, listener) {
    super.prependListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  prependOnceListener(eventName, listener) {
    super.prependOnceListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  removeListener(eventName, listener) {
    super.removeListener(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K
   * @param {K} eventName
   * @param {(...args: ParseEvents[K]) => void} listener
   * @returns {this}
   */
  on(eventName, listener) {
    super.on(eventName, listener);
    return this;
  }

  /**
   * @template {keyof ParseEvents} K
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
