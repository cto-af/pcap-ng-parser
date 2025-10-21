import * as BlockConfig from './BlockConfig.js';
import {
  ENHANCED_PACKET, INTERFACE_DESCRIPTION, OPTION_NAMES, SECTION_HEADER,
} from './options.js';
import {NoFilter} from 'nofilter';
import {Transform} from 'node:stream';

/** @import {Readable, TransformCallback} from 'node:stream' */

/**
 * @param {number} n
 * @returns {number}
 */
function pad4(n) {
  return Math.ceil(n / 4) * 4;
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
 * @typedef {object} Interface
 * @property {number | undefined} linkType See https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcaplinktype for info.
 * @property {number | undefined} snapLen Capture length.
 * @property {string} [name] Interface name.
 * @property {Option[]} options All interface options.
 */

/**
 * @typedef {object} Packet
 * @property {number} interfaceId
 * @property {number} timestampHigh
 * @property {number} timestampLow
 * @property {Buffer} data
 */

/**
 * @typedef {object} EnhancedPacketBlockFormat
 * @property {number} [blockType]
 * @property {number} [blockTotalLength]
 * @property {number} interfaceId
 * @property {number} timestampHigh
 * @property {number} timestampLow
 * @property {number} [capturedPacketLength]
 * @property {number} [originalPacketLength]
 * @property {Buffer} data
 * @property {Option[]} options
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
 * @typedef {object} EndLength
 * @property {number} endLength
 */

/**
 * @typedef {object} ParseEvents
 * @property {[number]} blockType
 * @property {[]} close
 * @property {[Packet]} data
 * @property {[]} drain
 * @property {[]} end
 * @property {[unknown]} error
 * @property {[]} finish
 * @property {[Interface]} interface
 * @property {[]} pause
 * @property {[Readable]} pipe
 * @property {[SectionHeader]} section
 * @property {[]} readable
 * @property {[]} resume
 * @property {[Readable]} unpipe
 */

/**
 * @typedef {object} ParserOptions
 * @property {AbortSignal} [signal]
 */

export class PCAPNGParser extends Transform {
  /** @type {Interface[]} */
  interfaces = [];

  /** @import {BlockDescriptor} from './BlockConfig.js' */

  /** @typedef {"BE" | "LE"} Endianess */

  /**
   * @typedef {Record<string, number>} Numbers
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

  /**
   * @typedef {object} SectionHeader
   * @property {Endianess} endianess
   * @property {number} majorVersion
   * @property {number} minorVersion
   * @property {number} sectionLength
   * @property {Option[]} [options]
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

  /**
   * @param {number} blockType
   * @throws {Error} Invalid first block.
   */
  #checkStart(blockType) {
    if (!this.#sectionHeader) {
      if (blockType === -1) {
        throw new Error('At least one Section Header required');
      }
      throw new Error(`Invalid first block 0x${blockType.toString(16)}, must be 0x${SECTION_HEADER.toString(16)}`);
    }
  }

  /**
   * Read the whole file, once data has started to flow.
   *
   * @param {NoFilter} nof
   */
  async #readFile(nof) {
    try {
      while (true) {
        const block = await this.#readBlock(nof);
        if (!block) {
          break;
        }
        switch (block.blockType) {
          case INTERFACE_DESCRIPTION:
            this.#checkStart(block.blockType);
            await this.#processInterface(block);
            break;
          case ENHANCED_PACKET:
            this.#checkStart(block.blockType);
            await this.#processEnhancedPacket(block);
            break;
          case SECTION_HEADER:
            await this.#processSectionHeader(block);
            break;
          default:
            this.#checkStart(block.blockType);
            if (block.blockType >= 0) {
              this.emit('blockType', block.blockType);
            }
        }
      }
      this.#checkStart(-1);
    } catch (er) {
      this.emit('error', er);
    }
  }

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
      if ((er instanceof Error) &&
          (er.message === 'Stream finished before 4 bytes were available')) {
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
    await nof.readFull(pad4(dataLen) - dataLen);

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

    this.emit('section', this.#sectionHeader);
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
        block.data.read(pad4(rb.dataLength) - rb.dataLength);
        options.push(opt);
      }
    }
    return options;
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
    /** @type {Interface} */
    const iData = {};
    const idRes = await this.#readNumbers(
      block.data,
      BlockConfig.interfaceDescriptionBlockFormat
    );
    iData.linkType = idRes.linkType;
    iData.snapLen = idRes.snapLen;
    iData.options = await this.#readOptions(block);
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
   * Enhanced Packet Block.
   *
   * @param {Block} block
   * @returns {Promise<void>}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-enhanced-packet-block
   */
  async #processEnhancedPacket(block) {
    const id =
      await this.#readNumbers(
        block.data,
        BlockConfig.enhancedPacketBlockFormat
      );

    /** @type {EnhancedPacketBlockFormat} */
    const pkt = {
      ...id,
      data: /** @type {Buffer} */(block.data.read(id.capturedPacketLength)),
      options: [],
    };

    block.data.read(pad4(id.capturedPacketLength) - id.capturedPacketLength);
    pkt.options = await this.#readOptions(block);
    this.push(pkt);
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
}

export default PCAPNGParser;
