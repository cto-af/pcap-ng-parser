import * as BlockConfig from './BlockConfig.js';
import {Buffer} from 'node:buffer';
import {Transform} from 'node:stream';

/** @import {Readable, TransformCallback} from 'node:stream' */

/**
 * @param {number} blockType
 * @throws {Error} On invalid block type.
 */
function checkBlockTypeFromBuffer(blockType) {
  if (blockType !== 0x0A0D0D0A) {
    throw new Error(`Invalid file, block type of ${blockType.toString(16)} not recognized`);
  }
}

/**
 * Read a block.
 *
 * @param {Buffer} buf
 * @param {BlockDescriptor} blockDescriptor
 * @param {Endianess} [endian]
 * @param {number} [offset]
 * @returns {Block}
 */
function readBlock(buf, blockDescriptor, endian = 'LE', offset = 0) {
  let pos = offset;

  /** @type {Record<string, number>} */
  const props = {};
  for (const [prop, {size, signed}] of Object.entries(blockDescriptor)) {
    const readMethod = `read${signed ? '' : 'U'}Int${size * 8}${endian}`;
    // @ts-expect-error readMethod hides type
    props[prop] = buf[readMethod](pos);
    pos += size;
  }
  return {
    newOffset: pos,
    data: props,
  };
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
 * @property {number | undefined} [linkType] See https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcaplinktype for info.
 * @property {number | undefined} [snapLen] Capture length.
 * @property {string} [name] Interface name.
 */

/**
 * @typedef {object} Packet
 * @property {number} interfaceId
 * @property {number} timestampHigh
 * @property {number} timestampLow
 * @property {Buffer} data
 */

/**
 * @typedef {object} ParseEvents
 * @property {[number]} blockType
 * @property {[]} close
 * @property {[Packet]} data
 * @property {[]} drain
 * @property {[]} end
 * @property {[Error]} error
 * @property {[]} finish
 * @property {[Interface]} interface
 * @property {[]} pause
 * @property {[Readable]} pipe
 * @property {[]} readable
 * @property {[]} resume
 * @property {[Readable]} unpipe
 */

export class PCAPNGParser extends Transform {
  /** @type {Interface[]} */
  interfaces = [];

  /** @import {BlockDescriptor} from './BlockConfig.js' */

  /** @typedef {"BE" | "LE"} Endianess */

  /**
   * @typedef {object} Data
   * @property {Buffer} [data]
   */

  /**
   * @typedef {Data & Record<string, number>} BlockData
   */

  /**
   * @typedef {object} Block
   * @property {number} newOffset
   * @property {BlockData} data
   */

  /**
   * @typedef {object} Option
   * @property {number} code
   * @property {number} dataLength
   * @property {Buffer} data
   */

  /**
   * @typedef {object} SectionHeader
   * @property {number} blockType
   * @property {number} blockTotalLength
   * @property {number} byteOrderMagic
   * @property {number} majorVersion
   * @property {number} minorVersion
   * @property {number} sectionLengthTop
   * @property {number} sectionLengthBottom
   */

  /** @type {Endianess} */
  #endianess = 'LE';

  /** @type {SectionHeader | undefined} */
  #sectionHeader = undefined;

  /** @type {Buffer | undefined} */
  #carryData = undefined;

  constructor() {
    // The magic bit to allow objects
    super({
      readableObjectMode: true,
    });
  }

  /**
   * Transform chunks of data into packets and interface events.
   *
   * @param {Buffer} chunk Data to process.
   * @param {string} _encoding Ignored.
   * @param {TransformCallback} callback Called when finished with chunk.
   */
  _transform(chunk, _encoding, callback) {
    let buf = chunk;
    // Stitch previous data packet fragment
    if (this.#carryData) {
      buf = Buffer.concat([this.#carryData, chunk]);
      this.#carryData = undefined;
    }

    let pos = 0;
    while (pos < (buf.length)) {
      if (!this.#sectionHeader) {
        try {
          pos = this.#readHeaderBlockFromBuffer(buf);
        } catch (err) {
          callback(/** @type {Error} */(err));
          return;
        }
      } else if (pos + 8 >= buf.length) {
        // If we don't have enough to read the next block length save the
        // remaining data to be pre-pended to the next received data
        this.#carryData = buf.subarray(pos);
        pos = buf.length;
      } else {
        // Read block type and length
        const block = readBlock(
          buf,
          BlockConfig.blockConfig,
          this.#endianess,
          pos
        );

        // @ts-expect-error
        if (pos + block.data.blockTotalLength > buf.length) {
          // This block is bigger than the data we have so save it to be
          // pre-pended to the next received data
          this.#carryData = buf.subarray(pos);
          pos = buf.length;
        } else {
          // We have the entire block, go ahead and process itj
          const blockData = buf.subarray(
            pos,
            // @ts-expect-error
            pos + block.data.blockTotalLength
          );
          const outputDataBlock = this.#processRawBlock(
            blockData,
            // @ts-expect-error
            block.data.blockType
          );
          if (outputDataBlock) {
            const sendBlock = {...outputDataBlock};
            delete sendBlock.blockType;
            delete sendBlock.blockTotalLength;
            delete sendBlock.capturedPacketLength;
            delete sendBlock.originalPacketLength;
            this.push(sendBlock);
          }
          // @ts-expect-error
          pos += block.data.blockTotalLength;

          // @ts-expect-error
          if (block.data.blockTotalLength <= 0) {
            callback(new Error('Invalid block with size 0, unable to scan stream'));
            return;
          }
        }
      }
    } // End while pos

    callback();
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
   * @param {Buffer} buf
   * @returns
   */
  #readHeaderBlockFromBuffer(buf) {
    // Read the header block to determine endianess and make sure its a
    // PCAP-NG file
    const blockType = buf.readUInt32BE(0);
    checkBlockTypeFromBuffer(blockType);

    const byteOrderMagic = buf.readUInt32BE(8);
    this.#endianess = processByteOrderMagic(byteOrderMagic);

    const res = readBlock(
      buf,
      BlockConfig.sectionHeaderBlock,
      this.#endianess,
      0
    );
    // @ts-expect-error
    this.#sectionHeader = res.data;

    // @ts-expect-error
    return this.#sectionHeader.blockTotalLength;
  }

  /**
   * @param {Buffer} buf
   * @returns {Option[]}
   */
  #readOptions(buf) {
    let pos = 0;
    let foundEndOption = false;

    /** @type {Option[]} */
    const options = [];
    while (pos < buf.length || foundEndOption) {
      const rb = readBlock(buf, BlockConfig.optionBlock, this.#endianess, pos);
      // @ts-expect-error
      pos = rb.newOffset + (rb.data.dataLength * 8);
      if (rb.data.code === 0) {
        foundEndOption = true;
      } else {
        // @ts-expect-error
        rb.data.data = buf.subarray(pos - (rb.data.dataLength * 8), pos);
        // @ts-expect-error
        options.push(rb.data);
      }
    }
    return options;
  }

  /**
   * @param {Buffer} blockData
   * @param {number} blockType
   * @returns {BlockData | undefined}
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-general-block-structure
   */
  #processRawBlock(blockData, blockType) {
    if (blockType < 0) {
      // MSB of 1 indicates this is 'local use' data
    } else if (blockType === 1) {
      // Interface definition

      /** @type {Interface} */
      const iData = {};
      const idRes = readBlock(
        blockData,
        BlockConfig.interfaceDescriptionBlockFormat,
        this.#endianess,
        0
      );
      iData.linkType = idRes.data.linkType;
      iData.snapLen = idRes.data.snapLen;
      if (idRes.newOffset < blockData.length) {
        const opts = this.#readOptions(blockData.subarray(idRes.newOffset));
        opts.forEach(opt => {
          if (opt.code === 2) {
            iData.name = opt.data.toString('utf8')
              .replace(/\0/g, '')
              .trim();
          } else {
            // @ts-expect-error
            iData[`code_${opt.code}`] = opt.data.toString();
          }
        });
      }
      this.interfaces.push(iData);

      // Notify listeners we got a new interface
      this.emit('interface', iData);
    } else if (blockType === 6) {
      // Enhanced block... data
      const id = readBlock(
        blockData,
        BlockConfig.enhancedPacketBlockFormat,
        this.#endianess,
        0
      );

      id.data.data = blockData.subarray(
        id.newOffset,
        // @ts-expect-error
        id.newOffset + id.data.capturedPacketLength
      );
      return id.data;
    } else {
      this.emit('blockType', blockType);
    }
    return undefined;
  }
}

export default PCAPNGParser;
