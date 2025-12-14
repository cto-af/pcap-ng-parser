import * as blocks from './blocks.ts';
import {
  CUSTOM_COPY,
  CUSTOM_NOCOPY,
  DECRYPTION_SECRETS,
  ENHANCED_PACKET,
  INTERFACE_DESCRIPTION,
  INTERFACE_STATISTICS,
  NAME_RESOLUTION,
  OPTION_NAMES,
  type OptionType,
  SECTION_HEADER,
  SIMPLE_PACKET,
} from './options.ts';
import {
  type CustomBlock,
  type DecryptionSecrets,
  EPB_FLAGS_DIRECTIONS,
  EPB_FLAGS_LINK_LAYER_ERRORS,
  EPB_FLAGS_RECEPTION,
  type EUI48ResolutionRecord,
  type EUI64ResolutionRecord,
  type Endianess,
  ErrorEvent,
  type GenericOption,
  type IPv4ResolutionRecord,
  type IPv6ResolutionRecord,
  type Interface,
  type InterfaceStatistics,
  type NameResolution,
  type NameResolutionRecord,
  type Option,
  type Packet,
  type PacketFlags,
  type PrivateEnterpriseNumber,
  type SectionHeader,
} from './events.ts';
import {DataViewReader, DataViewWritableStream, TruncationError} from 'dataview-stream';
import {colons, pad4} from './utils.ts';
import {LINK_TYPE_NAMES} from './linkTypes.ts';
import {assert} from '@cto.af/utils';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

export type {
  CustomBlock,
  DecryptionSecrets,
  EUI48ResolutionRecord,
  EUI64ResolutionRecord,
  GenericOption,
  Endianess,
  Interface,
  IPv4ResolutionRecord,
  IPv6ResolutionRecord,
  InterfaceStatistics,
  NameResolution,
  NameResolutionRecord,
  Option,
  OptionType,
  Packet,
  PacketFlags,
  PrivateEnterpriseNumber,
  SectionHeader,
};

const PCAP_MAGIC_MICRO = 0xA1B2C3D4;
const PCAP_MAGIC_NANO = 0xA1B23C4D;
const PCAP_MAGIC_MICRO_LE = 0xD4C3B2A1;
const PCAP_MAGIC_NANO_LE = 0x4D3CB2A1;

const TD = new TextDecoder();

// #region Types

export type EventCallback<T> =
  ((evt: T) => void) |
  {handleEvent(evt: T): void} |
  null;

/**
 * An error has occured when parsing inside a block.  This error can be
 * ignored and parsing can continue within the next block safely.
 */
export class RecoverableError extends Error {
  public constructor(err: unknown) {
    super(err instanceof Error ? err.message : 'Recoverable Error', {cause: err});
  }
}

export interface ParseEvents {
  close: Event;
  custom: CustomEvent<CustomBlock>;
  error: ErrorEvent;
  interface: CustomEvent<Interface>;
  names: CustomEvent<NameResolution>;
  data: CustomEvent<Packet>;
  section: CustomEvent<SectionHeader>;
  secrets: CustomEvent<DecryptionSecrets>;
  stats: CustomEvent<InterfaceStatistics>;
  unknown: CustomEvent<number>;
}

export type ParseEventsDetail<K extends keyof ParseEvents> =
  ParseEvents[K] extends CustomEvent<infer T> ? T :
    ParseEvents[K] extends ErrorEvent ? any :
      // Only for the close event
      // eslint-disable-next-line @typescript-eslint/no-invalid-void-type
      void;

export interface ParserOptions {
  /** If true, don't allow old PCAP format. */
  rejectOld?: boolean;

  /** If true, don't allow new PCAPng format. */
  rejectNG?: boolean;
}

interface Block {
  blockType: number;
  blockTotalLength: number;
  data: DataViewReader;
}

// #region WritableStream

/**
 * Parse a PCAPng or old-style PCAP file from a stream.
 *
 * @example
 * ```js
 * import fs from 'node:fs/promises';
 * import {PCAPNGParser} from '@cto.af/pcap-ng-parser';
 *
 * const parser = new PCAPNGParser();
 * parser.on('data', pkt => console.log(pkt.data)); // Uint8Array
 * const file = await fs.open('examples/res/myfile.pcapng');
 * file.readableWebStream().pipeTo(parser);
 * ```
 */
export class PCAPNGParser
  extends WritableStream<Uint8Array>
  implements EventTarget {
  /**
   * Interface information receieved for the current section, in order of
   * reception.
   */
  public interfaces: Interface[] = [];

  // This is a weak map since the wrapper is holding a reference to the
  // original listener, and #et is holding a reference to the wrapper.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
  #listeners = new WeakMap<Function, (ev: Event) => void>();
  #et = new EventTarget();
  #dv: DataViewWritableStream;
  #ng = true; // Is this the -ng format, or the older format?
  #opts: Required<ParserOptions>;

  public constructor(opts: ParserOptions = {}) {
    const dv = new DataViewWritableStream();
    const writer = dv.getWriter();

    let self: PCAPNGParser | undefined = undefined;

    super({
      write(chunk) {
        return writer.write(chunk);
      },
      async abort(reason) {
        await writer.abort(reason);
        self?.dispatchEvent(new ErrorEvent('error', {
          error: reason,
        }));
      },
      async close() {
        await writer.close();
      },
    });
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    self = this;
    this.#opts = {
      rejectOld: false,
      rejectNG: false,
      ...opts,
    };

    this.#dv = dv;
    this.#readFile();
  }

  /**
   * Is this file in the pcap-ng format?
   */
  public get ng(): boolean {
    return this.#ng;
  }

  /**
   * Endianness of the current section.
   * Little-endian => LE.
   * Big-endian => BE.
   */
  public get endianess(): Endianess {
    return this.#dv.littleEndian ? 'LE' : 'BE';
  }

  // #region EventTarget

  /**
   * The **`addEventListener()`** method of the EventTarget interface sets up
   * a function that will be called whenever the specified event is delivered
   * to the target.
   *
   * @see https://developer.mozilla.org/docs/Web/API/EventTarget/addEventListener
   */
  public addEventListener<E extends keyof ParseEvents>(
    type: E,
    callback: EventCallback<ParseEvents[E]>,
    options?: AddEventListenerOptions | boolean
  ): void;
  public addEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: AddEventListenerOptions | boolean
  ): void {
    this.#et.addEventListener(type, callback, options);
  }

  /**
   * The **`dispatchEvent()`** method of the EventTarget sends an Event to the
   * object, (synchronously) invoking the affected event listeners in the
   * appropriate order.
   *
   * @see https://developer.mozilla.org/docs/Web/API/EventTarget/dispatchEvent
   */
  public dispatchEvent(
    event: ParseEvents[keyof ParseEvents]
  ): boolean;
  public dispatchEvent(event: Event): boolean {
    return this.#et.dispatchEvent(event);
  }

  /**
   * The **`removeEventListener()`** method of the EventTarget interface
   * removes an event listener previously registered with
   * EventTarget.addEventListener() from the target.
   *
   * @see https://developer.mozilla.org/docs/Web/API/EventTarget/removeEventListener
   */
  public removeEventListener<E extends keyof ParseEvents>(
    event: E,
    calback: EventCallback<ParseEvents[E]>,
    options?: EventListenerOptions | boolean
  ): void;
  public removeEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: EventListenerOptions | boolean
  ): void {
    this.#et.removeEventListener(type, callback, options);
  }

  /**
   * Listen for an event, unwrapping the detailor error in the event so that
   * it is easier to process.
   *
   * @param eventName Event name.
   * @param listener Handler.
   * @returns This, for chaining.
   */
  public on<E extends keyof ParseEvents>(
    eventName: E,
    listener: (detail: ParseEventsDetail<E>) => void
  ): this {
    const wrapper = (ev: Event): void => {
      if (eventName === 'close') {
        // @ts-expect-error This should be inferred as correct.
        listener();
      }
      if (ev instanceof CustomEvent) {
        listener(ev.detail);
      } else if (ev instanceof ErrorEvent) {
        listener(ev.error);
      }
    };
    this.#listeners.set(listener, wrapper);
    this.addEventListener(eventName, wrapper);
    return this;
  }

  /**
   * Listen for the first occurence of a given event.  Does the same
   * unwrapping as `on`.
   *
   * @param eventName Event name.
   * @param listener Handler.
   * @returns This, for chaining.
   */
  public once<E extends keyof ParseEvents>(
    eventName: E,
    listener: (detail: ParseEventsDetail<E>) => void
  ): this {
    const wrapper = (ev: Event): void => {
      this.#listeners.delete(listener);
      if (eventName === 'close') {
        // @ts-expect-error This should be inferred as correct.
        listener();
      }
      if (ev instanceof CustomEvent) {
        listener(ev.detail);
      } else if (ev instanceof ErrorEvent) {
        listener(ev.error);
      }
    };
    this.#listeners.set(listener, wrapper);
    this.addEventListener(eventName, wrapper, {once: true});
    return this;
  }

  /**
   * Stop listening for the given event.
   *
   * @param eventName Event name.
   * @param listener Handler to remove.
   * @returns This, for chaining.
   * @throws On unknown listener.
   */
  public off<E extends keyof ParseEvents>(
    eventName: E,
    listener: (detail: ParseEventsDetail<E>) => void
  ): this {
    const wrapper = this.#listeners.get(listener);
    if (!wrapper) {
      throw new Error('Unknown listener');
    }
    this.removeEventListener(eventName, wrapper);
    this.#listeners.delete(listener);
    return this;
  }

  // #region utilities

  #timestamp(stampHigh: number, stampLow: number, interfaceId: number): Date {
    // Don't read as bigint, since each half could be LE.
    const stamp = (BigInt(stampHigh) << 32n) | BigInt(stampLow);
    const int = this.interfaces[interfaceId];
    assert(int, 'Interface always checked before calling');

    const off = int.tsoffset + (stamp / int.tsresol);
    return new Date(Number(off));
  }

  #dvr(bytes: Uint8Array): DataViewReader {
    return new DataViewReader(bytes, {littleEndian: this.#dv.littleEndian});
  }

  // #region Top-level

  /**
   * Read the whole file, once data has started to flow.
   */
  async #readFile(): Promise<void> {
    try {
      // Mostly, we're going to re-peek the first 8 bits in readBlock, so
      // optimize ever-so-slightly.
      const magicBuf = await this.#dv.peek(8);
      const magic = this.#dvr(magicBuf).u32();
      if (magic === SECTION_HEADER) {
        await this.#readSections();
      } else if (magic === PCAP_MAGIC_MICRO) {
        await this.#readPCAP(false, false);
      } else if (magic === PCAP_MAGIC_MICRO_LE) {
        await this.#readPCAP(true, false);
      } else if (magic === PCAP_MAGIC_NANO) {
        await this.#readPCAP(false, true);
      } else if (magic === PCAP_MAGIC_NANO_LE) {
        await this.#readPCAP(true, true);
      } else {
        throw new Error(`Invalid file format: magic = ${magic}`);
      }
    } catch (error) {
      this.dispatchEvent(new ErrorEvent('error', {error}));
    }
    this.dispatchEvent(new Event('close'));
  }

  /**
   * Read an old-style PCAP file.
   *
   * @param littleEndian If true, littleEndian, else false.
   * @param nano If true, nanosecond precision, else microsecond.
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-06.html
   */
  async #readPCAP(littleEndian: boolean, nano: boolean): Promise<void> {
    if (this.#opts.rejectOld) {
      throw new Error('Old PCAP format detected and rejected');
    }

    if (littleEndian) {
      this.#dv.littleEndian = !this.#dv.littleEndian;
    }
    this.#ng = false;
    const {linkType, snapLen} = await this.#dv.struct(
      blocks.pcapHeaderFormat
    );

    const tsresol = nano ? 1000000n : 1000n;

    const int: Interface = {
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
        data: new Uint8Array([FCSlen * 16]), // Bits
      });
    }
    this.interfaces.push(int);
    this.dispatchEvent(new CustomEvent('interface', {detail: int}));

    while (true) {
      try {
        await this.#dv.waitFor(4);
      } catch (er) {
        if (er instanceof TruncationError && er.requested === 4) {
          return;
        }
        throw er;
      }
      const {
        timestampHigh, timestampLow, capturedPacketLength, originalPacketLength,
      } = await this.#dv.struct(blocks.pcapPacketFormat);

      const data = await this.#dv.bytes(capturedPacketLength);

      const pkt: Packet = {
        interfaceId: 0,
        timestamp: new Date(
          (timestampHigh * 1000) + (timestampLow / Number(tsresol))
        ),
        originalPacketLength,
        data,
        options: [],
      };

      this.dispatchEvent(new CustomEvent('data', {
        detail: pkt,
      }));
    }
  }

  async #readSections(): Promise<void> {
    if (this.#opts.rejectNG) {
      throw new Error('PCAPng format detected and rejected');
    }

    while (true) {
      const block = await this.#readBlock();
      if (!block) {
        break;
      }
      try {
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
            this.dispatchEvent(new CustomEvent('unknown', {detail: block.blockType}));
            break;
        }
      } catch (error) {
        this.dispatchEvent(new ErrorEvent('error', {
          error: new RecoverableError(error),
        }));
      }
    }
  }

  // #region Blocks

  /**
   * Read a block.
   */
  async #readBlock(): Promise<Block | undefined> {
    let blockType = undefined;
    try {
      blockType = await this.#dv.u32();
    } catch (er) {
      assert(er instanceof TruncationError);
      assert(er.requested === 4);
      return undefined;
    }

    if (blockType === SECTION_HEADER) {
      // Peek at the byte order first.
      const prelude = await this.#dv.peek(8);
      const dv = this.#dvr(prelude);
      dv.skip(4); // Ignore length for now
      const bom = dv.u32();
      if (bom === 0x1A2B3C4D) {
        // No-op
      } else if (bom === 0x4D3C2B1A) {
        this.#dv.littleEndian = !this.#dv.littleEndian;
      } else {
        throw new Error(`Unable to determine endian from 0x${bom.toString(16)}`);
      }
    }

    const blockTotalLength = await this.#dv.u32();
    const dataLen = blockTotalLength - 12;
    const data = await this.#dv.bytes(dataLen);
    const block = {
      blockType,
      blockTotalLength,
      data: this.#dvr(data),
    };
    // Padding
    await this.#dv.bytes(pad4(dataLen));
    const endTotalLength = await this.#dv.u32();
    if (endTotalLength !== blockTotalLength) {
      throw new Error(`Length mismatch, ${endTotalLength} != ${blockTotalLength}`);
    }
    return block;
  }

  #readOptions(block: Block, interfaceId?: number): Option[] {
    let foundEndOption = false;

    const options: Option[] = [];
    while (!block.data.finished && !foundEndOption) {
      const rb = block.data.struct(blocks.optionBlock);
      if (rb.optionType === 0) {
        foundEndOption = true;
      } else {
        let pen: PrivateEnterpriseNumber | undefined = undefined;
        let name = undefined;
        let optLen = rb.dataLength;
        let typ: OptionType | undefined = undefined;

        const desc = OPTION_NAMES.get(block.blockType)?.get(rb.optionType);
        if (desc) {
          name = {name: desc[0]};
          // eslint-disable-next-line @typescript-eslint/prefer-destructuring
          typ = desc[1];
          if (desc[2]) {
            pen = {
              pen: block.data.u32(),
            };
            optLen -= 4;
          }
        }

        const opt: Option = {
          optionType: rb.optionType,
          ...name,
          ...pen,
        };

        if (rb.optionType & 0x8000) {
          opt.private = true;
        }
        switch (typ) {
          case 'string': {
            const left = block.data.bytes(optLen);
            opt.str = TD
              .decode(left)
              .replaceAll('\0', '')
              .trim();
            break;
          }
          case 'ipv4':
          case 'ipv6':
            opt.str = ipDecode(block.data.bytes(rb.dataLength));
            break;
          case 'ipv4mask':
            if (rb.dataLength !== 8) {
              throw new Error('Invalid ipv4mask option');
            }
            opt.str = `${ipDecode(block.data.bytes(4))}/${ipDecode(block.data.bytes(4))}`;
            break;
          case 'ipv6prefix':
            if (rb.dataLength !== 17) {
              throw new Error('Invalid ipv6prefix option');
            }
            opt.str = `${ipDecode(block.data.bytes(16))}/${block.data.u8()}`;
            break;
          case 'eui':
            opt.str = colons(block.data.bytes(rb.dataLength));
            break;
          case 'u32':
            opt.bigint = BigInt(block.data.u32());
            break;
          case 'u64':
            opt.bigint = block.data.u64();
            break;
          case 'timestamp': {
            const {timestampHigh, timestampLow} =
              block.data.struct(blocks.timestampFormat);
            opt.date = this.#timestamp(
              timestampHigh, timestampLow, interfaceId as number
            );
            break;
          }
          default:
            opt.data = block.data.bytes(rb.dataLength);
            break;
        }

        // Skip padding
        block.data.skip(pad4(rb.dataLength));
        options.push(opt);
      }
    }
    return options;
  }

  // #region Block types

  #processSectionHeader(block: Block): void {
    const hdr = block.data.struct(blocks.sectionHeaderBlock);

    const detail: SectionHeader = {
      ...hdr,
      endianess: this.endianess,
      options: this.#readOptions(block),
    };

    this.interfaces = []; // Reset interfaces in each section.
    this.dispatchEvent(new CustomEvent('section', {detail}));
  }

  /**
   * Interface Description Block.
   *
   * @param block Block.
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-interface-description-block
   */
  #processInterface(block: Block): void {
    const idRes = block.data.struct(
      blocks.interfaceDescriptionBlockFormat
    );

    const iData: Interface = {
      linkType: idRes.linkType,
      snapLen: idRes.snapLen,
      tsoffset: 0n,
      tsresol: 1000n,
      options: this.#readOptions(block),
    };
    for (const opt of iData.options) {
      switch (opt.optionType) {
        case 2:
          iData.name = opt.str as string;
          break;
        case 14: {
          iData.tsoffset = (opt.bigint as bigint) * 1000n;
          break;
        }
        case 9: {
          const tsresol = (opt.data as Uint8Array)[0] as number;
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
    this.dispatchEvent(new CustomEvent('interface', {detail: iData}));
  }

  /**
   * Simple Packet Block.
   *
   * @param block Block.
   * @throws Invalid interface.
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-simple-packet-block
   */
  #processSimplePacket(block: Block): void {
    const [int] = this.interfaces;
    if (!int) {
      throw new Error('No interface for simple packet');
    }
    const originalPacketLength = block.data.u32();
    const len = Math.min(originalPacketLength, int.snapLen);
    const data = block.data.bytes(len);

    const pkt: Packet = {
      interfaceId: 0,
      originalPacketLength,
      data,
      options: [],
    };

    this.dispatchEvent(new CustomEvent('data', {
      detail: pkt,
    }));
  }

  /**
   * Name Resolution Block.
   *
   * @param block Block.
   * @throws Invalid size.
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-name-resolution-block
   */
  #processNameResolution(block: Block): void {
    const res: NameResolution = {
      records: [],
      options: [],
    };
    while (true) {
      const {recordType, recordValueLength} =
        block.data.struct(blocks.nameResolutionFormat);
      if (recordType === 0) {
        break;
      }
      const val = block.data.bytes(recordValueLength);
      block.data.skip(pad4(recordValueLength));
      switch (recordType) {
        case 0x0001:
          if (recordValueLength < 6) {
            throw new Error('Invalid nrb_record_ipv4 record');
          }
          res.records.push({
            name: 'nrb_record_ipv4',
            ipv4: ipDecode(val.subarray(0, 4)),
            entries: TD.decode(val.subarray(4))
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
            entries: TD.decode(val.subarray(16))
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
            entries: TD.decode(val.subarray(6))
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
            entries: TD.decode(val.subarray(8))
              .split('\x00')
              .slice(0, -1),
          });
          break;
      }
    }
    res.options = this.#readOptions(block);
    this.dispatchEvent(new CustomEvent('names', {detail: res}));
  }

  /**
   * Interface Statistics block.
   *
   * @param block Block.
   * @throws Invalid interface.
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-interface-statistics-block
   */
  #processInterfaceStatistics(block: Block): void {
    const {interfaceId, timestampHigh, timestampLow} =
      block.data.struct(blocks.interfaceStatisticsFormat);
    if (interfaceId >= this.interfaces.length) {
      throw new Error(`Invalid interface id: ${interfaceId}`);
    }

    const stats: InterfaceStatistics = {
      interfaceId,
      timestamp: this.#timestamp(timestampHigh, timestampLow, interfaceId),
      options: this.#readOptions(block, interfaceId),
    };
    this.dispatchEvent(new CustomEvent('stats', {detail: stats}));
  }

  /**
   * Enhanced Packet Block.
   *
   * @param block Block.
   * @throws Invalid interface.
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-enhanced-packet-block
   */
  #processEnhancedPacket(block: Block): void {
    const {
      interfaceId,
      timestampHigh,
      timestampLow,
      capturedPacketLength,
      originalPacketLength,
    } = block.data.struct(blocks.enhancedPacketBlockFormat);

    if (interfaceId >= this.interfaces.length) {
      throw new Error(`Invalid interface ID: ${interfaceId} >= ${this.interfaces.length}`);
    }

    const data = block.data.bytes(capturedPacketLength);

    const pkt: Packet = {
      interfaceId,
      timestamp: this.#timestamp(timestampHigh, timestampLow, interfaceId),
      originalPacketLength,
      data,
      options: [],
    };

    block.data.skip(pad4(capturedPacketLength));
    pkt.options = this.#readOptions(block, interfaceId);
    for (const o of pkt.options) {
      if (o.optionType === 2) { // Type epb_flags
        assert(o.data);
        let flags = this.#dvr(o.data).u32();
        pkt.flags = {
          direction: EPB_FLAGS_DIRECTIONS[flags & 0x3] as
            typeof EPB_FLAGS_DIRECTIONS[number],
          reception: EPB_FLAGS_RECEPTION[(flags >> 2) & 0x7] as
            typeof EPB_FLAGS_RECEPTION[number],
          FCSlen: (flags >> 5) & 0xF,
          noChecksum: Boolean((flags >> 9) & 0x1),
          checksumValid: Boolean((flags >> 10) & 0x1),
          TCPsegmentationOffload: Boolean((flags >> 11) & 0x1),
          linkLayerErrors: [],
        };
        flags >>= 16;
        for (let i = 0; i < 8; i++) {
          if (flags & 0x1) {
            pkt.flags.linkLayerErrors?.push(EPB_FLAGS_LINK_LAYER_ERRORS[i] as
              typeof EPB_FLAGS_LINK_LAYER_ERRORS[number]);
          }
          flags >>= 1;
        }
      }
    }
    this.dispatchEvent(new CustomEvent('data', {
      detail: pkt,
    }));
  }

  /**
   * Decryption Secrets block.
   *
   * @param block Block.
   * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-decryption-secrets-block
   */
  #processDecryptionSecrets(block: Block): void {
    // TODO(@hildjj): parse the keying information for each of the spec'd
    // secret types.
    const {secretsType, secretsLength} =
      block.data.struct(blocks.decryptionSecretsFormat);

    const detail: DecryptionSecrets = {
      secretsType,
      data: block.data.bytes(secretsLength),
      options: [],
    };
    block.data.skip(pad4(secretsLength));
    detail.options = this.#readOptions(block);
    this.dispatchEvent(new CustomEvent('secrets', {detail}));
  }

  #processCustom(block: Block): void {
    const pen = block.data.u32();

    // For options, see:
    // https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap/issues/125
    const detail: CustomBlock = {
      pen,
      data: block.data.unused(),
      copy: (block.blockType === CUSTOM_COPY),
    };
    this.dispatchEvent(new CustomEvent('custom', {detail}));
  }
}

export default PCAPNGParser;
