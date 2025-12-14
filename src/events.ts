export const EPB_FLAGS_DIRECTIONS = [
  'notAvailable',
  'inbound',
  'outbound',
  'invalid',
] as const;

export const EPB_FLAGS_RECEPTION = [
  'notSpecified',
  'unicast',
  'multicast',
  'broadcast',
  'promiscuous',
  'invalid',
  'invalid',
  'invalid',
] as const;

export const EPB_FLAGS_LINK_LAYER_ERRORS = [
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
] as const;

export interface GenericOption {
  optionType: number;
  dataLength?: number;
  data?: Uint8Array;
  str?: string;
  bigint?: bigint;
  date?: Date;
  name?: string;
  private?: boolean;
}

export interface PrivateEnterpriseNumber {
  pen?: number;
}

export type Option = GenericOption & PrivateEnterpriseNumber;

export interface PacketFlags {
  direction?: typeof EPB_FLAGS_DIRECTIONS[number];
  reception?: typeof EPB_FLAGS_RECEPTION[number];
  FCSlen?: number;
  noChecksum?: boolean;
  checksumValid?: boolean;
  TCPsegmentationOffload?: boolean;
  linkLayerErrors?: typeof EPB_FLAGS_LINK_LAYER_ERRORS[number][];
}

export interface Packet {
  interfaceId: number;
  timestamp?: Date; // To be replaced with Temporal.Instant one day.
  flags?: PacketFlags;
  originalPacketLength: number;
  data: Uint8Array;
  options: Option[];
}

export interface Interface {
  /**
   * @see See https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcaplinktype for info.
   */
  linkType: number;
  linkTypeName?: string;
  snapLen: number;
  name?: string;
  tsoffset: bigint; // Offset, in MS, applied to each timestamp.
  tsresol: bigint; // Timestamp resolution in MS.
  options: Option[];
}

export type Endianess = 'BE' | 'LE';

export interface SectionHeader {
  endianess: Endianess;
  majorVersion: number;
  minorVersion: number;
  sectionLength: bigint;
  options: Option[];
}

export interface IPv4ResolutionRecord {
  name: 'nrb_record_ipv4';
  ipv4: string;
  entries: string[];
}

export interface IPv6ResolutionRecord {
  name: 'nrb_record_ipv6';
  ipv6: string;
  entries: string[];
}

export interface EUI48ResolutionRecord {
  name: 'nrb_record_eui48';
  eui48: string;
  entries: string[];
}

export interface EUI64ResolutionRecord {
  name: 'nrb_record_eui64';
  eui64: string;
  entries: string[];
}

export type NameResolutionRecord =
  IPv4ResolutionRecord | IPv6ResolutionRecord |
  EUI48ResolutionRecord | EUI64ResolutionRecord;

export interface NameResolution {
  records: NameResolutionRecord[];
  options: Option[];
}

export interface InterfaceStatistics {
  interfaceId: number;
  timestamp: Date;
  options: Option[];
}

export interface DecryptionSecrets {
  secretsType: number;
  data: Uint8Array;
  options: Option[];
}

export interface CustomBlock {
  pen: number;
  data: Uint8Array;
  copy: boolean;
}

// Needed before node 25.0.0.
export class ErrorEventPolyfill extends Event implements ErrorEvent {
  #eventInit;

  public constructor(type: string, eventInitDict: ErrorEventInit = {}) {
    super(type, eventInitDict);
    this.#eventInit = eventInitDict;
  }

  public get message(): string {
    return this.#eventInit.message ?? '';
  }

  public get filename(): string {
    return this.#eventInit.filename ?? '';
  }

  public get lineno(): number {
    return this.#eventInit.lineno ?? 0;
  }

  public get colno(): number {
    return this.#eventInit.colno ?? 0;
  }

  public get error(): any {
    return this.#eventInit.error;
  }
}

const LocalErrorEvent = globalThis.ErrorEvent ?? ErrorEventPolyfill;

export {
  LocalErrorEvent as ErrorEvent,
};
