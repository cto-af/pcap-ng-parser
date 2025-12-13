/**
 * @see documentation at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-section-header-block
 */
export const sectionHeaderBlock = {
  byteOrderMagic: {read: 'u32'},
  majorVersion: {read: 'u16'},
  minorVersion: {read: 'u16'},
  sectionLength: {read: 'i64'},
} as const;

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-enhanced-packet-block
 */
export const blockType = {
  blockType: {read: 'i32'},
} as const;

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-interface-description-block
 */
export const interfaceDescriptionBlockFormat = {
  linkType: {read: 'u16'},
  reserved: {read: 'u16'},
  snapLen: {read: 'u32'},
} as const;

export const nameResolutionFormat = {
  recordType: {read: 'u16'},
  recordValueLength: {read: 'u16'},
} as const;

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-enhanced-packet-block
 */
export const enhancedPacketBlockFormat = {
  interfaceId: {read: 'u32'},
  timestampHigh: {read: 'u32'},
  timestampLow: {read: 'u32'},
  capturedPacketLength: {read: 'u32'},
  originalPacketLength: {read: 'u32'},

  /* Packet Data */
  /* Options */
} as const;

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-options
 */
export const optionBlock = {
  optionType: {read: 'u16'},
  dataLength: {read: 'u16'},
} as const;

export const interfaceStatisticsFormat = {
  interfaceId: {read: 'u32'},
  timestampHigh: {read: 'u32'},
  timestampLow: {read: 'u32'},
} as const;

export const decryptionSecretsFormat = {
  secretsType: {read: 'u32'},
  secretsLength: {read: 'u32'},
} as const;

export const ifTsOffsetFormat = {
  tsoffset: {size: 8, sign: true},
};

export const timestampFormat = {
  timestampHigh: {read: 'u32'},
  timestampLow: {read: 'u32'},
} as const;

export const pcapHeaderFormat = {
  byteOrderMagic: {read: 'u32'},
  majorVersion: {read: 'u16'},
  minorVersion: {read: 'u16'},
  _reserved1: {read: 'u32'},
  _reserved2: {read: 'u32'},
  snapLen: {read: 'u32'},
  linkType: {read: 'u32'},
} as const;

export const pcapPacketFormat = {
  timestampHigh: {read: 'u32'},
  timestampLow: {read: 'u32'},
  capturedPacketLength: {read: 'u32'},
  originalPacketLength: {read: 'u32'},
} as const;
