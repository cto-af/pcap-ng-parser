/**
 * @typedef {object} BlockProperty
 * @property {number} size Bytes.
 * @property {boolean} [signed] If true, read signed.
 */

/**
 * @typedef {Record<string, BlockProperty>} BlockDescriptor
 */

/**
 * @see documentation at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-section-header-block
 */
export const sectionHeaderBlock = {
  byteOrderMagic: {size: 4},
  majorVersion: {size: 2},
  minorVersion: {size: 2},
  sectionLength: {
    size: 8,
    signed: true,
  },
};

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-enhanced-packet-block
 */
export const blockType = {
  blockType: {
    size: 4,
    signed: true,
  },
};

export const blockTotalLength = {
  blockTotalLength: {size: 4},
};

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-interface-description-block
 */
export const interfaceDescriptionBlockFormat = {
  linkType: {size: 2},
  reserved: {size: 2},
  snapLen: {size: 4},
};

export const simplePacketFormat = {
  originalPacketLength: {size: 4},
};

export const nameResolutionFormat = {
  recordType: {size: 2},
  recordValueLength: {size: 2},
};

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-enhanced-packet-block
 */
export const enhancedPacketBlockFormat = {
  interfaceId: {size: 4},
  timestampHigh: {size: 4},
  timestampLow: {size: 4},
  capturedPacketLength: {size: 4},
  originalPacketLength: {size: 4},

  /* Packet Data */
  /* Options */
};

/**
 * @see definition at https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html#name-options
 */
export const optionBlock = {
  optionType: {size: 2},
  dataLength: {size: 2},
};

export const endLength = {
  endTotalLength: {size: 4},
};

export const privateEnterpriseNumber = {
  pen: {size: 4},
};

export const interfaceStatisticsFormat = {
  interfaceId: {size: 4},
  timestampHigh: {size: 4},
  timestampLow: {size: 4},
};

export const decryptionSecretsFormat = {
  secretsType: {size: 4},
  secretsLength: {size: 4},
};

export const epbFlagsFormat = {
  flags: {size: 4},
};

export const ifTsOffsetFormat = {
  tsoffset: {
    size: 8,
    sign: true,
  },
};

export const ipv4MaskFormat = {
  ipv4: {size: 4},
  mask: {size: 4},
};

export const u32Format = {
  u32: {size: 4},
};

export const u64Format = {
  u64: {size: 8},
};

export const timestampFormat = {
  timestampHigh: {size: 4},
  timestampLow: {size: 4},
};

export const pcapHeaderFormat = {
  byteOrderMagic: {size: 4},
  majorVersion: {size: 2},
  minorVersion: {size: 2},
  reserved1: {size: 4},
  reserved2: {size: 4},
  snapLen: {size: 4},
  linkType: {size: 4},
};

export const pcapPacketFormat = {
  timestampHigh: {size: 4},
  timestampLow: {size: 4},
  capturedPacketLength: {size: 4},
  originalPacketLength: {size: 4},
};
