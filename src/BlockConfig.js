/**
 * @typedef {object} BlockProperty
 * @property {number} size Bytes.
 * @property {boolean} [signed] If true, read signed.
 */

/**
 * @typedef {Record<string, BlockProperty>} BlockDescriptor
 */

/**
 * @type {BlockDescriptor}
 * @see documentation at http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.4.1
 */
export const sectionHeaderBlock = {
  blockType: {
    size: 4,
  },
  blockTotalLength: {
    size: 4,
  },
  byteOrderMagic: {
    size: 4,
  },
  majorVersion: {
    size: 2,
  },
  minorVersion: {
    size: 2,
  },

  // This is a signed 64 bit value... but node doesn't do 64 bit values
  sectionLengthTop: {
    size: 4,
  },
  sectionLengthBottom: {
    size: 4,
  },
};

/**
 * @type {BlockDescriptor}
 * @see definition at http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.4.3
 */
export const blockConfig = {
  blockType: {
    size: 4,
    signed: true,
  },
  blockTotalLength: {
    size: 4,
  },
};

/**
 * @type {BlockDescriptor}
 * @see definition at http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.4.2
 */
export const interfaceDescriptionBlockFormat = {
  blockType: {
    size: 4,
  },
  blockTotalLength: {
    size: 4,
  },
  linkType: {
    size: 2,
  },
  reserved: {
    size: 2,
  },
  snapLen: {
    size: 4,
  },
};

/**
 * @type {BlockDescriptor}
 * @see definition at http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.4.3
 */
export const enhancedPacketBlockFormat = {
  blockType: {
    size: 4,
  },
  blockTotalLength: {
    size: 4,
  },
  interfaceId: {
    size: 4,
  },
  timestampHigh: {
    size: 4,
  },
  timestampLow: {
    size: 4,
  },
  capturedPacketLength: {
    size: 4,
  },
  originalPacketLength: {
    size: 4,
  },

  /* Packet Data */
  /* Options */
};

/**
 * @type {BlockDescriptor}
 * @see definition at http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.3.5
 */
export const optionBlock = {
  code: {
    size: 2,
  },
  dataLength: {
    size: 2,
  },
};
