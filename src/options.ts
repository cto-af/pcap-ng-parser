export const SECTION_HEADER = 0x0A0D0D0A;
export const INTERFACE_DESCRIPTION = 0x1;
export const SIMPLE_PACKET = 0x3;
export const NAME_RESOLUTION = 0x4;
export const INTERFACE_STATISTICS = 0x5;
export const ENHANCED_PACKET = 0x6;
export const DECRYPTION_SECRETS = 0xA;
export const CUSTOM_COPY = 0x00000BAD;
export const CUSTOM_NOCOPY = 0x40000BAD;

export type OptionType = 'ipv4' | 'ipv6' | 'ipv4mask' | 'ipv6prefix' | 'eui' |
  'u32' | 'u64' | 'timestamp' | 'string' | undefined;

export type OptionDescription = [name: string, typ?: OptionType, pen?: boolean];

export type BlockOpts = Map<number, OptionDescription>;

export const OPTION_NAMES = new Map<number, BlockOpts>([
  [SECTION_HEADER, /** @type {BlockOpts} */ (new Map([
    [1, ['opt_comment', 'string']],
    [2, ['shb_hardware', 'string']],
    [3, ['shb_os', 'string']],
    [4, ['shb_userappl', 'string']],
    [2988, ['opt_custom', 'string', true]],
    [2989, ['opt_custom', undefined, true]],
    [19372, ['opt_custom', 'string', true]],
    [19373, ['opt_custom', undefined, true]],
  ]))],
  [INTERFACE_DESCRIPTION, /** @type {BlockOpts} */ (new Map([
    [1, ['opt_comment', 'string']],
    [2, ['if_name', 'string']],
    [3, ['if_description', 'string']],
    [4, ['if_IPv4addr', 'ipv4mask']],
    [5, ['if_IPv6addr', 'ipv6prefix']],
    [6, ['if_MACaddr', 'eui']],
    [7, ['if_EUIaddr', 'eui']],
    [8, ['if_speed']],
    [9, ['if_tsresol']],
    [10, ['if_tzone']],
    [11, ['if_filter']],
    [12, ['if_os', 'string']],
    [13, ['if_fcslen']],
    [14, ['if_tsoffset', 'u64']],
    [15, ['if_hardware', 'string']],
    [16, ['if_txspeed', 'u64']],
    [17, ['if_rxspeed', 'u64']],
    [18, ['if_iana_tzname', 'string']],
    [2988, ['opt_custom', 'string', true]],
    [2989, ['opt_custom', undefined, true]],
    [19372, ['opt_custom', 'string', true]],
    [19373, ['opt_custom', undefined, true]],
  ]))],
  [NAME_RESOLUTION, /** @type {BlockOpts} */ (new Map([
    [1, ['opt_comment', 'string']],
    [2, ['ns_dnsname', 'string']],
    [3, ['ns_dnsIP4addr', 'ipv4']],
    [4, ['ns_dnsIP6addr', 'ipv6']],
    [2988, ['opt_custom', 'string', true]],
    [2989, ['opt_custom', undefined, true]],
    [19372, ['opt_custom', 'string', true]],
    [19373, ['opt_custom', undefined, true]],
  ]))],
  [INTERFACE_STATISTICS, /** @type {BlockOpts} */ (new Map([
    [1, ['opt_comment', 'string']],
    [2, ['isb_starttime', 'timestamp']],
    [3, ['isb_endtime', 'timestamp']],
    [4, ['isb_ifrecv', 'u64']],
    [5, ['isb_ifdrop', 'u64']],
    [6, ['isb_filteraccept', 'u64']],
    [7, ['isb_osdrop', 'u64']],
    [8, ['isb_usrdeliv', 'u64']],
    [2988, ['opt_custom', 'string', true]],
    [2989, ['opt_custom', undefined, true]],
    [19372, ['opt_custom', 'string', true]],
    [19373, ['opt_custom', undefined, true]],
  ]))],
  [ENHANCED_PACKET, /** @type {BlockOpts} */ (new Map([
    [1, ['opt_comment', 'string']],
    [2, ['epb_flags']],
    [3, ['epb_hash']],
    [4, ['epb_dropcount', 'u64']],
    [5, ['epb_packetid', 'u64']],
    [6, ['epb_queue', 'u32']],
    [7, ['epb_verdict']],
    [8, ['epb_processid_threadid']],
    [2988, ['opt_custom', 'string', true]],
    [2989, ['opt_custom', undefined, true]],
    [19372, ['opt_custom', 'string', true]],
    [19373, ['opt_custom', undefined, true]],
  ]))],
  [DECRYPTION_SECRETS, /** @type {BlockOpts} */ (new Map([
    [1, ['opt_comment', 'string']],
    [2988, ['opt_custom', 'string', true]],
    [2989, ['opt_custom', undefined, true]],
    [19372, ['opt_custom', 'string', true]],
    [19373, ['opt_custom', undefined, true]],
  ]))],
]);
