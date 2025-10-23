export const SECTION_HEADER = 0x0A0D0D0A;
export const INTERFACE_DESCRIPTION = 0x1;
export const SIMPLE_PACKET = 0x3;
export const NAME_RESOLUTION = 0x4;
export const INTERFACE_STATISTICS = 0x5;
export const ENHANCED_PACKET = 0x6;
export const DECRYPTION_SECRETS = 0xA;

/**
 * @typedef {[name: string, str?: boolean, pen?: boolean]} OptionDescription
 */

/** @typedef {Map<number, OptionDescription>} BlockOpts*/

/**
 * @type {Map<number, BlockOpts>}
 */
export const OPTION_NAMES = new Map([
  [SECTION_HEADER, new Map([
    [1, ['opt_comment', true]],
    [2, ['shb_hardware', true]],
    [3, ['shb_os', true]],
    [4, ['shb_userappl', true]],
    [2988, ['opt_custom', true, true]],
    [2989, ['opt_custom', false, true]],
    [19372, ['opt_custom', true, true]],
    [19373, ['opt_custom', false, true]],
  ])],
  [INTERFACE_DESCRIPTION, new Map([
    [1, ['opt_comment', true]],
    [2, ['if_name', true]],
    [3, ['if_description', true]],
    [4, ['if_IPv4addr']],
    [5, ['if_IPv6addr']],
    [6, ['if_MACaddr']],
    [7, ['if_EUIaddr']],
    [8, ['if_speed']],
    [9, ['if_tsresol']],
    [10, ['if_tzone']],
    [11, ['if_filter']],
    [12, ['if_os', true]],
    [13, ['if_fcslen']],
    [14, ['if_tsoffset']],
    [15, ['if_hardware', true]],
    [16, ['if_txspeed']],
    [17, ['if_rxspeed']],
    [18, ['if_iana_tzname', true]],
    [2988, ['opt_custom', true, true]],
    [2989, ['opt_custom', false, true]],
    [19372, ['opt_custom', true, true]],
    [19373, ['opt_custom', false, true]],
  ])],
  [NAME_RESOLUTION, new Map([
    [1, ['opt_comment', true]],
    [2, ['ns_dnsname', true]],
    [3, ['ns_dnsIP4addr']],
    [4, ['ns_dnsIP6addr']],
    [2988, ['opt_custom', true, true]],
    [2989, ['opt_custom', false, true]],
    [19372, ['opt_custom', true, true]],
    [19373, ['opt_custom', false, true]],
  ])],
  [INTERFACE_STATISTICS, new Map([
    [1, ['opt_comment', true]],
    [2, ['isb_starttime']],
    [3, ['isb_endtime']],
    [4, ['isb_ifrecv']],
    [5, ['isb_ifdrop']],
    [6, ['isb_filteraccept']],
    [7, ['isb_osdrop']],
    [8, ['isb_usrdeliv']],
    [2988, ['opt_custom', true, true]],
    [2989, ['opt_custom', false, true]],
    [19372, ['opt_custom', true, true]],
    [19373, ['opt_custom', false, true]],
  ])],
  [ENHANCED_PACKET, new Map([
    [1, ['opt_comment', true]],
    [2, ['epb_flags']],
    [3, ['epb_hash']],
    [4, ['epb_dropcount']],
    [5, ['epb_packetid']],
    [6, ['epb_queue']],
    [7, ['epb_verdict']],
    [8, ['epb_processid_threadid']],
    [2988, ['opt_custom', true, true]],
    [2989, ['opt_custom', false, true]],
    [19372, ['opt_custom', true, true]],
    [19373, ['opt_custom', false, true]],
  ])],
  [DECRYPTION_SECRETS, new Map([
    [1, ['opt_comment', true]],
    [2988, ['opt_custom', true, true]],
    [2989, ['opt_custom', false, true]],
    [19372, ['opt_custom', true, true]],
    [19373, ['opt_custom', false, true]],
  ])],
]);
