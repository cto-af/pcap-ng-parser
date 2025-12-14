/**
 * Return this number padded to the nearest multiple of 4.
 *
 * @param n Number.
 * @returns Padded.
 */
export function pad4(n: number): number {
  return (Math.ceil(n / 4) * 4) - n;
}

/**
 * Convert buffer to hex string with colon separators (e.g. Ethernet address).
 *
 * @param buf Buffer.
 * @returns Colon-separated string.
 */
export function colons(buf: Uint8Array): string {
  return Array.from(buf)
    .map(x => x.toString(16).padStart(2, '0'))
    .join(':');
}
