/*
 * EXAMPLE of using ether-frame package with PCAPNGParser to decode ethernet
 * packet.
 *
 * Link to ether-frame package: https://www.npmjs.com/package/ether-frame
 */

import {Buffer} from 'node:buffer';
import EtherFrame from 'ether-frame';
import {PCAPNGParser} from '../lib/index.mjs';
import {Readable} from 'node:stream';
import fs from 'node:fs';

const pcapNgParser = new PCAPNGParser();

const filename = process.argv[2] ?? new URL('./res/myfile.pcapng', import.meta.url);

// To pipe from tcpdump, use '-' as the filename.
const myFileStream = filename === '-' ?
  process.stdin :
  fs.createReadStream(filename);

pcapNgParser.on('data', ev => {
  console.log('PACKET', ev);
  const buf = Buffer.from(ev.data);
  try {
    console.log(
      EtherFrame.fromBuffer(buf, pcapNgParser.endianess)
    );
  } catch (ex) {
    // Catches for type codes not currently supported by ether-frame
    console.log('ETHERFRAME ERROR', ex.message);
  }
});

pcapNgParser.addEventListener('section', ev => {
  console.log('SECTION', ev.detail);
});

pcapNgParser.addEventListener('interface', ev => {
  console.log('INTERFACE', ev.detail);
});

pcapNgParser.addEventListener('names', ev => {
  console.log('NAMES', ev.detail);
});

pcapNgParser.addEventListener('secrets', ev => {
  console.log('SECRETS', ev.detail);
});

pcapNgParser.addEventListener('stats', ev => {
  console.log('STATS', ev.detail);
});

pcapNgParser.addEventListener('custom', ev => {
  console.log('STATS', ev.detail);
});

pcapNgParser.addEventListener('blockType', ev => {
  console.log(`Unimplemented block type: ${ev.detail}`);
});

pcapNgParser.addEventListener('error', ev => {
  console.log('ERROR', ev.error);
});

pcapNgParser.on('close', () => {
  console.log('CLOSE');
});
Readable.toWeb(myFileStream).pipeTo(pcapNgParser);
