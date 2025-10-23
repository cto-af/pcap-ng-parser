/*
 * EXAMPLE of using ether-frame package with PCAPNGParser to decode ethernet
 * packet.
 *
 * Link to ether-frame package: https://www.npmjs.com/package/ether-frame
 */

import EtherFrame from 'ether-frame';
import PCAPNGParser from '../src/PCAPNGParser.js';
import fs from 'node:fs';

const pcapNgParser = new PCAPNGParser();

const filename = process.argv[2] ?? new URL('./res/myfile.pcapng', import.meta.url);

// To pipe from tcpdump, use '-' as the filename.
const myFileStream = filename === '-' ?
  process.stdin :
  fs.createReadStream(filename);

myFileStream
  .pipe(pcapNgParser)
  .on('data', parsedPacket => {
    console.log(parsedPacket);
    try {
      console.log(
        EtherFrame.fromBuffer(parsedPacket.data, pcapNgParser.endianess)
      );
    } catch (ex) {
      // Catches for type codes not currently supported by ether-frame
      console.log('ETHERFRAME ERROR', ex.message);
    }
  })
  .on('section', sectionHeader => {
    console.log('SECTION', sectionHeader);
  })
  .on('interface', interfaceInfo => {
    console.log('INTERFACE', interfaceInfo);
  })
  .on('blockType', t => {
    console.log(`Unimplemented block type: ${t}`);
  })
  .on('names', nm => {
    console.log('NAMES', nm);
  })
  .on('error', er => {
    console.log('ERROR', er);
  });
