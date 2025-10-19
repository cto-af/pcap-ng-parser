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
// To pipe from tcpdump:
// const myFileStream = process.stdin
const myFileStream = fs.createReadStream('./examples/res/myfile.pcapng');

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
      console.log(ex.message);
    }
  })
  .on('interface', interfaceInfo => {
    console.log(interfaceInfo);
  });

