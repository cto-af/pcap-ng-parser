#!/usr/bin/env bun
import {PCAPNGParser} from '../lib/index.mjs';
const pcapNgParser = new PCAPNGParser();

pcapNgParser
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  })
  .on('interface', interfaceInfo => {
    console.log(interfaceInfo);
  });

const file = new URL('./res/myfile.pcapng', import.meta.url);
const f = Bun.file(file);
f.stream().pipeTo(pcapNgParser);
