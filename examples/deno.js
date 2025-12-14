#!/usr/bin/env -S deno --allow-read
import {PCAPNGParser} from '../lib/index.mjs';
const pcapNgParser = new PCAPNGParser();

pcapNgParser
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  });

const f = await Deno.open('examples/res/myfile.pcapng');
f.readable.pipeTo(pcapNgParser);
