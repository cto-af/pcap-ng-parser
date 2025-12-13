
# Overview
@cto.af/pcap-ng-parser is a stream-based module to decode, print and analyze
network traffic packets. With this module, you can read from an existing
.pcap or .pcapng file or connect it to an active stream.

Implements:
- [draft-ietf-opsawg-pcap-06](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-06.html)
- [draft-ietf-opsawg-pcapng-04](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html)

# Installation

This module is available through the [npm registry](https://www.npmjs.com/).

```bash
$ npm install @cto.af/pcap-ng-parser
```

# Usage

Note that the package on its own should work just fine in any modern JS
runtime (including browsers).  However, reading from a file requires some
runtime-dependent code.

## Via .pcapng File for Node.js
Here is a quick example of how to log out packets to the console from a valid .pcapng file named `myfile.pcapng`.

```javascript
import {PCAPNGParser} from '@cto.af/pcap-ng-parser';
import fs from 'node:fs/promises';
const parser = new PCAPNGParser();
const file = await fs.open('examples/res/myfile.pcapng');

parser
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  })
  .on('interface', interfaceInfo => {
    console.log(interfaceInfo);
  });
file.readableWebStream().pipeTo(parser);
```

In the example above, we create a new ReadableStream from our file and pipe to
the instance `parser` which will cause various events to fire.

## Via .pcapng file in Deno

```js
import {PCAPNGParser} from '@cto.af/pcap-ng-parser';
const pcapNgParser = new PCAPNGParser();

pcapNgParser
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  });

const f = await Deno.open('examples/res/myfile.pcapng');
f.readable.pipeTo(pcapNgParser);
```

## Via .pcapng file in Bun

```js
import {PCAPNGParser} from './src/index.ts';
const pcapNgParser = new PCAPNGParser();

pcapNgParser
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  })
  .on('interface', interfaceInfo => {
    console.log(interfaceInfo);
  });

const f = Bun.file('examples/res/myfile.pcapng');
f.stream().pipeTo(pcapNgParser);
```

## Via TCPDump in Node.JS

You can also pipe from TCPDump using `process.stdin` for a command line interaction.

```javascript
import {PCAPNGParser} from '@cto.af/pcap-ng-parser';
import {Readable} from 'node:stream';
const pcapNgParser = new PCAPNGParser();

pcapNgParser
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  })
  .on('interface', interfaceInfo => {
    console.log(interfaceInfo);
  });

Readable.toWeb(process.stdin).pipeTo(pcapNgParser);
```

```bash
$ sudo tcpdump -w - | node exampleAbove.js
```

Note that in order to utilize tcpdump you must be a superuser. Refer to [tcpdump documentation](http://www.tcpdump.org/manpages/tcpdump.1.html) for details.

Further note: If you specify an interface to listen on with "-i", tcpdump on some systems uses the old PCAP format, which PCAPNGParser will read just fine.

## Other Examples

Additional examples can be found in the [examples directory](/examples/).

It allows you to read from a sample capture file (the default), a file (if you
specify a file name on the command line), or stdin (if you specify "-" as the
input file).

# Class PCAPNGParser

PCAPNGParser is an extension of the [stream.Transform
class](https://nodejs.org/api/stream.html#stream_class_stream_transform). The
PCAPNGParser class fires the following events:

- `data`: An Enhanced Packet or Simple block was parsed.
- `section`: A Section Header block was parsed.
- `interface`: An Interface block was parsed.
- `names`: A Name Resolution block was parsed.
- `secrets`: A Decryption Secrets block was parsed.
- `stats`: An Interface Statistics block was parsed.
- `custom`: A Custom block was parsed.
- `blockType`: An unknown block type has been received.

See the full [API documentation](https://cto-af.github.io/pcap-ng-parser/) for
the types of the event parameters.

# Contribution

Refer to the the [Contribution Guide](/docs/CONTRIBUTING.md) for details on how to contribute.

# License

This module is covered under the BSD-3 Open Software License. Review the [License Documention](/docs/LICENSE.md) for more information.

# Provenance

This code was forked from https://github.com/CollinearGroup/pcap-ng-parser due
to lack of maintenance.  To simplify matters, copyright remains with the
original authors, including all changes made in this repository.  If the
original authors contact me (easiest would be to file an issue here), all of
this can be changed in any way that suits them.

The following things have been added:

- Fixed critical RangeError bug
- Made 'end' and 'finish' events fire correctly by removing broken _finish code.  Note that you have to add an event for 'data' to get these events or 'close'
  to fire, as with all Node Transform streams.
- Converted to ES6 (BREAKING)
- Added TypeScript types
- Brought dependencies up to date
- Added linting in @cto.af house style (to make maintenance easier)
- Added test coverage
- Renamed 'master' branch to 'main'
- Added Github Actions for testing and publishing
- Fixed broken links in readme and code
- Fixed issues with padding for options
- Now reads all options for supported block types, giving them names when known
- Fixed issues with reading unexpected sizes in input stream
- Added support for AbortSignals
- Added support for multiple Section Header blocks in a stream, including
  changes of endian-ness.
- Added support for Simple Packet blocks.
- Added support for Name Resolution blocks.
- Added support for Interface Statistics blocks.
- Added initial Support for Decryption Secrets blocks.
- Added support for Custom blocks.
- Added Enhanced Packet flag decoding.
- Added converting timestamps to JS Dates.  Does not handle timezones yet. (BREAKING)
- Added generate API documentation.
- Added implementation of old .pcap format, with auto-detection.
- Added decoding of linkType names.
- Switched to web streams and Uint8Array, for portability.  (BREAKING)

[![Tests](https://github.com/cto-af/pcap-ng-parser/actions/workflows/node.js.yml/badge.svg)](https://github.com/cto-af/pcap-ng-parser/actions/workflows/node.js.yml)
[![codecov](https://codecov.io/gh/cto-af/pcap-ng-parser/graph/badge.svg?token=Akjw67WYcn)](https://codecov.io/gh/cto-af/pcap-ng-parser)
