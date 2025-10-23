
# Overview
@cto.af/pcap-ng-parser is a stream-based module to decode, print and analyze network traffic packets. With this module, you can read from an existing .pcapng file or connect it to an active stream.

# Installation

This module is available through the [npm registry](https://www.npmjs.com/).

```bash
$ npm install @cto.af/pcap-ng-parser
```

# Usage

## Via .pcapng File
Here is a quick example of how to log out packets to the console from a valid .pcapng file named `myfile.pcapng`.

```javascript
import PCAPNGParser from '@cto.af/pcap-ng-parser';
import fs from 'node:fs';

const pcapNgParser = new PCAPNGParser();
const myFileStream = fs.createReadStream('./myfile.pcapng');

myFileStream.pipe(pcapNgParser)
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  })
  .on('interface', interfaceInfo => {
    console.log(interfaceInfo);
  });
```

In the example above, we create a new Readable stream from our file and pipe the instance `pcapNgParser` which will read our packet data on the `_transform` event.

## Via TCPDump

You can also pipe from TCPDump using `process.stdin` for a command line interaction.

```javascript
import PCAPNGParser from '@cto.af/pcap-ng-parser';
const pcapNgParser = new PCAPNGParser();

process.stdin.pipe(pcapNgParser)
  .on('data', parsedPacket => {
    console.log(parsedPacket);
  })
  .on('interface', interfaceInfo => {
    console.log(interfaceInfo);
  });
```

```bash
$ sudo tcpdump -w - | node exampleAbove.js
```

Note that in order to utilize tcpdump you must be a superuser. Refer to [tcpdump documentation](http://www.tcpdump.org/manpages/tcpdump.1.html) for details.

Further note: If you specify an interface to listen on with "-i", tcpdump no
longer uses the pcapng format.

## Other Examples

Additional examples can be found in the [examples directory](/examples/).

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

[![Tests](https://github.com/cto-af/pcap-ng-parser/actions/workflows/node.js.yml/badge.svg)](https://github.com/cto-af/pcap-ng-parser/actions/workflows/node.js.yml)
[![codecov](https://codecov.io/gh/cto-af/pcap-ng-parser/graph/badge.svg?token=Akjw67WYcn)](https://codecov.io/gh/cto-af/pcap-ng-parser)
