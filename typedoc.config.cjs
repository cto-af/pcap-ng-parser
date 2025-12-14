'use strict';

/** @import {TypeDocOptions} from 'typedoc' */
/** @type {TypeDocOptions} */
module.exports = {
  entryPoints: [
    'src/index.ts',
  ],
  out: 'doc',
  cleanOutputDir: true,
  sidebarLinks: {
    GitHub: 'https://github.com/cto-af/pcap-ng-parser/',
    Spec: 'https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-04.html',
    Documentation: 'http://cto-af.github.io/pcap-ng-parser/',
  },
  navigation: {
    includeCategories: false,
    includeGroups: false,
  },
  categorizeByGroup: false,
  sort: ['static-first', 'alphabetical'],
  exclude: ['test/**'],
};
