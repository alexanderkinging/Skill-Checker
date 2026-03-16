// Skill Checker - Security checker for Claude Code skills
// Copyright (C) 2026 Alexander Jin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

/**
 * IOC (Indicators of Compromise) database type definition and seed data.
 * Seed data is compiled from publicly available threat intelligence.
 */

export type DomainCategory = 'exfiltration' | 'tunnel' | 'oast' | 'paste' | 'c2';

export interface CategorizedDomains {
  exfiltration: string[];
  tunnel: string[];
  oast: string[];
  paste: string[];
  c2: string[];
}

export interface IOCDatabase {
  version: string;
  updated: string;
  c2_ips: string[];
  malicious_hashes: Record<string, string>;
  malicious_domains: CategorizedDomains;
  typosquat: {
    known_patterns: string[];
    protected_names: string[];
  };
  malicious_publishers: string[];
}

/**
 * Default embedded IOC seed data.
 * Sources: public threat intelligence reports, community advisories.
 */
export const DEFAULT_IOC: IOCDatabase = {
  version: '2026.03.16',
  updated: '2026-03-16',

  c2_ips: [
    '91.92.242.30',
    '91.92.242.39',
    '185.220.101.1',
    '185.220.101.2',
    '45.155.205.233',
  ],

  malicious_hashes: {
    // NOTE: Never add the SHA256 of an empty file (e3b0c44298fc...b855)
    // as it causes false positives on any empty file.
    'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2':
      'clawhavoc-exfiltrator',
  },

  malicious_domains: {
    exfiltration: [
      'webhook.site',
      'requestbin.com',
      'requestcatcher.com',
      'pipedream.com',
      'pipedream.net',
      'hookbin.com',
      'beeceptor.com',
      'postb.in',
      'webhook.lol',
      'requestinspector.com',
      'mockbin.org',
    ],
    tunnel: [
      'ngrok.io',
      'ngrok-free.app',
      'serveo.net',
      'localtunnel.me',
      'bore.pub',
      'localhost.run',
      'loca.lt',
      'telebit.cloud',
      'playit.gg',
      'portmap.io',
      'pagekite.me',
    ],
    oast: [
      'interact.sh',
      'oast.fun',
      'oastify.com',
      'dnslog.cn',
      'ceye.io',
      'burpcollaborator.net',
      'canarytokens.com',
      'requestrepo.com',
    ],
    paste: [
      'pastebin.com',
      'paste.ee',
      'hastebin.com',
      'ghostbin.com',
      'dpaste.org',
      'rentry.co',
      '0bin.net',
      'privatebin.net',
      'paste.mozilla.org',
    ],
    c2: [
      'evil.com',
      'malware.com',
      'exploit.in',
      'darkweb.onion',
    ],
  },

  typosquat: {
    known_patterns: [
      'clawhub1',
      'cllawhub',
      'clawhab',
      'moltbot',
      'claw-hub',
      'clawhub-pro',
    ],
    protected_names: [
      'clawhub',
      'secureclaw',
      'openclaw',
      'clawbot',
      'claude',
      'anthropic',
      'skill-checker',
    ],
  },

  malicious_publishers: [
    'clawhavoc',
    'phantom-tracker',
    'solana-wallet-drainer',
  ],
};
