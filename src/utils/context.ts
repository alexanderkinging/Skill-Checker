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
 * Context-aware helpers to reduce false positives.
 * Distinguishes between patterns in executable/instructional context
 * vs documentation/reference context.
 */

/**
 * Check if a line is inside a markdown code block by tracking
 * the fence state across all lines up to the target index.
 */
export function isInCodeBlock(lines: string[], lineIndex: number): boolean {
  let inBlock = false;
  for (let i = 0; i < lineIndex && i < lines.length; i++) {
    if (lines[i].trim().startsWith('```')) {
      inBlock = !inBlock;
    }
  }
  return inBlock;
}

/**
 * Check if a line is inside an inline code span (backticks).
 * e.g. `placeholder` or `sudo apt-get install foo`
 */
export function isInInlineCode(line: string, matchStart: number): boolean {
  // Count backticks before the match position
  let inCode = false;
  for (let i = 0; i < matchStart && i < line.length; i++) {
    if (line[i] === '`') inCode = !inCode;
  }
  return inCode;
}

/**
 * Check if a URL is a namespace/schema identifier rather than a network endpoint.
 *
 * Namespace URIs are used as unique identifiers in XML/OOXML/SVG/RDF etc.
 * They follow `http://` but are never actually fetched over the network.
 *
 * Detection heuristics (general, not whitelist-based):
 * - URL path contains year-like segments (e.g. /2006/, /2000/)
 * - Line contains xmlns, namespace, schema keywords
 * - URL path is a specification-style path (no file extension, hierarchical)
 * - URL appears as a string constant assignment, not in a fetch/curl context
 */
export function isNamespaceOrSchemaURI(url: string, line: string): boolean {
  // Context: line contains XML namespace indicators
  if (/\bxmlns\b/i.test(line)) return true;
  if (/\bnamespace\b/i.test(line)) return true;
  if (/\bschema[s]?\b/i.test(line) && !/(schema\.org)/i.test(url)) return true;

  // URL structure: path looks like a namespace identifier
  // e.g. http://schemas.openxmlformats.org/drawingml/2006/main
  // e.g. http://www.w3.org/2000/svg
  // Pattern: domain + hierarchical path with year segment, no query/file extension
  const parsed = parseURLPath(url);
  if (!parsed) return false;

  // Has a 4-digit year segment in path (very common in namespace URIs)
  if (/\/\d{4}\//.test(parsed.path)) {
    // And no query string or typical file extension → likely namespace
    if (!parsed.hasQuery && !parsed.hasFileExtension) return true;
  }

  return false;
}

/**
 * Check if a URL appears in an actual network request context on the same line.
 * i.e. the URL is an argument to fetch/curl/wget/axios etc.
 */
export function isInNetworkRequestContext(line: string): boolean {
  const networkPatterns = [
    /\bfetch\s*\(/i,
    /\bcurl\s+/i,
    /\bwget\s+/i,
    /\baxios\b/i,
    /\brequests?\.(get|post|put|delete|head)\s*\(/i,
    /\bhttp\.(get|request)\s*\(/i,
    /\bopen\s*\(\s*["'](?:GET|POST|PUT|DELETE)/i,
    /\bURLSession\b/,
    /\bInvoke-WebRequest\b/i,
  ];
  return networkPatterns.some((p) => p.test(line));
}

/**
 * Check if a line is in a documentation/guide section.
 * Looks for markdown list items describing setup/installation steps.
 */
export function isInDocumentationContext(
  lines: string[],
  lineIndex: number
): boolean {
  const line = lines[lineIndex];

  // Markdown list item describing a tool/prerequisite
  if (/^\s*[-*]\s+\*\*\w+\*\*\s*[:：]/.test(line)) return true;

  // Look at nearby headers for documentation keywords
  for (let i = lineIndex; i >= Math.max(0, lineIndex - 15); i--) {
    const l = lines[i];
    if (/^#{1,4}\s+.*(install|setup|prerequisite|requirement|depend|getting\s+started)/i.test(l)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a line is near a documentation/guide section header.
 * Similar to isInDocumentationContext but only checks headers, not list patterns.
 * Used for double-context reduction (code block + doc header).
 */
export function isNearDocumentationHeader(
  lines: string[],
  lineIndex: number
): boolean {
  for (let i = lineIndex; i >= Math.max(0, lineIndex - 15); i--) {
    const l = lines[i];
    if (/^#{1,4}\s+.*(install|setup|prerequisite|requirement|depend|getting\s+started|quickstart)/i.test(l)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a file path is a license/legal file (content is not executable instruction).
 */
export function isLicenseFile(filePath: string): boolean {
  const name = filePath.split('/').pop()?.toUpperCase() ?? '';
  const base = name.replace(/\.[^.]+$/, ''); // strip extension
  return /^(LICENSE|LICENCE|COPYING|NOTICE|AUTHORS|PATENTS)$/.test(base);
}

/**
 * Check if a URL points to localhost / loopback (no external attack surface).
 */
export function isLocalhostURL(url: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/i.test(url);
}

function parseURLPath(
  url: string
): { path: string; hasQuery: boolean; hasFileExtension: boolean } | null {
  try {
    const u = new URL(url);
    const hasQuery = u.search.length > 0;
    const lastSegment = u.pathname.split('/').pop() ?? '';
    const hasFileExtension = /\.\w{1,5}$/.test(lastSegment);
    return { path: u.pathname, hasQuery, hasFileExtension };
  } catch {
    return null;
  }
}
