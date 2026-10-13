import { pathToFileURL } from 'node:url';

// Docker tags cannot contain SemVer build metadata (+). Release tags use vX.Y.Z[-pre].
export function parseVersion(text) {
  const match = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(text);
  if (!match) throw new Error(`Invalid release tag: ${text}`);
  const pre = match[4]?.split('.') ?? [];
  if (pre.some(part => /^\d+$/.test(part) && part.length > 1 && part[0] === '0')) throw new Error(`Leading zero in prerelease: ${text}`);
  return { core: match.slice(1, 4).map(BigInt), pre };
}

export function compareVersions(a, b) {
  a = parseVersion(a); b = parseVersion(b);
  for (let i = 0; i < 3; i++) if (a.core[i] !== b.core[i]) return a.core[i] > b.core[i] ? 1 : -1;
  if (a.pre.length === 0 || b.pre.length === 0) return a.pre.length === b.pre.length ? 0 : a.pre.length === 0 ? 1 : -1;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    if (a.pre[i] === undefined || b.pre[i] === undefined) return a.pre[i] === undefined ? -1 : 1;
    const x = a.pre[i], y = b.pre[i];
    if (x === y) continue;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx !== ny) return nx ? -1 : 1;
    if (nx) return BigInt(x) > BigInt(y) ? 1 : -1;
    return x > y ? 1 : -1;
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [command, ...versions] = process.argv.slice(2);
    if (command === 'validate' && versions.length === 1) parseVersion(versions[0]);
    else if (command === 'ge' && versions.length === 2) process.exitCode = compareVersions(...versions) >= 0 ? 0 : 1;
    else if (command === 'max' && versions.length > 0) console.log(versions.reduce((a, b) => compareVersions(a, b) >= 0 ? a : b));
    else throw new Error('Usage: version.mjs validate VERSION | ge A B | max VERSIONS...');
  } catch (error) { console.error(error.message); process.exitCode = 2; }
}
