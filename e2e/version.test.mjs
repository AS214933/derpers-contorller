import test from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, parseVersion } from './version.mjs';

test('stable release ordering is numeric and latest never moves backward', () => {
  assert.equal(compareVersions('v1.10.0', 'v1.9.99'), 1);
  assert.equal(compareVersions('v1.0.0', 'v2.0.0'), -1);
  assert.equal(compareVersions('v2.1.3', 'v2.1.3'), 0);
  assert.equal(compareVersions('v999999999999999999999.0.0', 'v999999999999999999998.0.0'), 1);
});
test('SemVer prereleases precede stable and numeric identifiers compare numerically', () => {
  assert.equal(compareVersions('v1.0.0-rc.10', 'v1.0.0-rc.2'), 1);
  assert.equal(compareVersions('v1.0.0-rc.1', 'v1.0.0'), -1);
  assert.equal(compareVersions('v1.0.0-alpha', 'v1.0.0-alpha.1'), -1);
  assert.equal(compareVersions('v1.0.0-1', 'v1.0.0-alpha'), -1);
});
test('invalid or Docker-incompatible tags fail before changing registry tags', () => {
  for (const input of ['v01.2.3', 'v1.2', '1.2.3', 'v1.2.3-', 'v1.2.3-a..b', 'v1.2.3-01', 'v1.2.3+build']) assert.throws(() => parseVersion(input));
});
