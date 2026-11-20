import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDpkgSourceVersions, parseUbuntuOval } from '../cs3-scan-agent.mjs';

const id = (name) => `oval:com.ubuntu.jammy:def:${name}`;
// OpenSCAP can embed source definitions; only definition_id/result tags are evaluation records.
const results = (...definitions) => `<oval_results><definitions><definition id="${id('100')}" class="patch" /></definitions><results><system><definitions>${definitions.join('')}</definitions></system></results></oval_results>`;
const result = (name, value) => `<definition result="${value}" definition_id="${id(name)}" />`;
const source = (...definitions) => `<oval_definitions><definitions>${definitions.join('')}</definitions></oval_definitions>`;

test('Ubuntu OVAL reports only true patches with CVE, package, severity, and fix evidence', () => {
  const xml = source(`
    <definition id="${id('1')}" class="inventory"><metadata><title>Jammy</title></metadata></definition>
    <definition class="patch" id="${id('100')}">
      <metadata>
        <title>USN-100-1 -- OpenSSL &amp; kernel</title>
        <reference ref_url="https://ubuntu.com/security/notices/USN-100-1" ref_id="USN-100-1" source="USN" />
        <reference source="CVE" ref_id="CVE-2026-0001" />
        <reference ref_id="CVE-2026-0002" source="CVE" />
        <advisory><severity>High</severity>
          <cve cvss_score="7.8" cvss_severity="high">CVE-2026-0001</cve>
          <cve cvss_severity="low">CVE-2026-0002</cve>
        </advisory>
      </metadata>
      <criteria>
        <criterion comment="Ubuntu 22.04 LTS (jammy) is installed" />
        <criterion comment="openssl source package in jammy is affected and has been fixed (note: '3.0.2-0ubuntu1.2')." />
        <criterion comment="'linux' kernel in jammy was vulnerable but has been fixed (note: '5.15.0-30.31')." />
        <criterion comment="openssl source package in jammy is affected and has been fixed (note: '3.0.2-0ubuntu1.2')." />
      </criteria>
    </definition>
    <definition id="${id('200')}" class="patch"><metadata>
      <title>USN-200-1 -- not applicable</title>
      <reference source="USN" ref_id="USN-200-1" /><reference source="CVE" ref_id="CVE-2026-9999" />
      <advisory><severity>Critical</severity></advisory>
    </metadata><criteria><criterion comment="falsepkg source package has been fixed (note: '2')." /></criteria></definition>
    <definition id="${id('300')}" class="patch"><metadata>
      <title>USN-300-2 -- Git regression update</title>
      <reference source="USN" ref_id="USN-300-2" ref_url="https://ubuntu.com/security/notices/USN-300-2" />
      <advisory><severity>Medium</severity></advisory>
    </metadata><criteria><criterion comment="git source package in jammy is affected and has been fixed (note: '1:2.34.1-1ubuntu1.2')." /></criteria></definition>`);
  const parsed = parseUbuntuOval(xml, results(
    '<definition definition_id="oval:com.ubuntu.jammy:def:1" result="true" />',
    result('100', 'true'), result('200', 'false'), result('300', 'true'),
  ), 'jammy', { openssl: '3.0.2-0ubuntu1.1', linux: '5.15.0-27.28', git: '1:2.34.1-1ubuntu1.1' });

  assert.equal(parsed.evaluatedDefinitions, 4);
  assert.equal(parsed.evaluatedPatchDefinitions, 3);
  assert.equal(parsed.truePatchDefinitions, 2);
  assert.equal(parsed.findings.length, 5);
  assert.ok(!parsed.findings.some((finding) => finding.cve === 'CVE-2026-9999'));
  const openssl = parsed.findings.find((finding) => finding.cve === 'CVE-2026-0001' && finding.package === 'openssl');
  assert.deepEqual(openssl, {
    cve: 'CVE-2026-0001', package: 'openssl', title: 'USN-100-1 -- OpenSSL & kernel',
    installedVersion: '3.0.2-0ubuntu1.1', fixedVersion: '3.0.2-0ubuntu1.2', severity: 'HIGH', cvss: 7.8,
    remediationGuide: 'Update openssl to 3.0.2-0ubuntu1.2 (USN-100-1): https://ubuntu.com/security/notices/USN-100-1',
  });
  const kernelLow = parsed.findings.find((finding) => finding.cve === 'CVE-2026-0002' && finding.package === 'linux');
  assert.equal(kernelLow.severity, 'LOW');
  assert.equal(kernelLow.cvss, 0);
  const advisoryOnly = parsed.findings.find((finding) => finding.package === 'git');
  assert.equal(advisoryOnly.cve, 'USN-300-2');
  assert.equal(advisoryOnly.severity, 'MEDIUM');
});

test('Ubuntu OVAL represents a true Livepatch notice without inventing a package version', () => {
  const xml = source(`<definition id="${id('861')}" class="patch"><metadata>
    <title>LSN-0086-1 -- Kernel Live Patch Security Notice</title>
    <reference source="LSN" ref_id="LSN-0086-1" ref_url="https://ubuntu.com/security/notices/LSN-0086-1" />
    <reference source="CVE" ref_id="CVE-2022-21499" />
    <advisory><severity>High</severity><cve cvss_severity="medium" cvss_score="6.7">CVE-2022-21499</cve></advisory>
  </metadata><criteria><criterion comment="Is livepatch installed?" /><criterion comment="livepatch" /></criteria></definition>`);
  const parsed = parseUbuntuOval(xml, results(result('861', 'true')), 'jammy', { 'canonical-livepatch': '10.0' });
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].package, 'canonical-livepatch');
  assert.equal(parsed.findings[0].installedVersion, '');
  assert.equal(parsed.findings[0].fixedVersion, '');
  assert.match(parsed.findings[0].remediationGuide, /LSN-0086-1/);
});

test('Ubuntu OVAL accepts a valid evaluated feed with zero vulnerable definitions', () => {
  const xml = source(`<definition id="${id('100')}" class="patch"><metadata>
    <title>USN-100-1</title><reference source="USN" ref_id="USN-100-1" />
    <reference source="CVE" ref_id="CVE-2026-0001" /><advisory><severity>Low</severity></advisory>
  </metadata><criteria><criterion comment="openssl source package has been fixed (note: '3.0.2')." /></criteria></definition>`);
  const parsed = parseUbuntuOval(xml, results(result('100', 'false')), 'jammy');
  assert.equal(parsed.evaluatedPatchDefinitions, 1);
  assert.equal(parsed.truePatchDefinitions, 0);
  assert.deepEqual(parsed.findings, []);
});

test('Ubuntu OVAL rejects malformed, mismatched, or unsupported true results', () => {
  const unsupported = source(`<definition id="${id('100')}" class="patch"><metadata>
    <title>USN-100-1</title><reference source="USN" ref_id="USN-100-1" />
  </metadata><criteria><criterion comment="unrecognized test" /></criteria></definition>`);
  assert.throws(() => parseUbuntuOval(unsupported, results(result('100', 'true')), 'jammy'), /No supported package criteria/);
  assert.throws(() => parseUbuntuOval(unsupported, results(result('100', 'true')), 'jammy\'; invalid'), /validation failed/);
  assert.throws(() => parseUbuntuOval(unsupported.replaceAll('com.ubuntu.jammy', 'com.ubuntu.noble'), results(result('100', 'true')), 'jammy'), /validation failed/);
  assert.throws(() => parseUbuntuOval(unsupported, '<oval_results><definitions /></oval_results>', 'jammy'), /no evaluated definitions/);
  assert.throws(() => parseUbuntuOval(unsupported, results('<definition definition_id="oval:com.ubuntu.jammy:def:999" result="false" />'), 'jammy'), /no evaluated Ubuntu patch definitions/);
});

test('dpkg source inventory uses source versions and suppresses conflicting values', () => {
  const inventory = parseDpkgSourceVersions([
    'libssl3:amd64\t3.0.2-0ubuntu1.1\topenssl\t3.0.2-0ubuntu1.1',
    'libssl3:i386\t3.0.2-0ubuntu1.1\topenssl\t3.0.2-0ubuntu1.1',
    'git\t1:2.34.1-1ubuntu1.1\t\t',
    'one\t1\tconflicted\t1',
    'two\t2\tconflicted\t2',
  ].join('\n'));
  assert.equal(inventory.installedPackages, 5);
  assert.equal(inventory.sourceVersions.openssl, '3.0.2-0ubuntu1.1');
  assert.equal(inventory.sourceVersions.git, '1:2.34.1-1ubuntu1.1');
  assert.equal(inventory.sourceVersions.conflicted, '');
});
