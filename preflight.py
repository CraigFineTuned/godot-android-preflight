#!/usr/bin/env python3
"""Private Android preflight v0.1.1. No signing, publishing, network or auto-install."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET
from pixels import measure_pixels

VERSION = '0.1.1'
ANDROID = '{http://schemas.android.com/apk/res/android}'


class EvidenceError(Exception):
    pass


class NoEvidenceError(EvidenceError):
    """Instrument/setup unavailable; never report an observed artifact defect."""
    pass


def run(argv, timeout=45, binary=False):
    """Argument vectors only. Never include vendor output or local paths in reports."""
    try:
        p = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise NoEvidenceError('tool unavailable or timed out')
    if binary:
        return p.returncode, p.stdout
    return p.returncode, (p.stdout + p.stderr).decode('utf-8', errors='replace')


def sdk_tool(sdk, name):
    suffix = '.exe' if os.name == 'nt' else ''
    if name == 'apksigner' and os.name == 'nt':
        # Invoke the JAR directly, avoiding Windows batch shell quoting.
        jar = Path(sdk) / 'build-tools' / sdk_version(sdk) / 'lib' / 'apksigner.jar'
        if not jar.is_file():
            raise NoEvidenceError('SDK signature reader missing')
        return ['java', '-jar', str(jar)]
    if name == 'adb':
        return [str(Path(sdk) / 'platform-tools' / (name + suffix))]
    return [str(Path(sdk) / 'build-tools' / sdk_version(sdk) / (name + suffix))]


def sdk_version(sdk):
    root = Path(sdk) / 'build-tools'
    versions = [p.name for p in root.iterdir() if re.fullmatch(r'\d+(?:\.\d+)+', p.name)
                and (p / ('aapt2.exe' if os.name == 'nt' else 'aapt2')).is_file()]
    if not versions:
        raise EvidenceError('SDK build tools missing')
    return max(versions, key=lambda x: tuple(map(int, x.split('.'))))


def parse_badging(text):
    p = re.search(r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']*)'", text, re.M)
    target = re.search(r"^targetSdkVersion:'(\d+)'", text, re.M)
    if not p or not target:
        raise EvidenceError('required APK manifest fields unreadable')
    return {'package': p[1], 'versionCode': int(p[2]), 'versionName': p[3],
            'targetApi': int(target[1]), 'debuggable': bool(re.search(r'^application-debuggable\s*$', text, re.M)),
            'permissions': sorted(set(re.findall(r"^uses-permission(?:-sdk-\d+)?: name='([^']+)'", text, re.M)))}


def parse_bundle_manifest(text):
    try:
        node = ET.fromstring(text)
        app = node.find('application')
        sdk = node.find('uses-sdk')
        if app is None or sdk is None or node.tag != 'manifest':
            raise ValueError()
        debug = app.get(ANDROID + 'debuggable', 'false')
        if debug not in ('true', 'false'):
            raise ValueError()
        return {'package': node.attrib['package'], 'versionCode': int(node.attrib[ANDROID + 'versionCode']),
                'versionName': node.get(ANDROID + 'versionName', ''),
                'targetApi': int(sdk.attrib[ANDROID + 'targetSdkVersion']), 'debuggable': debug == 'true',
                'permissions': sorted(set(n.attrib[ANDROID + 'name'] for n in node
                                         if n.tag in ('uses-permission', 'uses-permission-sdk-23')))}
    except (ET.ParseError, KeyError, ValueError):
        raise EvidenceError('required bundle manifest fields unreadable')


def elf_segments(data):
    """Read ELF program headers; no extraction or execution of native code."""
    if data[:4] != b'\x7fELF' or len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise EvidenceError('invalid ELF')
    endian = '<' if data[5] == 1 else '>'
    is64 = data[4] == 2
    try:
        off = struct.unpack_from(endian + ('Q' if is64 else 'I'), data, 32 if is64 else 28)[0]
        size, count = struct.unpack_from(endian + 'HH', data, 54 if is64 else 42)
        if count == 0 or count == 65535 or size < (56 if is64 else 32) or off + size * count > len(data):
            raise EvidenceError('invalid ELF header table')
        headers = []
        for i in range(count):
            x = struct.unpack_from(endian + ('IIQQQQQQ' if is64 else 'IIIIIIII'), data, off + i * size)
            headers.append({'type': x[0], 'offset': x[2] if is64 else x[1],
                            'vaddr': x[3] if is64 else x[2], 'filesz': x[5] if is64 else x[4],
                            'memsz': x[6] if is64 else x[5], 'alignment': x[7]})
        if not any(h['type'] == 1 for h in headers):
            raise EvidenceError('ELF has no load segments')
        if any(h['offset'] + h['filesz'] > len(data) for h in headers):
            raise EvidenceError('ELF segment exceeds file')
        return headers
    except struct.error:
        raise EvidenceError('truncated ELF')


def alignment_ok(headers):
    loads = [h for h in headers if h['type'] == 1]
    return bool(loads) and all(h['alignment'] >= 16384 and h['alignment'] & (h['alignment'] - 1) == 0
                             and (h['vaddr'] - h['offset']) % 16384 == 0 for h in loads)


def relro_ok(headers):
    return all((h['vaddr'] + h['memsz']) % 16384 == 0 for h in headers if h['type'] == 0x6474e552)


def safe_archive(z):
    names = z.namelist()
    if len(names) != len(set(names)):
        raise EvidenceError('duplicate archive members')
    if len(names) > 20000:
        raise EvidenceError('archive member limit exceeded')
    total = 0
    for info in z.infolist():
        p = PurePosixPath(info.filename)
        if p.is_absolute() or '..' in p.parts or '\\' in info.filename or ':' in info.filename:
            raise EvidenceError('unsafe archive path')
        total += info.file_size
        if total > 2 * 1024 ** 3 or info.file_size > 512 * 1024 ** 2 or info.flag_bits & 1:
            raise EvidenceError('archive resource or encryption limit exceeded')
        if info.file_size > max(1024 ** 2, info.compress_size * 1000):
            raise EvidenceError('archive expansion limit exceeded')
    if z.testzip() is not None:
        raise EvidenceError('archive CRC failure')


def policy_checks(meta, args):
    return [
        ('identity', meta['package'] == args.package and meta['versionCode'] == args.version_code
         and (args.version_name is None or meta['versionName'] == args.version_name), meta),
        ('version_monotonicity', None if args.previous_code is None else meta['versionCode'] > args.previous_code,
         {'previousCode': args.previous_code, 'observedCode': meta['versionCode'], 'baselineIsCallerSupplied': True,
          'reason': 'baseline unavailable' if args.previous_code is None else 'compared with supplied baseline'}),
        ('debug_state', not meta['debuggable'], {'debuggable': meta['debuggable'], 'releaseBuildProven': False}),
        ('target_api', meta['targetApi'] >= args.min_target, {'observed': meta['targetApi'], 'minimum': args.min_target}),
        ('permissions', set(meta['permissions']) <= set(args.allow_permission),
         {'observed': meta['permissions'], 'allowed': sorted(args.allow_permission)})]


def signature_ok(kind, code, text):
    if code:
        return False
    if kind == 'apk':
        return bool(re.search(r'Verified using v2 scheme .*: true', text))
    return bool(re.search(r'(?im)^jar verified\.', text)) and not re.search(r'(?i)unsigned entr|jar is unsigned', text)


def require_clear_keyguard(text):
    values = re.findall(r'(?m)^\s*(?:showing|mIsShowing)=(true|false)\s*$', text)
    if not values:
        raise NoEvidenceError('keyguard state could not be observed')
    if 'true' in values:
        raise NoEvidenceError('emulator keyguard is showing; operator must prepare an unlocked test surface')


def smoke(apk, package, args, report):
    """Opt-in, emulator-only, absent-package installation. Never overwrite/uninstall/clear."""
    if not re.fullmatch(r'emulator-\d+', args.smoke_emulator or '') or not (args.allow_install or getattr(args, 'observe_installed', False)):
        raise EvidenceError('smoke requires explicit emulator serial and install or observation consent')
    adb = sdk_tool(args.sdk, 'adb') + ['-s', args.smoke_emulator]
    def call(*argv, binary=False):
        code, data = run(adb + list(argv), timeout=90, binary=binary)
        if code:
            raise NoEvidenceError('emulator command failed at ' + argv[0])
        return data
    if call('shell', 'getprop', 'sys.boot_completed').strip() != '1':
        raise NoEvidenceError('emulator not booted')
    # pm path returns nonzero for an absent package, so inspect both return and output.
    code, existing = run(adb + ['shell', 'pm', 'path', package])
    if getattr(args, 'observe_installed', False):
        paths = existing.strip().splitlines()
        if code or len(paths) != 1 or not re.fullmatch(r'package:/[A-Za-z0-9_./+=~-]+\.apk', paths[0]):
            raise NoEvidenceError('single installed APK path could not be proved')
    else:
        if code not in (0, 1) or (existing.strip() and not existing.strip().startswith('package:')):
            raise NoEvidenceError('package absence could not be observed')
        if existing.strip():
            raise EvidenceError('package already installed; no overwrite')
        installation = call('install', str(apk))
        if 'Success' not in installation:
            raise EvidenceError('installation did not succeed')
        code, existing = run(adb + ['shell', 'pm', 'path', package])
        paths = existing.strip().splitlines()
        if code or len(paths) != 1 or not re.fullmatch(r'package:/[A-Za-z0-9_./+=~-]+\.apk', paths[0]):
            raise NoEvidenceError('new installed APK path could not be proved')
    # Read back exact bytes for BOTH new installation and installed observation.
    # An install-success message or matching versionCode alone is not byte identity.
    digest_output = call('shell', 'sha256sum', paths[0][8:]).split()
    if not digest_output or not re.fullmatch(r'[0-9a-f]{64}', digest_output[0]):
        raise NoEvidenceError('installed APK digest unavailable')
    digest = digest_output[0]
    if digest != report['artifact']['sha256']:
        raise EvidenceError('installed APK bytes differ from supplied artifact')
    # Capture validity requires an awake screen; reject keyguard/black pixels instead
    # of pretending process liveness proves presentation. Never dismiss a lock screen.
    call('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
    require_clear_keyguard(call('shell', 'dumpsys', 'window', 'policy'))
    installed = call('shell', 'dumpsys', 'package', package)
    if not re.search(r'\bversionCode=' + str(args.version_code) + r'\b', installed):
        raise EvidenceError('installed version identity mismatch')
    components = call('shell', 'cmd', 'package', 'resolve-activity', '--brief', package).strip().splitlines()
    if not components:
        raise NoEvidenceError('launcher query returned no evidence')
    component = components[-1]
    if not component.startswith(package + '/') or not re.fullmatch(r'[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+', component):
        raise EvidenceError('launcher activity unresolved')
    launch = call('shell', 'am', 'start', '-W', '-n', component)
    if 'Status: ok' not in launch or re.search(r'(?i)error|exception', launch):
        raise EvidenceError('activity launch rejected')
    frames = []
    for i in range(2):
        time.sleep(5)
        pid = call('shell', 'pidof', package).strip()
        foreground = call('shell', 'dumpsys', 'activity', 'activities')
        require_clear_keyguard(call('shell', 'dumpsys', 'window', 'policy'))
        if not pid or not any(package + '/' in line for line in foreground.splitlines()
                              if 'ResumedActivity' in line or 'topResumedActivity' in line):
            raise EvidenceError('app not alive and foreground')
        png = call('exec-out', 'screencap', '-p', binary=True)
        out = Path(args.evidence_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / ('frame-%d.png' % i)).write_bytes(png)
        metrics = measure_pixels(png)
        observed = {'sha256': hashlib.sha256(png).hexdigest(), 'metrics': metrics}
        report.setdefault('smokeObservations', []).append(observed)
        if metrics['lit'] < .05 or metrics['flat'] >= .995:
            raise EvidenceError('black or flat rendered frame')
        if args.expect_canary and (metrics['magenta'] < .1 or metrics['cyan'] < .1):
            raise EvidenceError('canary colours absent')
        frames.append(observed)
    return {'surface': 'emulator', 'samples': frames, 'secondsBetweenSamples': 5,
            'installedArtifactSha256': digest, 'installedVersionCode': args.version_code,
            'installationLeftInEmulator': True, 'performanceOrGameplayAcceptance': False}


def inspect(args):
    report = {'schemaVersion': 1, 'toolVersion': VERSION, 'scope': 'artifact preflight', 'checks': []}
    def add(name, state, evidence=None):
        report['checks'].append({'id': name, 'status': state, 'evidence': evidence or {}})
    def check(name, fn):
        try:
            okay, evidence = fn()
            add(name, 'UNKNOWN' if okay is None else 'PASS' if okay else 'FAIL', evidence)
        except (EvidenceError, OSError, ValueError, zipfile.BadZipFile, struct.error):
            add(name, 'UNKNOWN', {'reason': 'required evidence unavailable or invalid'})
    path = Path(args.artifact)
    if not path.is_file() or path.suffix.lower() not in ('.apk', '.aab'):
        add('artifact', 'UNKNOWN', {'reason': 'APK or AAB input unavailable'})
        report['status'] = 'UNKNOWN'
        return report
    kind = path.suffix.lower()[1:]
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    report['artifact'] = {'kind': kind, 'sha256': h.hexdigest(), 'sizeBytes': path.stat().st_size}
    add('size', 'PASS' if path.stat().st_size <= args.max_bytes else 'FAIL',
        {'bytes': path.stat().st_size, 'maximumBytes': args.max_bytes, 'downloadSizeEstimate': False})
    try:
        with zipfile.ZipFile(path) as z:
            safe_archive(z)
            add('archive_integrity', 'PASS', {'members': len(z.namelist())})
            native = [i for i in z.infolist() if re.fullmatch(r'(?:[^/]+/)?lib/[^/]+/[^/]+\.so', i.filename)]
            headers = [elf_segments(z.read(i)) for i in native]
            libraries = [{'member': info.filename,
                          'loadAlignments': [h['alignment'] for h in hs if h['type'] == 1],
                          'loadAddressOffsetMod16384': [(h['vaddr'] - h['offset']) % 16384 for h in hs if h['type'] == 1],
                          'relroEndMod16384': [(h['vaddr'] + h['memsz']) % 16384 for h in hs if h['type'] == 0x6474e552]}
                         for info, hs in zip(native, headers)]
            add('elf_16k_load_alignment', 'PASS' if all(alignment_ok(x) for x in headers) else 'FAIL',
                {'libraries': libraries, 'noNativeLibraries': not headers, 'runtime16kProven': False})
            add('elf_16k_relro_end', 'PASS' if all(relro_ok(x) for x in headers) else 'FAIL', {'libraries': libraries})
    except (EvidenceError, OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        add('archive_integrity', 'FAIL', {'reason': 'invalid or unsupported archive or native library'})
        add('elf_16k_load_alignment', 'UNKNOWN')
        add('elf_16k_relro_end', 'UNKNOWN')
    try:
        if kind == 'apk':
            code, text = run(sdk_tool(args.sdk, 'aapt2') + ['dump', 'badging', path])
            if code:
                raise EvidenceError('manifest reader failed')
            meta = parse_badging(text)
        else:
            if not args.bundletool:
                raise EvidenceError('bundletool required for observed AAB identity')
            code, text = run(['java', '-jar', args.bundletool, 'dump', 'manifest', '--bundle=' + str(path)])
            if code:
                raise EvidenceError('bundle manifest reader failed')
            meta = parse_bundle_manifest(text)
        for name, okay, evidence in policy_checks(meta, args):
            add(name, 'UNKNOWN' if okay is None else 'PASS' if okay else 'FAIL', evidence)
    except (EvidenceError, OSError, KeyError, ValueError):
        for name in ('identity', 'version_monotonicity', 'debug_state', 'target_api', 'permissions'):
            add(name, 'UNKNOWN', {'reason': 'manifest was not observed'})
    def sig():
        if kind == 'apk':
            code, text = run(sdk_tool(args.sdk, 'apksigner') + ['verify', '--verbose', path])
        else:
            code, text = run(['jarsigner', '-verify', path])
        return signature_ok(kind, code, text), {'cryptographicVerificationAttempted': True, 'trustedSignerIdentityProven': False,
                                              'apkV2Required': kind == 'apk'}
    check('signature', sig)
    if kind == 'apk':
        check('zip_16k_alignment', lambda: (run(sdk_tool(args.sdk, 'zipalign') + ['-c', '-P', '16', '4', path])[0] == 0,
                                          {'vendor': 'zipalign', 'pageKiB': 16}))
    else:
        add('zip_16k_alignment', 'UNKNOWN', {'reason': 'delivery APK alignment requires generated APKs; AAB offsets are not delivery offsets'})
    # Diagnostic smoke may run despite a readiness finding, but identity, archive,
    # signature and non-debug safety gates must be observed and pass first.
    smoke_safety = {'identity', 'archive_integrity', 'signature', 'debug_state'}
    if args.smoke_emulator and kind == 'apk' and all(c['status'] == 'PASS' for c in report['checks'] if c['id'] in smoke_safety):
        try:
            evidence = smoke(path, args.package, args, report)
            add('emulator_smoke', 'PASS', evidence)
        except NoEvidenceError as error:
            add('emulator_smoke', 'UNKNOWN', {'reason': str(error)})
        except EvidenceError as error:
            add('emulator_smoke', 'FAIL', {'reason': str(error)})
        except (OSError, ValueError, struct.error, zlib.error):
            add('emulator_smoke', 'UNKNOWN', {'reason': 'rendered evidence unreadable'})
    else:
        add('emulator_smoke', 'UNKNOWN', {'reason': 'not run; requires APK identity/signature/archive/non-debug gates, explicit emulator serial and --allow-install'})
    states = [c['status'] for c in report['checks']]
    current = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            current.update(b)
    if current.hexdigest() != report['artifact']['sha256']:
        add('artifact_stability', 'FAIL', {'reason': 'artifact bytes changed during inspection'})
        states.append('FAIL')
    report['status'] = 'FAIL' if 'FAIL' in states else 'UNKNOWN' if 'UNKNOWN' in states else 'PASS'
    return report


def human(report):
    lines = ['Android preflight ' + VERSION, 'Result: ' + report['status'],
             'Scope: artifact and optional emulator smoke; no Play, gameplay or performance approval.']
    if report.get('sampleKind') == 'SYNTHETIC':
        lines.insert(0, 'SYNTHETIC FORMAT EXAMPLE: vendor/transport stubs; not real artifact acceptance.')
    if 'artifact' in report:
        lines += ['Artifact SHA256: ' + report['artifact']['sha256'], 'Bytes: ' + str(report['artifact']['sizeBytes'])]
    identity = next((c for c in report['checks'] if c['id'] == 'identity'), None)
    if identity and 'package' in identity['evidence']:
        m = identity['evidence']
        lines += ['Package: ' + m['package'], 'Version: %s (code %d)' % (m['versionName'], m['versionCode']),
                  'Target API: ' + str(m['targetApi']), 'Debuggable: ' + str(m['debuggable']).lower(),
                  'Permissions: ' + (', '.join(m['permissions']) or 'none declared')]
    lines += [c['id'] + ': ' + c['status'] for c in report['checks']]
    relro = next((c for c in report['checks'] if c['id'] == 'elf_16k_relro_end'), None)
    if relro and relro['status'] == 'FAIL':
        for library in relro['evidence'].get('libraries', []):
            if any(library['relroEndMod16384']):
                lines.append('RELRO end mismatch: %s; modulo 16384 = %s' %
                             (library['member'], library['relroEndMod16384']))
    lines.append('UNKNOWN blocks aggregate PASS. See JSON evidence and limitations.')
    return '\n'.join(lines) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('artifact')
    p.add_argument('--sdk', required=True)
    p.add_argument('--package', required=True)
    p.add_argument('--version-code', type=int, required=True)
    p.add_argument('--version-name')
    p.add_argument('--previous-code', type=int)
    p.add_argument('--min-target', type=int, required=True)
    p.add_argument('--max-bytes', type=int, required=True)
    p.add_argument('--allow-permission', action='append', default=[])
    p.add_argument('--bundletool')
    p.add_argument('--smoke-emulator')
    p.add_argument('--allow-install', action='store_true')
    p.add_argument('--observe-installed', action='store_true', help='require exact installed APK SHA256; no install/overwrite')
    p.add_argument('--expect-canary', action='store_true')
    p.add_argument('--evidence-dir', default='smoke-evidence')
    p.add_argument('--json', required=True)
    p.add_argument('--text', required=True)
    args = p.parse_args()
    if args.version_code < 1 or args.min_target < 1 or args.max_bytes < 1:
        p.error('policy integers must be positive')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', args.package):
        p.error('package must be a dotted Android identifier')
    if args.allow_install and args.observe_installed:
        p.error('choose installation or installed observation, not both')
    try:
        report = inspect(args)
    except (EvidenceError, OSError):
        report = {'schemaVersion': 1, 'toolVersion': VERSION, 'status': 'UNKNOWN',
                  'checks': [{'id': 'instrument', 'status': 'UNKNOWN', 'evidence': {'reason': 'tool environment unavailable'}}]}
    Path(args.json).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    Path(args.text).write_text(human(report), encoding='utf-8')
    print(human(report), end='')
    return {'PASS': 0, 'FAIL': 1, 'UNKNOWN': 2}[report['status']]


if __name__ == '__main__':
    sys.exit(main())
