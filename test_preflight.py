"""Rejectable policy, parser and rendered-frame fixtures; no game data."""
import argparse
import copy
import io
import json
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib
from pathlib import Path
import preflight as pf
from pixels import measure_pixels


def png(pixel, width=40, height=80):
    rows = b''.join(b'\0' + b''.join(bytes(pixel(x, y)) + b'\xff' for x in range(width)) for y in range(height))
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')


def elf(alignment=16384, relro_end=16384, bits=64, big=False):
    endian = '>' if big else '<'
    if bits == 64:
        data = bytearray(176)
        data[:16] = b'\x7fELF\x02' + (b'\x02' if big else b'\x01') + b'\x01' + b'\0' * 9
        struct.pack_into(endian + 'HHIQQQIHHHHHH', data, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        struct.pack_into(endian + 'IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, len(data), 16384, alignment)
        struct.pack_into(endian + 'IIQQQQQQ', data, 120, 0x6474e552, 4, 0, 0, 0, 0, relro_end, 1)
    else:
        data = bytearray(116)
        data[:16] = b'\x7fELF\x01' + (b'\x02' if big else b'\x01') + b'\x01' + b'\0' * 9
        struct.pack_into(endian + 'HHIIIIIHHHHHH', data, 16, 3, 40, 1, 0, 52, 0, 0, 52, 32, 2, 0, 0, 0)
        struct.pack_into(endian + 'IIIIIIII', data, 52, 1, 0, 0, 0, len(data), 16384, 5, alignment)
        struct.pack_into(endian + 'IIIIIIII', data, 84, 0x6474e552, 0, 0, 0, 0, relro_end, 4, 1)
    return bytes(data)


def options(artifact='missing.apk'):
    return argparse.Namespace(artifact=str(artifact), sdk='absent-sdk', package='org.example.androidpreflight',
                              version_code=1, version_name='1.0', previous_code=0, min_target=36,
                              max_bytes=200000000, allow_permission=['android.permission.INTERNET'],
                              bundletool=None, smoke_emulator=None, allow_install=False, expect_canary=False,
                              evidence_dir='unused')


# Scripted transport supplies planted PNGs to the real smoke verifier.
# These are negative fixtures, never claimed as native positive evidence.
def assert_rejected(pixels, reason, wrong_hash=False, wrong_foreground=False, fresh_install=False):
    args = options(); args.smoke_emulator = 'emulator-5554'; args.observe_installed = True
    args.expect_canary = True
    package = args.package
    digest = '0' * 64
    path_queries = []
    def fixture_transport(argv, **kw):
        if 'getprop' in argv: return 0, '1\n'
        if 'path' in argv:
            path_queries.append(True)
            if fresh_install and len(path_queries) == 1: return 1, ''
            return 0, 'package:/data/app/generic/base.apk\n'
        if 'install' in argv: return 0, 'Success\n'
        if 'sha256sum' in argv: return 0, ('1' * 64 if wrong_hash else digest) + '  /data/app/generic/base.apk\n'
        if 'KEYCODE_WAKEUP' in argv: return 0, ''
        if 'window' in argv: return 0, 'showing=false\nmIsShowing=false\n'
        if 'dumpsys' in argv and 'package' in argv: return 0, 'versionCode=1\n'
        if 'resolve-activity' in argv: return 0, package + '/org.example.Main\n'
        if 'am' in argv: return 0, 'Status: ok\n'
        if 'pidof' in argv: return 0, '123\n'
        if 'activities' in argv: return 0, 'ResumedActivity: ' + ('org.example.other' if wrong_foreground else package) + '/org.example.Main\n'
        if 'screencap' in argv: return 0, pixels
        raise AssertionError('unexpected transport operation')
    with tempfile.TemporaryDirectory() as tmp:
        args.evidence_dir = tmp
        if fresh_install:
            args.observe_installed = False; args.allow_install = True
        with patch.object(pf, 'sdk_tool', return_value=['fixture-adb']), patch.object(pf, 'run', side_effect=fixture_transport), patch.object(pf.time, 'sleep'):
            try:
                result = pf.smoke(Path('fixture.apk'), package, args, {'artifact': {'sha256': digest}})
                if reason is None: return result
            except pf.EvidenceError as error:
                if reason not in str(error): raise AssertionError(str(error))
                return
            raise AssertionError('smoke accepted planted bad state')


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.meta = {'package': 'org.example.androidpreflight', 'versionCode': 1, 'versionName': '1.0',
                     'targetApi': 36, 'debuggable': False, 'permissions': ['android.permission.INTERNET']}
    def check_field(self, key, value, check):
        bad = dict(self.meta, **{key: value})
        verdict = {n: okay for n, okay, _ in pf.policy_checks(bad, options())}
        self.assertFalse(verdict[check])
    def test_clean(self):
        self.assertTrue(all(okay for _, okay, _ in pf.policy_checks(self.meta, options())))
    def test_wrong_package(self): self.check_field('package', 'org.example.wrong', 'identity')
    def test_wrong_code(self): self.check_field('versionCode', 2, 'identity')
    def test_wrong_name(self): self.check_field('versionName', '2.0', 'identity')
    def test_debug(self): self.check_field('debuggable', True, 'debug_state')
    def test_low_target(self): self.check_field('targetApi', 35, 'target_api')
    def test_permission(self): self.check_field('permissions', ['android.permission.CAMERA'], 'permissions')
    def test_non_monotonic(self):
        args = options(); args.previous_code = 1
        self.assertFalse(dict((n, okay) for n, okay, _ in pf.policy_checks(self.meta, args))['version_monotonicity'])
    def test_missing_baseline_is_not_a_pass(self):
        args = options(); args.previous_code = None
        self.assertIsNone(dict((n, okay) for n, okay, _ in pf.policy_checks(self.meta, args))['version_monotonicity'])
    def test_badging_requires_observation(self):
        with self.assertRaises(pf.EvidenceError): pf.parse_badging("package: name='x' versionCode='1' versionName='1'")
    def test_badging_debug_and_permission(self):
        m = pf.parse_badging("package: name='org.example.androidpreflight' versionCode='1' versionName='1.0'\ntargetSdkVersion:'36'\napplication-debuggable\nuses-permission-sdk-23: name='android.permission.CAMERA'\n")
        self.assertTrue(m['debuggable']); self.assertEqual(m['permissions'], ['android.permission.CAMERA'])
    def test_bundle_manifest_requires_observation(self):
        with self.assertRaises(pf.EvidenceError): pf.parse_bundle_manifest('<manifest package="x"/>')
    def test_bundle_manifest_debug(self):
        xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.androidpreflight" android:versionCode="1"><uses-sdk android:targetSdkVersion="36"/><application android:debuggable="true"/><uses-permission android:name="android.permission.CAMERA"/></manifest>'
        self.assertTrue(pf.parse_bundle_manifest(xml)['debuggable'])
    def test_unsigned_apk(self): self.assertFalse(pf.signature_ok('apk', 1, 'DOES NOT VERIFY'))
    def test_apk_v1_only(self): self.assertFalse(pf.signature_ok('apk', 0, 'Verified using v2 scheme (APK Signature Scheme v2): false'))
    def test_unsigned_bundle(self): self.assertFalse(pf.signature_ok('aab', 0, 'jar is unsigned.'))
    def test_partial_signature(self): self.assertFalse(pf.signature_ok('aab', 0, 'jar verified.\nWarning: This jar contains unsigned entries'))
    def test_bad_signature_exit(self): self.assertFalse(pf.signature_ok('aab', 1, 'jar verified.'))
    def test_missing_artifact_not_pass(self): self.assertEqual(pf.inspect(options())['status'], 'UNKNOWN')
    def test_missing_signature_jar_is_no_evidence(self):
        if pf.os.name != 'nt': self.skipTest('Windows Java adapter only')
        with tempfile.TemporaryDirectory() as tmp:
            tools = Path(tmp) / 'build-tools/99.0.0'; tools.mkdir(parents=True)
            (tools / 'aapt2.exe').write_bytes(b'fixture only; never executed')
            with self.assertRaises(pf.NoEvidenceError): pf.sdk_tool(tmp, 'apksigner')
    def test_smoke_instrument_failure_stays_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / 'fixture.apk'
            with zipfile.ZipFile(artifact, 'w') as z: z.writestr('payload', b'fixture')
            args = options(artifact); args.smoke_emulator = 'emulator-5554'; args.previous_code = None
            badging = "package: name='org.example.androidpreflight' versionCode='1' versionName='1.0'\ntargetSdkVersion:'36'\n"
            def transport(argv, **kw):
                if 'badging' in argv: return 0, badging
                if 'verify' in argv: return 0, 'Verified using v2 scheme (APK Signature Scheme v2): true'
                return 0, ''
            with patch.object(pf, 'sdk_tool', return_value=['fixture-reader']), patch.object(pf, 'run', side_effect=transport), patch.object(pf, 'smoke', side_effect=pf.NoEvidenceError('planted missing transport')):
                report = pf.inspect(args)
            self.assertEqual(next(c['status'] for c in report['checks'] if c['id'] == 'emulator_smoke'), 'UNKNOWN')
            self.assertEqual(next(c['status'] for c in report['checks'] if c['id'] == 'version_monotonicity'), 'UNKNOWN')
            self.assertEqual(report['status'], 'UNKNOWN')
    def test_artifact_changed_during_inspection(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.apk'
            with zipfile.ZipFile(path, 'w') as z: z.writestr('payload', b'fixture')
            changed = []
            def mutating_vendor(argv, **kwargs):
                if not changed:
                    with path.open('ab') as f: f.write(b'planted concurrent change')
                    changed.append(True)
                return 1, 'not observed'
            with patch.object(pf, 'sdk_tool', return_value=['fixture-vendor']), patch.object(pf, 'run', side_effect=mutating_vendor):
                result = pf.inspect(options(path))
            self.assertEqual(next(c['status'] for c in result['checks'] if c['id'] == 'artifact_stability'), 'FAIL')
            self.assertEqual(result['status'], 'FAIL')


class BinaryTests(unittest.TestCase):
    def test_elf_32_64_endianness(self):
        for bits in (32, 64):
            for big in (False, True):
                with self.subTest(bits=bits, big=big): self.assertTrue(pf.alignment_ok(pf.elf_segments(elf(bits=bits, big=big))))
    def test_elf_4k_rejected(self): self.assertFalse(pf.alignment_ok(pf.elf_segments(elf(4096))))
    def test_elf_non_power_two(self): self.assertFalse(pf.alignment_ok(pf.elf_segments(elf(20000))))
    def test_bad_relro(self): self.assertFalse(pf.relro_ok(pf.elf_segments(elf(relro_end=4096))))
    def test_truncated_elf(self):
        with self.assertRaises(pf.EvidenceError): pf.elf_segments(elf()[:100])
    def test_not_elf(self):
        with self.assertRaises(pf.EvidenceError): pf.elf_segments(b'not an ELF')
    def test_elf_no_load(self):
        b = bytearray(elf()); struct.pack_into('<I', b, 64, 2)
        with self.assertRaises(pf.EvidenceError): pf.elf_segments(b)
    def test_elf_bad_congruence(self):
        h = pf.elf_segments(elf()); h[0]['vaddr'] = 4096
        self.assertFalse(pf.alignment_ok(h))
    def test_archive_traversal(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w') as z: z.writestr('../escape', b'bad')
        with zipfile.ZipFile(b) as z, self.assertRaises(pf.EvidenceError): pf.safe_archive(z)
    def test_archive_duplicates(self):
        import warnings
        b = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(b, 'w') as z: z.writestr('x', b'1'); z.writestr('x', b'2')
        with zipfile.ZipFile(b) as z, self.assertRaises(pf.EvidenceError): pf.safe_archive(z)


class PixelTests(unittest.TestCase):
    def test_keyguard_rejected(self):
        with self.assertRaises(pf.EvidenceError): pf.require_clear_keyguard('  showing=true\n  mIsShowing=true\n')
    def test_keyguard_unobserved(self):
        with self.assertRaises(pf.EvidenceError): pf.require_clear_keyguard('not observed')
    def test_keyguard_clear(self): pf.require_clear_keyguard(' showing=false\n mIsShowing=false\n')
    def test_canary_content(self):
        m = measure_pixels(png(lambda x, y: (255, 0, 255) if y < 40 else (0, 255, 255)))
        self.assertGreater(m['magenta'], .1); self.assertGreater(m['cyan'], .1); self.assertLess(m['flat'], .995)
    def test_black(self): self.assertLess(measure_pixels(png(lambda x, y: (0, 0, 0)))['lit'], .05)
    def test_flat(self): self.assertGreater(measure_pixels(png(lambda x, y: (77, 77, 77)))['flat'], .995)
    def test_wrong_canary(self): self.assertLess(measure_pixels(png(lambda x, y: (255, 255, 0)))['cyan'], .1)
    def test_corrupt_png(self):
        b = bytearray(png(lambda x, y: (1, 2, 3))); b[-1] ^= 1
        with self.assertRaises(ValueError): measure_pixels(b)
    def test_missing_png_data(self):
        with self.assertRaises(ValueError): measure_pixels(b'not png')
    def test_install_consent_and_serial_guard(self):
        for serial, consent in [('physical-device', True), ('emulator-5554', False), (None, False)]:
            args = options(); args.smoke_emulator = serial; args.allow_install = consent
            with self.assertRaises(pf.EvidenceError): pf.smoke(Path('absent.apk'), 'org.example.androidpreflight', args, {})


class SmokePipelineTests(unittest.TestCase):
    def test_fresh_install_exact_hash_positive(self):
        result = assert_rejected(png(lambda x, y: (255, 0, 255) if x < 20 else (0, 255, 255)),
                                 None, fresh_install=True)
        self.assertEqual(result['installedArtifactSha256'], '0' * 64)
    def test_fresh_install_wrong_hash_rejected(self):
        assert_rejected(png(lambda x, y: (255, 0, 255) if x < 20 else (0, 255, 255)),
                        'installed APK bytes differ', wrong_hash=True, fresh_install=True)
    def test_black_rejected_by_smoke(self):
        assert_rejected(png(lambda x, y: (0, 0, 0)), 'black or flat')
    def test_flat_rejected_by_smoke(self):
        assert_rejected(png(lambda x, y: (77, 77, 77)), 'black or flat')
    def test_wrong_canary_rejected_by_smoke(self):
        assert_rejected(png(lambda x, y: (200, 120, 40) if y < 40 else (30, 60, 200)), 'canary colours absent')
    def test_wrong_foreground_rejected_by_smoke(self):
        assert_rejected(png(lambda x, y: (0, 0, 0)), 'app not alive and foreground', wrong_foreground=True)
    def test_wrong_installed_hash_rejected_by_smoke(self):
        assert_rejected(png(lambda x, y: (0, 0, 0)), 'installed APK bytes differ', wrong_hash=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
