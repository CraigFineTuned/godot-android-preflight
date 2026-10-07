# Godot Android preflight

Version: **0.1.1**. Source-only, CLI-first, Windows-validated.
Version monotonicity is UNKNOWN when no prior-code baseline is supplied; omitting it
blocks aggregate PASS. Both installation and installed observation read back the APK
digest from the emulator before claiming exact artifact identity. An install-success
message or matching version code alone is insufficient.

Samples: `examples/pass.json` and `pass.txt` are prominently labelled **SYNTHETIC**
format examples generated through scripted vendor/transport fixtures, not real app
acceptance. `examples/report.json` and `report.txt` are a current **real FAIL** from
the generic Godot canary's RELRO-end check. Current emulator availability is UNKNOWN
when none is connected; earlier native proof is dated separately in QUALITY.json.
Do not reinterpret these samples as a working release, runtime16KB or store approval.

Build context means caller expectations and an optional prior version code. Input
SHA-256 and before/after byte stability are observed. Git/source-to-build provenance
is not proved by this v0; bind source externally through your build system. No
production keystore, signing alias or signing password is accepted by this CLI.

Free CLI preflight for Godot Android developers. Inspect an APK or AAB locally, compare it with explicit release expectations, and produce JSON plus a short text report. Optional APK smoke testing records native emulator frames. No telemetry, external network requests, signing or publishing are included. Optional smoke uses ADB to connect to an explicitly selected local emulator.

This is **not Play Store approval, runtime/performance certification or complete 16 KB compatibility certification**. `PASS` means all checks in this report were observed and met their configured criteria. `FAIL` means at least one finding; `UNKNOWN` means required evidence is unavailable. Missing smoke or delivery evidence blocks aggregate PASS. Exit codes are 0, 1 and 2 respectively.

## Run locally

Use Python 3.9 or newer, installed Android SDK build tools with AAPT2, apksigner and zipalign, and Java. The tested environment is Windows, Python 3.9, build tools 36.1.0 and JDK 17. Other platforms are unvalidated. Supply an SDK path; no private path is embedded and no automatic SDK download occurs.

```sh
python preflight.py app.apk --sdk "$ANDROID_SDK_ROOT" \
  --package org.example.app --version-code 7 --version-name 1.0 \
  --previous-code 6 --min-target 36 --max-bytes 100000000 \
  --allow-permission android.permission.INTERNET \
  --json report.json --text report.txt
python test_preflight.py
```

All policy thresholds come from the caller. API 36 and the size in this example are illustrative, not a current Play policy promise. No permission is allowed unless explicitly listed. `previous-code` is optional and caller-supplied; the tool cannot know codes already consumed by a store. Signing verification requires APK v2, but does not prove an approved signing certificate. `debuggable=false` is observed state, not proof that the build used a release configuration.

For AAB metadata, additionally supply `--bundletool bundletool.jar`, using your own installed Google bundletool and `jarsigner` on PATH. Version 1.18.3 was tested. AAB metadata is decoded from its actual manifest. AAB ZIP offsets cannot prove generated APK alignment; AAB delivery alignment and launch remain UNKNOWN in v0. It never generates or installs delivery splits, so an AAB cannot earn aggregate PASS in this version.

## Emulator evidence

Explicitly select an already booted, unlocked disposable emulator. Physical devices are refused. To install an APK whose package is absent, add:

```sh
--smoke-emulator emulator-5554 --allow-install --evidence-dir smoke-evidence
```

To observe an existing installation, use `--observe-installed` instead. This requires a single installed APK whose SHA256 exactly matches the supplied artifact. Split installations are unsupported. The tool refuses overwrite, downgrade, uninstall and data clearing. It does not boot an emulator or dismiss keyguard. It wakes the selected display and starts the app activity; the installation stays in the emulator. Operator cleanup is separate.

Identity, signature, archive and non-debug gates must pass before smoke. Other readiness findings may coexist with diagnostic smoke PASS. Two foreground/liveness checks and native frame samples five seconds apart reject obvious black or uniform frames. This is not motion, gameplay, performance, crash-free endurance or ARM64/16 KB runtime acceptance. A colourful wrong app overlay can require manual review; pixel diversity alone cannot prove product quality.

`canary.py output-directory` reuses an asset-free Godot probe: magenta/cyan halves and a moving square. It creates source only; export and signing remain operator tasks. Add `--expect-canary` only when observing this canary. A real canary smoke passed on the tested emulator; its independent RELRO-end finding remained FAIL. The example reports preserve both observations.

## Features and boundaries

| Check | v0 behaviour | Development classification |
|---|---|---|
| Package, versionCode, optional version name | Actual APK badging or decoded AAB manifest against caller expectations | SMALL EXTRACTION of existing identity verification; NEW AAB adapter |
| Version monotonicity | Greater than supplied previous code, if supplied | SMALL EXTRACTION; no store lookup |
| Signing state | APK v2 cryptographic verification; AAB JAR verification rejects unsigned appended entries | SMALL EXTRACTION; approved signer/trust policy absent |
| Debug state | Reject observed debuggable builds | NEW policy over EXISTS SDK observation |
| Target API | Reject below caller minimum | NEW policy over EXISTS SDK observation |
| 16 KB checks | ELF PT_LOAD alignment/congruence, RELRO end, APK vendor zipalign | NEW policy/parser over EXISTS vendor capability |
| Permissions | Actual declared names compared with explicit allow-list | NEW policy over EXISTS SDK observation |
| Size | Exact file bytes against caller maximum | SMALL EXTRACTION; not delivered/compressed download estimate |
| Emulator smoke and PNG evidence | Opt-in launch, foreground, exact installed APK binding, two bounded native samples | SMALL EXTRACTION of pixel core and NEW generic smoke adapter |
| JSON and text verdicts | FAIL takes precedence over UNKNOWN; absent evidence never passes | SMALL EXTRACTION of existing three-state proof convention |
| AAB delivery APK alignment and smoke | UNKNOWN, outside v0; never inferred from AAB offsets or an unrelated APK | NEW IMPLEMENTATION REQUIRED |

Archive integrity also rejects unsafe/duplicate member names, encrypted ZIPs and resource limits. Input is never extracted into the filesystem. Native libraries are read as bytes, not executed by inspection. APK testing does execute the selected app in an emulator when explicitly requested.

ELF load checks inspect packaged shared objects under module `lib` directories. RELRO-end validation is additional static evidence. These checks do not inspect every native payload hidden in assets, hardcoded page-size assumptions, linker/runtime behaviour or generated delivery APKs. A file with no native libraries passes these static predicates vacuously and reports `noNativeLibraries=true`; it is not proven playable. ZIP limit: 20,000 entries, 2 GiB expanded total, 512 MiB per member, and a bounded expansion ratio. PNG decoding supports non-interlaced 8-bit RGB/RGBA, bounded dimensions and CRC checks. Unsupported formats return UNKNOWN.

See [Android page-size guidance](https://developer.android.com/guide/practices/page-sizes), [apksigner](https://developer.android.com/tools/apksigner), [bundletool](https://developer.android.com/tools/bundletool) and [jarsigner](https://docs.oracle.com/en/java/javase/17/docs/specs/man/jarsigner.html) for vendor semantics. Policy can change; this tool embeds no dated store deadline.

## Security and licensing

The candidate ships source, generic examples and synthetic controls only. It includes no credentials, keys, SDK executables, game assets, account identifiers or private logs. SDK/JDK/Godot/bundletool remain separately installed dependencies under their own licences. No telemetry is implemented.

Reports intentionally omit local paths, serial identifiers, signer subjects and raw vendor logs. Runtime reports still contain the caller's package name, permissions, artifact hash and captured screen content. Treat those as potentially sensitive: review them before sharing. An emulator is not a security sandbox guarantee for hostile APKs. Use trusted artifacts on an isolated disposable emulator; inspection itself is not a hostile-input security certification.

MIT licence; see `LICENSE`. This grant covers the authored code and documentation in this repository. Separately installed SDK/JDK/Godot/bundletool dependencies retain their own licences.

## Free demand experiment

See `DEMAND_PLAN.json` for the preregistered 30-day free-release experiment and frozen thresholds. No telemetry, paid layer or new spend. The experiment starts only with the first authorised public downloadable release; no demand result is claimed.

Estimated maintenance: 1–3 hours per month for issue triage and dated tool/parser checks, plus roughly half a day for a breaking SDK/Godot/bundletool change. This is a planning estimate, not measured demand or a support commitment. Keep v0 free; no paid layer until evidence justifies a separate decision.
