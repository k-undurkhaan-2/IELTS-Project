# Issue #13 Windows transport recovery candidate

NON-AUTHORITATIVE / DIAGNOSTIC-ONLY / ISSUE-13-ACQUISITION

This candidate recovers only the Windows diagnostic encryption transport. It adds
five files on a new local branch, directly above the immutable partial acquisition
commit `bad2b46c8d22c587ac3b8604fb7a5dc12aa31cc0`. It does not alter the capture
commit `c696c5d7e8abbb195c0b42303be199049a63f6b9`, the old acquisition workflow,
PR #12, or the Ubuntu evidence from run `34621663011`. A push or hosted acquisition
requires separate authorization.

## Reviewed Windows dependency

The exact official package is
[gnupg-w32-2.5.22_20260831.wixlib](https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.5.22_20260831.wixlib).
The version is **GnuPG 2.5.22**, build **20260831**. No mutable latest URL,
Chocolatey package, installer execution, PATH fallback, or system-directory copy
is used.

| Identity | Value |
| --- | --- |
| Package SHA-256 | `d4e3d0fe66a09567d40cf64071ea935c13175b03b5bb83556130040a927cc9e1` |
| Package bytes | 7,205,212 |
| Embedded CAB bytes | 7,045,608 |
| Runtime location | `$RUNNER_TEMP/issue13-gnupg/` |
| Executed binary | `$RUNNER_TEMP/issue13-gnupg/bin/gpg.exe` |
| Binary SHA-256 | `576b217cc73f83058d7867d2dc4994fd8bc9328d5214c7917f2dc0a1e9e56fd3` |
| Binary bytes | 1,376,296 |
| Complete runtime files / bytes | 87 / 17,500,491 |
| Canonical runtime manifest SHA-256 | `01be0bac21b43acd9ad6dc2cf5ed8e13a2847213909fae58cc42c3ce22810694` |

During local package review, the official detached package signature was verified
against release signer `6DAA6E64A76D2840571B4902528897B826403ADA`, using the
[official release-key publication](https://gnupg.org/signature_key.html) and an
isolated public-only verification keyring. The official installer was independently
identified as SHA-256
`2e5841e345d56f05199351bfcf585d28c6dc2326c8f76962f1e402f41f6d10e9`, matching
the [published integrity information](https://gnupg.org/download/integrity_check.html).
The installer was never executed. Hosted provisioning uses the reviewed package
hash directly; it does not retrieve release or reviewer keys dynamically.

The WiX library contains a complete CAB distribution plus WiX metadata. The
reviewed manifest maps all 87 numeric cabinet members to their distribution paths.
The fixed Windows OS extractor `C:/Windows/System32/expand.exe` expands the verified
CAB into a private staging directory. Every expanded member is checked before the
whole runtime is assembled in an absent dedicated directory. A Windows WinSxS
hardlink is permitted only for this fixed protected OS extractor. Every GnuPG
component must remain a regular, non-reparse, single-link file.

The eight adjacent DLLs are `libassuan-9.dll`, `libgcrypt-20.dll`,
`libgpg-error-0.dll`, `libksba-8.dll`, `libnpth-0.dll`, `libntbtls-0.dll`,
`libsqlite3-0.dll`, and `zlib1.dll`. The complete package also contains `gpgconf`,
`gpg-agent`, `keyboxd`, `dirmngr`, `scdaemon`, `pinentry-basic`, and its other
executables, locale catalogs, and support files. All are retained and hashed.
Only the exact `gpg.exe` is invoked for this transport; the validated synthetic
public import/encryption/decryption-rejection sequence needs no running agent,
keybox daemon, dirmngr, pinentry, or secret material. Autostart is disabled.

## Runtime and public-only home checks

Preflight first inspects only the three approved existing GnuPG locations named
in the request. It emits a fixed availability category, not the discovered path.
This recovery configuration explicitly selects the whole pinned package even if
an existing binary is present. An existing location alone does not establish
runtime authority. The bounded unapproved-hint helper is private-data-only and
never authorizes execution; the CLI performs no PATH scan.

The runtime manifest has an exact versioned schema, an exact 87-file inventory,
per-file sizes and SHA-256, a closure hash, an 8 MiB component limit, a 32 MiB
aggregate limit, and a 256-node inventory limit. Unexpected, missing, linked,
reparse, oversized, or changed files stop execution. Windows share-read file
handles deny writes/deletes to every reviewed component while the process runs;
directory handles prevent reviewed subtree renames. The entire inventory,
identities, and hashes are checked before and after every invocation, and again
from a fresh lease after the ordinary producer/verifier has terminated.

GnuPG receives a small explicitly constructed environment and a new private home.
No parent environment, user config, agent session, secret key, or passphrase is
imported. `--no-options`, `--no-autostart`, `--disable-dirmngr`,
`--no-auto-key-retrieve`, `--no-auto-key-import`, `--auto-key-locate clear`, and
`--pinentry-mode error` remain explicit. Import additionally uses `only-pubkeys`
after the pinned armor and public-packet-only checks.

The local Windows probes established a bounded transport-specific failure:
a long isolated profile produces a GnuPG socket-path length error during public
import even with autostart disabled. A short isolated home makes import succeed.
The recovery therefore requires an absolute ASCII home of at most 48 characters
and uses short fixed keyring leaf names. Longer runner temporary paths fail closed;
they are never silently redirected elsewhere. This local finding is not a claim
about the unobserved cause of the old hosted Windows failure.

GnuPG 2.5.22 derives its Windows socket namespace beneath the isolated profile's
`AppData/Local/gnupg` directory. The implementation follows the
[exact release's socket-directory derivation](https://github.com/gpg/gnupg/blob/gnupg-2.5.22/common/homedir.c):
80 SHA-1 bits, z-base-32 encoded, of the lowercase slash-form home. This SHA-1 is
only a namespace calculation; integrity uses SHA-256 throughout. Precreating
empty default-profile directories prevents GnuPG from generating `common.conf`.
The profile tree is checked before and after each process: only the exact empty
namespace directories are allowed. Configs, sockets, secret files, arbitrary
files, and plaintext outputs are rejected. Existing fixed public-keyring filenames
are bounded, and lock files must be empty.

## Reviewer and synthetic checks

| Pin | Exact value |
| --- | --- |
| Primary fingerprint | `86D51BCDBC946CF1389969D530479D840D9D562B` |
| Encryption subkey | `670239EA1230D51EE2220DBB96327B4091754647` |
| Recipient selector | `670239EA1230D51EE2220DBB96327B4091754647!` |
| Public certificate SHA-256 | `52397bc3915c9738d73c2177c7af3eabd43d2372763fa9a6c57676b260cd3567` |

The unchanged certificate is read from the checked-out Git blob and matched to
its SHA-256 before import. Imported primary/subkey fingerprints, cv25519 curve,
encryption capability, revoked/expired/disabled state, public subkey inventory,
and secret-free state are checked before encryption. `--trust-model always` is
used only after those checks, with the exact `!`-suffixed subkey selector.

The fixed synthetic payload is 39 bytes with SHA-256
`f92c07b683053137ef7e666d883fbaab35284255ea8949e0ea2b9afd57dc5955`.
Its ciphertext must be nonempty and at most 8 KiB, have the bounded expected
OpenPGP packet structure, including the full Curve25519 MPI and wrapped-key
length, and name exactly the pinned encryption subkey. Only the observed v3 ECDH
session-key packet plus GnuPG v1 AES-256/OCB encrypted-data packet (tag 20,
chunk parameter 16) is accepted. The full 263-bit Curve25519 MPI, 48-byte wrapped
key, 15-byte OCB nonce space, and minimum two authentication-tag lengths are
bounded. The structures are documented by the
[OpenPGP ECDH format](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1.5) and
[the exact GnuPG packet writer](https://github.com/gpg/gnupg/blob/gnupg-2.5.22/g10/build-packet.c). The
public-only keyring is then asked to decrypt **only this synthetic ciphertext**
to stdout. Exit 2, the exact NO_SECKEY recipient, DECRYPTION_FAILED, and zero
plaintext bytes are all required. The keyring inventory is checked again.
No acquisition bundle is decrypted. Nonzero import/encryption results are never
converted to success.

## Windows-only scheduling and export boundary

The new workflow contains exactly three Windows jobs: standalone lightweight
preflight, producer, and fresh replay. The initial preflight runs only on a
branch-creation push at attempt 1. Both ordinary jobs also perform their own
preflight on their actual Windows host before dependency installs or ordinary
commands. A failed preflight emits `STOP WINDOWS ACQUISITION` and cannot schedule
ordinary execution. Preflight never calls the producer, verifier, or repository
test suite.

Producer execution retains its original command and ordinary step result. Its
completed diagnostic export and both encrypted/private and public uploads must
succeed before fresh replay can be scheduled. A failed ordinary producer result
remains failed; `always()` on the replay scheduling condition permits diagnosis
only when that producer nevertheless produced a complete encrypted export.
The fresh replay retains its original command and result. Diagnostic export and
upload steps use `continue-on-error: true`; they cannot turn an ordinary failure
into success or mask its exit status.

Each host derives the same Windows pair ID from the new recovery commit, new run
ID, and `windows`. Context checks reject the old acquisition commit, wrong branch,
wrong repository/event/job, run attempt 2, phase mismatch, and the old Windows
transaction `127c77fd950b5dc7476b4aa2f0cadff1`.

Preflight proof is a strictly bounded, versioned diagnostic object. Export checks
its exact schema, context, current candidate source identity, pinned tool and
recipient fields, and synthetic results. A modified digest field cannot inject
arbitrary public text. The proof grants only diagnostic scheduling permission;
it is never imported by replay verification and never satisfies an acceptance
hard gate or creates a ReplayAuthorizationEnvelope.

After the ordinary command terminates, the frozen snapshot reader reads its
capture without rewriting it. The plaintext tar/gzip exists only in bounded
memory. A separate absent private export directory contains only:

- `issue13-private.tar.gz.gpg`;
- privacy-safe `public.json`;
- privacy-safe bounded provenance `transport.json`.

Only the ciphertext path is in the private upload. Neither raw capture directories
nor plaintext archives are upload targets. Export failure does not fall back to
plaintext. Public errors consist only of the fixed allowlisted category. Runtime
output, arbitrary exception text, credentials, environment dumps, and private
stream contents never enter public diagnostics.

## Focused validation and negative matrix

Run only `test_issue13_windows_transport_recovery`, with
`ISSUE13_REVIEWED_PACKAGE` naming the reviewed local WiX package and
`ISSUE13_TEST_TEMP_PARENT` naming a short private temporary parent outside the
checkout. The fixtures validate the package again and provision a complete
runtime; they do not select the workstation's GnuPG from PATH. Fixture directories
are resolved and checked against their designated parent before recursive cleanup.

| Case | Required result / evidence |
| --- | --- |
| Approved locations absent | Fixed unavailable category; no PATH execution; pinned provisioning remains explicit |
| Approved preinstalled runtime | Complete closure required; missing component rejected |
| Unapproved discovered runtime | Private metadata only; process not invoked |
| Correct package, binary, and version | Complete 87-file provisioning and real GnuPG invocation pass |
| Wrong package hash/size, network error, redirected URL | Stop before extraction/execution |
| Wrong gpg.exe or adjacent DLL hash | Fail closed with bounded integrity category |
| Missing/extra runtime component | Closure rejected before process launch |
| Mutation after validation | Writes/deletes/rename denied while leased; changed or added components rejected before use |
| Hardlink or real Windows junction | Rejected before process launch |
| Wrong binary path/version; long home | Stop before import |
| Wrong primary/subkey/curve/capability; alternative recipient | Reject |
| Revoked/expired primary or subkey; disabled/secret records | Reject, including expired timestamps without a status marker |
| Wrong certificate hash; secret primary/subkey packet tags | Reject before any GnuPG process |
| Synthetic encryption succeeds | Exact recipient, bounded packets, public-only decryption fails, zero plaintext |
| Encryption failure/empty/truncated/plaintext/extra-recipient output | Never pass or fall back to plaintext |
| Wrong decryption status or nonzero plaintext | Preflight rejected |
| Secret/config/plaintext file in home; output bound/timeout | Reject with private process details |
| Preflight proof altered/unknown/oversized field | Reject; no public-text injection |
| Preflight FAIL / PASS | No scheduling output on failure; only bounded pair ID and PASS on success |
| Workflow topology | Only Windows jobs; PASS before ordinary commands; encrypted export before replay; attempt 1 only |
| Real paired synthetic exports | Capture files, authoritative records/transcript/violations/hard gates unchanged byte for byte |
| Replay eligibility controls | Existing compact passing and mismatching controls retain byte-identical eligibility across transport state changes |
| Diagnostic document substituted as authority | Existing verifier rejects it |
| Error privacy | Canary exception/argument text cannot appear in public output |
| Source isolation | Frozen source bytes match reviewed commits; ordinary command strings unchanged |

Only focused tests, workflow/static checks, source identity checks, and
`git diff --check` are permitted for this candidate. No full 476-test suite,
producer recovery, hosted acceptance, push, or additional hosted run is part of
this local validation transaction. Exact signed commit/tree identity and final
validation counts are reported separately after local signing.
