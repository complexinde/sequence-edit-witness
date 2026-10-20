# SequenceEditWitness

AI-assisted independent GenLayer IC prototype for optimal, exactly applicable line-edit witnesses between two bounded UTF8 snapshots. It uses no LLM, holds no assets and executes no patch. Source fixtures remain synthetic HTTP mocks; the free Studio constructor is deployed, but the full live business lifecycle remains unverified.

## Exact edit semantics

Owner fixes two public commit-pinned raw GitHub URLs and byte SHA256 values. Anyone may request consensus certification. Leader and validators each fresh-fetch **both** sources, verify exact bytes/UTF8/limits and independently recompute the full suffix dynamic program, canonical script and exact target reconstruction. Full canonical bound results must agree. A plausible script, schema, self-reported cost or target hash alone cannot be accepted.

Sources0..8192 bytes each; UTF8 decoding is strict. Empty bytes mean `[]`. Every other text uses `text.split("\n")`, max64 elements. Thus `a\n` becomes `["a",""]`, `a\r\n` becomes `["a\r",""]`, and oneLF-only file becomes `["",""]`. CR, BOM, Unicode line separators, trailing empty elements and Unicode code points are preserved; no newline/Unicode/whitespace normalization. Joining elements withLF reconstructs exact UTF8 bytes. Consequently an empty file and aLF-only file have distance2 under this specified representation. This is a line-element metric, not character distance or approximate semantic similarity.

Suffix DP dimensions are at most65x65. Boundary costs are remaining line counts. Recurrence minimum: identical MATCH cost0; REPLACE, DELETE and INSERT each cost1. From cursor(i,j), emit the **first optimal** operation in MATCH -> REPLACE -> DELETE -> INSERT priority, not merely any optimum. Script includes MATCH steps and exact source_index/target_index cursors. MATCH/DELETE carry `text`, INSERT target `text`, REPLACE source `old` and target `new`; no unrelated fields. The replay pass checks each cursor/text/shape, full source/target consumption, edit cost equal to DP optimum and exact reconstructed target. Every validator repeats this from fresh source bytes, then compares the complete packet using canonical JSON (which distinguishes bool from int).

For fixture `alpha\nbeta\n` -> `alpha\ngamma\n`, cost1 and script is MATCH alpha, REPLACE beta鈫抔amma, MATCH empty final element. For `a\nb` -> `b\na`, both two replacements and delete+match+insert cost2; this protocol selects the two replacements. Script describes transformation only: it does not certify code correctness, semantic equivalence, author intent or permission to apply it.

## Interface and lifecycle

Constructor takes **zero arguments**, fixing owner to sender. IDs ASCII `[A-Za-z0-9_-]{1,32}`. URLs exact `https://raw.githubusercontent.com/<owner>/<repo>/<40 lowercase hex>/<path>`, length<=512, safe ASCII nonempty path segments and no `.`/`..`, percent encoding, credentials/ports/query/fragment/mutable ref. Owner is1..39 ASCII alphanumerics/single hyphens, beginning/ending alphanumeric. Repository1..100 ASCII alphanumerics/underscore/dot/hyphen may be `.github`, but not `.` or `..`; namespace and file-path segments are checked separately. Hashes64 lowercase hex. Both sources may share URL/commit, but are individually fetched and bound.

| Method | Behavior |
|---|---|
| `register(edit_id,left_url,left_sha256,right_url,right_sha256)` | Owner only, unused immutable pair -> REGISTERED revision0; does not fetch or claim validity. |
| `certify(edit_id,expected_revision) -> str` | Anyone, REGISTERED0 only; fresh two-source DP/script/replay -> CERTIFIED1; returns certificate ID. |
| `activate(edit_id,expected_revision,certificate_id)` | Owner, exact CERTIFIED1 revision/certificate -> ACTIVE2. Historical acceptance; no refetch. |
| `revoke(edit_id,expected_revision,reason)` | Owner, any nonREVOKED phase, increments revision and terminally withdraws offline. |
| `get_edit(edit_id) -> dict` | Immutable sources, status/revision, attestation/result and history. Unknown ID reverts. |
| `is_active(edit_id,certificate_id,expected_revision) -> bool` | Exact current ACTIVE certificate/revision; unknown ID false. |
| `get_configuration() -> dict` | Owner/protocol, limits, tie order and normalization specification. |

Result contains source_lines, target_lines, optimal integer cost, complete script and target_sha256. Certificate hashes protocol plus the full packet. Packet binding includes chain, contract, owner, editID, both URLs+SHA, registration/certification time, certifier and exact prior revision. It cannot be moved to another pair/record/contract. Max8 lifetime registrations, at most4 phase events. Capacity never recycles; IDs cannot be replaced even after withdrawal. Certification/activation are one-time. Source error leaves REGISTERED0 without certificate and supports exact-source retry or owner offline revoke. Revisions are exact integers; bool is rejected. Reason is trimmed nonempty1..200 characters.

Integration: publish two non-personal fixtures with actual immutable public URLs; register actual byte hashes -> anyone `certify(id,0)` -> owner checks complete bound script and `activate(id,1,certificate)` -> consumer reads `get_edit` and `is_active(id,certificate,2)`, then applies only its own separately authorized source bytes after checking exact hashes. Revocation invalidates current status while retaining historical packet. Historical ACTIVE must not be cached as permanent authorization. No deadline, timed liveness promise, source monitor or semantic approval is implied.

## Reproduce and evidence

Python3.12, isolated environment, no browser/wallet/RPC:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe tools\verify.py
```

Verifier pins official GenVM **v0.2.12**, runner `1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`, stdlib `11rhn002yfajawsz7fai6mykznbxkxs6l91iskj5cm82c92qhy3v`. Requirements pin genlayer-test0.29.2, genvm-linter0.11.0, cloudpickle3.1.2. Initial SDK setup may fetch public artifacts. Whole suite executes real deployable code/storage/calldata/authorization and validator closures; only HTTP responses are mocks. Standalone conftest adjusts upstream Windows fd0 unlink cleanup and official warp datetime metadata; it replaces no edit algorithm. Test application is a simple replay of contract output with literal expected operations, never a host optimum solver.

Evidence retains **26 genuine initial failures** on a minimal deployed API, and **4 genuine failures/8 passes** when REPLACE priority was deliberately disabled in actual source. Original source was restored before full verification. The first mutation capture attempt had a Windows stdout decoding error; the retained run uses exact byte capture and is described in its JSON evidence. Independent review found the shared locator primitive accepted dot repository namespaces; this affected the fixed-commit URL promise, while exact content SHA checks remained effective. New tests on both left/right URL positions produced **10 failures/6 passes** before explicit namespace validation fixed them (`evidence/tdd-namespace-red.log`). Final whole-suite source/hash/results and full official semantic lint/schema logs are under `evidence/`. Coverage includes empty/CRLF/trailingLF/BOM/Unicode/repeated lines/multiple optima, useful non-greedy edits, full-shaped forged cost/script/lines/domain, independent two-source refetch, failed source/UTF8/limits and owner/CAS/terminal history. Valid8192-byte and64-element cases pass; 8193/65 fail.

Fixtures are original MIT synthetic examples; `fixtures/source.json` explicitly records local-only `test_url`, `public_url:null` and no live-source verification. Root must publish real fixture snapshots and use actual immutable URLs/hashes before live demonstration. Independent frozen-source review closed after the namespace fix; see `evidence/independent-review.json`. Only the constructor deployment is recorded in deployment.json; no full-lifecycle live receipts or execution-cost evidence is claimed.

## Threat limits

Only public non-personal text should be used; both texts, complete script, URLs and reasons become public. Hashes identify declared bytes, not correct authorship, legal permission, safe changes, real progress or semantic equivalence. Source transport and SHA collision resistance remain assumptions; Git object content is not independently rebuilt. Owner can revoke and permanently exhaust their own finite record capacity. Protocol tie order and LF representation are deliberately strict; other diff tools can produce different but equally optimal scripts. Runtime is bounded O(linesLeft*linesRight), but worst-case real VM gas has not been measured. SDK response caps apply after download; it offers no pre-download/final-URL/redirect enforcement. Only SDK/testing/JSON primitives are shared with other work; this optimal edit/replay core is independently implemented.

## Verified local result

Final full-package actual SDK suite: **51 passing tests**. Full official lint/semantic and schema extraction exit0; ABI constructor has no parameters. Source hash is recorded in evidence/verification.json and CONTRIBUTION.json. Independent read-only frozen-source review by `/root/genlayer_projects_pair02` closed after the namespace fix with no remaining important findings; scope and original finding are retained in `evidence/independent-review.json`. Only documentation/evidence/package metadata changed after that review; tests were not rerun during final closeout. This is local prototype review, not an audit. Constructor deployment is recorded separately; live source retrieval and full certify/apply/revoke operation remain untested.
