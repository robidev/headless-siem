# Design Proposal: Staged Cold-Storage Compaction & Compression

> **Status: draft, unscheduled** (2026-07-03). Deliberately *not* part of the
> phased SOC rollout — pick this up independently whenever storage pressure
> warrants. Nothing in the SOC path depends on it.

Should logs and indexes be gzipped to save space — always, or staggered by
age? Short answer: **yes, viable, and the staggered model is the right one**
— but the measurements below reorder the priorities. The single biggest
consumer of disk today is not log data at all; it's a SQLite WAL-checkpoint
lifecycle bug, and the second biggest is filesystem block slack from tiny
per-second files. Naive per-file gzip would fix neither. This doc designs the
fix in four batches: reclaim the free wins first, then age-based
consolidation + compression of the raw tree, with the read paths taught to
handle it transparently.

---

## Measurements (2026-07-03, 3 days of live data, dev pipeline)

Total `data/`: **284.6 MB**. Where it actually is:

| Component | Logical size | On disk | Notes |
|---|---|---|---|
| raw JSONL | 5.4 MB | ~32 MB | 5,177 files, avg 1.1 KB → ~4 KB block each |
| raw TSV sidecars | 0.7 MB | ~21 MB | 5,177 files, same block slack |
| index `.db` | 11.1 MB | 11.1 MB | 81 hourly buckets |
| index `.db-wal` | **265.2 MB** | 265.2 MB | un-checkpointed WAL, see Batch 1 |
| index `.db-shm` | 2.5 MB | 2.5 MB | companions to the stale WALs |
| alerts | 0.3 MB | 0.3 MB | negligible; out of scope |

So: **93% of current usage is stale WAL**, and of the raw tree's ~53 MB
on-disk footprint, ~88% is block slack around 6 MB of actual data.

Compression ratios, measured on the full day 2026-07-02 (1,131,950 bytes of
JSONL) and one real index bucket:

| Approach | Result | Ratio |
|---|---|---|
| per-second files, `zstd -3` each | 371,029 B | **3.0×** (and block slack remains — physical win ≈ 0) |
| day concatenated, `gzip -9` | 54,327 B | 20.8× |
| day concatenated, `zstd -3` | 52,329 B | 21.6× |
| day concatenated, `zstd -19` | 38,174 B | **29.7×** |
| index bucket `2026-07-01-10.db` (1,961,984 B), `zstd -19` | 104,907 B | 18.7× |

Two design conclusions fall straight out:

1. **Compressing the per-second files in place is not worth building.** 3×
   logical, ~0× physical. The unit of compression must be coarser —
   consolidation per hour, then compress.
2. **zstd, not gzip.** Better ratio at every speed point, `zstdcat`/
   `zstdgrep`/`rg -z` keep the grep-ability design principle intact, and the
   `zstd` crate is mature. Cold data is write-once, so use `-19`.

---

## Batch 1 — Fix the WAL leak in `indexd` (not compression at all)

*Sonnet 5, effort: medium.* This is really a bug fix and reclaims ~93% of
current usage on its own; do it before (and independently of) everything
else.

**Root cause, confirmed in code:** `src/indexd/src/db.rs` keeps a
`connections: Mutex<HashMap<String, Connection>>` cache keyed by bucket path,
opened with `journal_mode=WAL`, and never evicts ("Already open: skip the
connection open"). Event-time buckets go quiet forever once their hour
passes, so after the last commit there is never another write to trigger
SQLite's auto-checkpoint — each bucket's final WAL (observed ~3.3–4.3 MB,
i.e. right around the 1000-page auto-checkpoint threshold) is stranded until
process shutdown. 81 buckets × ~3.3 MB = the 265 MB above. `close_all()`
exists but only runs at shutdown, and this pipeline has been up since 06-30.

**Fix:** evict idle bucket connections. After N minutes without a write to a
bucket (suggest 2× the hour boundary slack, e.g. 15 min), close its
connection — closing the last connection checkpoints and removes the
WAL/SHM automatically. A periodic sweep over the cache (the main loop already
wakes for inotify events; add a coarse timer) is enough; no LRU sophistication
needed at 24 new buckets/day. Late-arriving events for an evicted bucket just
re-open it — `open_bucket` already handles that path.

**Tests:** unit test that an idle bucket's connection is dropped and the
`-wal`/`-shm` files disappear while the `.db` retains all rows; integration
assertion in an existing pipeline test that after a quiet period only `.db`
files remain.

**Expected impact:** 284.6 MB → ~50 MB on this snapshot, no read-path or
format change whatsoever.

---

## Batch 2 — Teach every raw reader the compacted format (before any writer exists)

*Sonnet 5, effort: high.* Readers ship before the compactor so there is never
a moment where data on disk is unreadable by the installed `siemctl`.
High effort: this touches every raw consumer, and a missed one silently
returns partial results — the same "worst failure mode" class as an index
gap.

**Compacted format (the contract Batch 3 will write):** for an hour that has
been compacted, the per-second directories under `data/raw/YYYY/MM/DD/HH/`
are replaced by one file per source directly in the hour directory:

```
data/raw/2026/07/01/00/<source>.jsonl.zst    # all events, original line
                                             # order preserved (per-second
                                             # bucket paths sort chrono-
                                             # logically; concatenate in
                                             # sorted order)
```

TSV sidecars are **dropped** at compaction, not compressed — they exist for
interactive grep convenience and are fully derivable from the JSONL;
`zstdcat file | grep` (or `rg -z`) covers the same need on cold data.

**Reader rule (uniform across all consumers):** when enumerating an hour,
read *both* `HH/<source>.jsonl.zst` files *and* any `HH/MM/SS/` per-second
buckets present, as a union. This makes the format self-describing (no
marker files, no config), handles partially-compacted hours during a crash
recovery, and — importantly — handles **late events**: `normalized` knows
nothing about compaction and will happily write a fresh per-second bucket
into an already-compacted hour; the union rule makes that correct by
construction. (Compaction of that residue happens on the next sweep.)

Consumers to update (survey of current code):

- `siemctl` walkers: `main.rs::walk_jsonl`, `digest_query.rs::
  raw_files_in_range`, the `search --raw` scan, and `stats`' raw fallback —
  all gain the union rule + streaming zstd decompression (`zstd` crate,
  stream, never full-file into memory; files are ≤ a few MB compressed).
- `db.rs::resolve_raw_line` (`raw_contains()` UDF and raw-line resolution):
  index rows for compacted hours still hold the *original* per-second
  `raw_file` path and `byte_offset`. Resolution order: try the stored path
  (hot data, unchanged fast path); on ENOENT, map
  `raw/Y/M/D/HH/MM/SS/<source>.jsonl` → `raw/Y/M/D/HH/<source>.jsonl.zst`
  and scan the decompressed stream for the line whose own embedded
  `_raw`… — no. Keep it deterministic instead: **Batch 3's compactor records
  each constituent file's starting offset** in a tiny sidecar manifest
  (`<source>.jsonl.zst.idx`: one `original_path<TAB>uncompressed_start_offset`
  line per constituent). `resolve_raw_line` then seeks
  `start_offset + byte_offset` in the decompressed stream. Cheap to produce,
  removes all guesswork, and keeps `raw_contains()` correct on cold data.
- `indexd`: ignore `*.zst`/`*.idx` in its inotify handling (it currently
  reacts to any file events under `raw/`). It must neither parse nor
  re-index compacted files — their contents are already indexed.
- `siemctl tail`: follows newest buckets only; no change beyond not choking
  if pointed at a compacted hour (`--no-follow` over history should apply
  the union rule like the other walkers).

**Known, accepted caveat:** `time.rs::parse_raw_file_time` derives event time
from the per-second path; for compacted hours, path-derived time degrades to
hour precision. Every event still carries its own `timestamp` field, and the
compaction age threshold (Batch 3, default 7 days) is far beyond the digest's
normal windows — sub-hour sparklines over compacted history are the only
thing that coarsens, and only when someone runs a digest over week-old data.
Document it in `../user-guide.md` rather than engineering around it.

**Tests:** every updated reader gets a fixture pair (hot per-second layout /
compacted layout / mixed with a late-event residue bucket) asserting
identical results across all three.

---

## Batch 3 — The compactor: age-staggered consolidation in `siemctl retention`

*Sonnet 5, effort: high.* The staggered model: hot data stays exactly as
today; hours older than a threshold get consolidated + compressed. Lives in
`siemctl retention` (house convention: one thing to run periodically — it
already does deletion and ack compaction), not a new daemon.

- New flag/config: `--compact-after-days N` (default 7; `0` = disabled;
  also a `[retention]` section in a config file if one ever appears —
  flag-only is fine for now). Runs after the existing deletion sweep.
- Per eligible hour (every hour dir older than N days that still contains
  per-second subdirectories): concatenate each source's per-second files in
  path-sorted order into `HH/<source>.jsonl.zst` (zstd level 19) + the
  `.idx` manifest from Batch 2; verify decompressed line count == sum of
  constituent line counts **before** deleting the per-second directories;
  write via `.tmp` + rename (the codebase's existing atomicity convention).
  A crash mid-compaction leaves both forms present → the union rule reads it
  correctly, and the next sweep finishes the job (idempotent: skip sources
  whose `.zst` already exists and matches, or redo from scratch — redo is
  simpler and cheap).
- If a compacted hour has accumulated late-event residue buckets, fold them
  in: decompress + append + recompress (rare by construction; correctness
  over cleverness).
- TSV sidecars deleted (per Batch 2's format decision).
- **mtime interplay with the deletion sweep (subtle, must not be skipped):**
  `retention --days` ages files by mtime; a freshly written `.zst` would
  reset the clock and make cold data effectively immortal. Set the `.zst`
  mtime to the newest constituent's mtime (`filetime`/`utimensat`) so the
  deletion sweep behaves as if compaction never happened.
- `--dry-run` reports what would be compacted and the projected size change,
  mirroring the existing dry-run posture.

**Tests:** integration test running the real pipeline, aging fixtures
artificially (set mtimes back), running `retention --compact-after-days`,
then asserting: search/digest/stats results identical pre/post; index-row
`raw_contains` still resolves; deletion sweep later removes the `.zst` at
the right age; crash-mid-compaction (kill between write and delete) recovers
on next run.

**Expected impact at current volume:** raw tree ~53 MB-on-disk/3 days →
~120 KB/3 days for compacted history (measured 38 KB/day compressed), and
5,177+5,177 files/3 days → ~50/day. At production volume (pfSense filterlog
+ 5 Proxmox nodes forwarding, plausibly 10–50× today's event rate) this is
the difference between "years of history on a small SSD" and "weeks".

---

## Batch 4 (optional) — Cold index handling

*Sonnet 5, effort: medium.* Only worth doing if post-Batch-1 index growth
(~3.7 MB/day of `.db` at current volume) actually matters on the target
host. Two options, in preference order:

1. **VACUUM + zstd the `.db` for compacted hours** (18.7× measured) inside
   the same retention sweep; `siemctl` decompresses on demand to a temp file
   (scratch dir, LRU-capped) when a historical query touches a cold bucket.
   Keeps full DSL query capability over all history at a small latency cost
   on cold queries. The existing "skip bucket on schema mismatch"
   (`is_benign`) tolerance pattern shows where per-bucket open errors are
   handled; the decompress hook goes at the same layer
   (`db::open_bucket_conn` call sites).
2. **Separate index retention** (`--index-days M < --days N`): delete cold
   indexes outright and let `search` fall back to scanning the compacted
   `.zst` raw (Batch 2 already built that reader). Simpler, but historical
   field-predicate queries degrade to full scans — fine for a homelab,
   annoying for the SOC's weekly soclead lookbacks. Ship (1) unless it
   proves fiddly.

Note: the README's "Index is optional / indexes are tiny" claim is only true
post-Batch-1 — at 11 MB per 3 days the index is ~2× the raw data it indexes,
which is normal for a many-column index but worth an honest README touch-up
in whichever batch lands first.

---

## Explicitly rejected alternatives

- **Per-file gzip/zstd of per-second files** (the intuitive reading of
  "gzip the logs"): measured 3× logical, ~0× physical (block slack), breaks
  `byte_offset` resolution for no meaningful win. Rejected.
- **gzip instead of zstd:** strictly worse ratio (20.8× vs 29.7×), slower
  decompress, no better tooling story. Rejected.
- **Compressing hot data / compress-on-write:** breaks `O_APPEND` bucket
  writes, `tail`, inotify-driven indexing, and grep-during-incident. The
  entire value of the staggered model is that hot data stays plain. Rejected.
- **A new compaction daemon:** retention already exists, already runs
  periodically, already owns "make old data smaller". Rejected.
- **tar-per-day archives:** kills per-source addressing and random access;
  one corrupt archive loses a day. Rejected.

## Sequencing & risk summary

Batch 1 is independent and safe — do it first, it's most of the win. Batches
2→3 are strictly ordered (readers before writer). Batch 4 is optional and
independent of 2/3 (different tree). The dangerous batch is 3 (it deletes
originals): its verify-before-delete + idempotent-recovery requirements are
the non-negotiable part of this design, and its integration test must
include the crash case before the `--compact-after-days` flag is documented.
