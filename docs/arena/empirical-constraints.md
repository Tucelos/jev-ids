# Empirical constraints: what the NSL-KDD Pool actually says

Measured by `scripts/fit_mutations.py` on `data/nsl-kdd/pool.csv` (125,973 Flows, KDDTrain+) and
`data/nsl-kdd/test.csv` (22,544 Flows, KDDTest+). The model it produced is
`data/nsl-kdd/mutations.json`; the hashes of both inputs are in that file's `provenance` block.

This document closes open question 4 of `docs/arena/evasion-constraints.md`: *"Coupling
identities not empirically validated ... They follow from the published definitions, but
rounding/truncation in the original derivation may break exact equality."*

**Headline: rounding is not the problem. Three of the four predicted couplings are wrong by
construction, not by rounding.** `count`/`srv_count` and `dst_host_count`/`dst_host_srv_count` are
**not nested pairs**. Each pair is computed over **two parallel windows** — one over connections to
the same *host*, one over connections to the same *service*. The report's §4 reads them as one
window partitioned into parts, and that reading does not survive contact with the data.

Reproduce with:

```
uv run python -m scripts.fit_mutations
uv run pytest tests/test_mutations.py
```

---

## 1. Coupling identities

A coupling is **accepted** only when its p99 residual on the Pool fits inside the *rounding slack*
its features' stored precision allows: 0.01 for a statement about two two-decimal rates, 0.005 for
one about a single rate, 0 for one about integer counts. The tolerance an accepted coupling ships
with is that measured p99 and nothing wider.

| Identity | Verdict | Pool violations | residual p50 / p90 / p99 / max | Test violations |
|---|---|---|---|---|
| `same_srv_rate + diff_srv_rate == 1` | **rejected** | **37.48 %** | 0.00 / 0.90 / 0.93 / 1.00 | 26.30 % |
| `dst_host_same_srv_rate + dst_host_diff_srv_rate == 1` | **rejected** | **60.49 %** | 0.24 / 0.91 / 0.94 / 1.00 | 53.93 % |
| `dst_host_srv_count <= dst_host_count` | **rejected** | **27.52 %** | 0 / 209 / 253 / 254 conn. | 23.46 % |
| `srv_count <= count` (the 2 s mirror, added here) | **rejected** | **22.10 %** | 0 / 6 / 80 / 510 conn. | 21.35 % |
| `dst_host_same_srv_rate == min(1, dst_host_srv_count / dst_host_count)` | **rejected** | **6.92 %** | 0.0014 / 0.0047 / 0.5319 / 0.99 | 6.26 % |
| `same_srv_rate == min(1, srv_count / count)` (fitted here) | **accepted**, tol **0.005** | 0.78 % at slack, **1.10 % at tolerance** | 0.0000 / 0.0038 / 0.0050 / 0.88 | 2.86 % at tolerance |
| `num_outbound_cmds == 0` | **accepted**, tol **0.0** | **0.00 %** | 0 / 0 / 0 / 0 | 0.00 % |

Violation rates are quoted at the rounding slack unless marked; `mutations.json` carries both
`violation_rate_above_slack` and, for accepted couplings, `violation_rate_above_tolerance`.

### 1.1 CONTRADICTED: the two "partition" identities

`same_srv_rate + diff_srv_rate` equals 1 in only **62.5 %** of Flows. The failures are not near
misses. The modal residual is about **−0.90**: the two rates sum to roughly 0.10. Example Flow
(Pool): `count=13, srv_count=1, same_srv_rate=0.08, diff_srv_rate=0.15`. And **2,364 Flows** have a
sum *above* 1, reaching 1.50 — so the pair is not even bounded above by 1.

`dst_host_same_srv_rate + dst_host_diff_srv_rate` is worse: it sums to 1 in only **39.5 %** of
Flows, and its median residual is 0.24.

What the data supports instead: `same_srv_rate` is the same-service **share** of the same-host 2 s
window, while `diff_srv_rate` behaves as a count of *distinct other services* over the same
denominator — a much smaller quantity. **An attacker model must never set
`diff_srv_rate := 1 - same_srv_rate`.** Doing so would produce Flows the sensor could not emit, and
would silently manufacture evasion success.

### 1.2 CONTRADICTED: both count orderings

`dst_host_srv_count > dst_host_count` in **34,670 Flows (27.5 %)**, by up to 254 connections. This
is not a parsing artifact. Verified against the raw file: line 4 of `KDDTrain+.txt` has
`dst_host_count=30`, `dst_host_srv_count=255`, `dst_host_same_srv_rate=1.00`, `service=http`.

Same story one window down: `srv_count > count` in **27,836 Flows (22.1 %)**, by up to 510
connections.

The explanation, which the report's §4 misses: the KDD derivation maintains two windows per
statistic. `count`/`dst_host_count` are counted inside the window of connections to the same
**host**; `srv_count`/`dst_host_srv_count` inside the window of connections to the same **service**.
A saturated service window (255) beside a thin host window (30) is perfectly normal traffic. The
corroborating evidence is decisive: **where `srv_count > count`, `same_srv_rate == 1.00` in 97.8 %
of Flows** — the share is clamped at 1 exactly because the numerator comes from a different, larger
population.

### 1.3 CONFIRMED: `num_outbound_cmds` is identically zero

One distinct value across all 125,973 Pool Flows **and** all 22,544 test Flows. The report marked
this "[synthesis], not verified against a paper" — it is now verified against the data. The feature
carries no information; perturbing it is a wasted move, and any Detector weight on it is noise.

### 1.4 The one usable replacement, with a caveat

`same_srv_rate == min(1, srv_count / count)` holds inside 0.005 for 98.9 % of Pool Flows, which is
the two-decimal rounding bound and nothing more. **This is the only numeric rate identity the data
supports**, and it is the mechanism that forces `same_srv_rate` to move whenever behaviour moves
`count` or `srv_count`.

Be honest about its limits. On KDDTest+ the same identity is violated by **2.86 %** of Flows and its
p99 residual is 0.50, a hundred times the Pool's. The model ships the Pool's tolerance because the
model is fitted on the Pool, but a consumer that enforces it on test Flows will reject about one
Flow in thirty-five as inconsistent. That number is in `mutations.json`, not hidden.

The host-based twin, `dst_host_same_srv_rate == min(1, dst_host_srv_count / dst_host_count)`, is
**nearly** good enough and is still rejected: 93.1 % of Flows sit inside 0.01, but the p99 residual
is **0.53**. Its 8,711 failures are concentrated in benign Flows (7,926 of them) with an unsaturated
`dst_host_count`. Accepting it would mean inventing a tolerance fifty times the rounding bound to
make a story work. It is recorded as rejected.

### 1.5 CONFIRMED: `flag` fixes the error-rate family

The one §4 coupling that is symbolic rather than numeric holds cleanly.

| `flag` | Flows | `serror_rate > 0.5` | `rerror_rate > 0.5` |
|---|---|---|---|
| `SF` | 74,945 | 0.002 | 0.001 |
| `S0` | 34,851 | **0.988** | 0.003 |
| `REJ` | 11,233 | 0.000 | **0.995** |
| `RSTR` | 2,421 | 0.000 | 0.949 |
| `RSTO` | 1,562 | 0.001 | 0.963 |
| `SH` | 271 | 0.985 | 0.000 |
| `S1` | 365 | 0.649 | 0.003 |
| `OTH` | 46 | 0.000 | 0.000 |

A Flow cannot keep `flag=S0` and drop `serror_rate`, nor keep `flag=REJ` and drop `rerror_rate`.
This matters directly for dos `neptune`, whose definitional `flag=S0` pins `serror_rate` near 1.

---

## 2. Admissible symbolic combinations

Sheatsley et al.'s critique, answered with counts from the Pool.

| `protocol_type` | Flows | services (≥10 Flows) | rare services (<10) | flags |
|---|---|---|---|---|
| `tcp` | 102,689 | 56 | `pm_dump`, `aol`, `harvest`, `http_8001`, `http_2784` | 11 |
| `udp` | 14,993 | 4 | `tftp_u` | 1 (`SF` only) |
| `icmp` | 8,291 | 4 | `red_i`, `tim_i` | 1 (`SF` only) |

Only **`other`** and **`private`** occur on more than one protocol (both tcp and udp). Every other
one of the 70 services is pinned to exactly one protocol. UDP and ICMP admit **only `SF`** — all
eleven flags belong to TCP.

This reproduces Sheatsley et al.'s own failure case exactly: `tftp_u` is a UDP service with 3 Flows
in the Pool, and `ftp` is TCP-only, so the switch their unconstrained attack proposed is infeasible.
No service appears in KDDTest+ that is absent from the Pool, so the table is complete for this study.

---

## 3. The r2l signature

Per `attack_name` inside Category r2l (995 Pool Flows). `failed` = share with
`num_failed_logins > 0`, and so on.

| attack_name | Flows | failed | hot | guest | logged_in | file_creations | service | flag |
|---|---|---|---|---|---|---|---|---|
| `warezclient` | 890 | 0.000 | 0.402 | 0.344 | **1.000** | 0.000 | ftp_data, ftp | SF |
| `guess_passwd` | 53 | **0.981** | 0.981 | 0.019 | 0.019 | 0.000 | telnet | RSTO, RSTR |
| `warezmaster` | 20 | 0.000 | 0.050 | 0.100 | 0.100 | 0.100 | ftp_data, ftp | SF |
| `imap` | 11 | 0.000 | 0.182 | 0.000 | 0.091 | 0.000 | imap4 | SF, SH |
| `ftp_write` | 8 | 0.000 | 0.250 | 0.250 | 0.750 | 0.250 | ftp_data, ftp | SF |
| `multihop` | 7 | 0.000 | 0.571 | 0.286 | 0.571 | 0.571 | ftp_data, ftp | SF |
| `phf` | 4 | 0.000 | **1.000** | 0.000 | **1.000** | 0.000 | http | SF |
| `spy` | 2 | 0.000 | 0.000 | 0.000 | 0.500 | 0.500 | telnet | SF |

### 3.1 CONFIRMED (with a caveat): `num_failed_logins` is the guess_passwd signal

In the Pool, **98.1 %** of guess_passwd Flows carry `num_failed_logins > 0` (51 of 53 hold exactly
1), and no other r2l name carries it at all. Across the whole Pool only 122 Flows have it non-zero:
68 `normal`, 52 `guess_passwd`, 1 `satan`, 1 `rootkit`. So it is the attack's own signal and
zeroing it to evade a Detector would remove the attack — `fixed` is the right role.

**Caveat the report does not anticipate:** in KDDTest+ only **37.9 %** of the 1,231 guess_passwd
Flows carry it. The feature is the signal in the Pool, but a Detector that learns it from the Pool
generalises to barely a third of the test occurrences. That is a finding about NSL-KDD's
train/test mismatch, not about the constraint model, but it belongs in any discussion of results.

guess_passwd is otherwise extremely rigid: `service` is `telnet` in 53 of 53, `src_bytes` is
**exactly 126 in every single Pool Flow** (p50 = p90 = max = 126), and `flag` is `RSTO` in 45 of 53.
A mutation that pads `src_bytes` on a guess_passwd Flow leaves the only value the Pool has ever seen
for that attack.

### 3.2 CONTRADICTED: `is_guest_login` / `num_file_creations` are **not** definitional for warezmaster or ftp_write

The report states they are "definitional for warezmaster/ftp_write". The Pool says otherwise:

- `warezmaster` (20 Flows): `is_guest_login` non-zero in **10 %** (2 Flows), `num_file_creations`
  non-zero in **10 %** (2 Flows).
- `ftp_write` (8 Flows): both non-zero in **25 %** (2 Flows).

Neither is close to definitional. `is_guest_login` is in fact far more associated with
**`warezclient`** (34.4 % of 890 Flows) than with warezmaster.

Checked on KDDTest+, where warezmaster is 944 Flows rather than 20, the picture splits:
`is_guest_login` non-zero in **52.6 %** — suggestive but still not definitional — while
`num_file_creations` is non-zero in **0.1 %** (1 Flow of 944). **The `num_file_creations` claim is
contradicted outright in both files.**

This does not change the *role*: content features stay `fixed`, because the payload determines them
and the attacker does not choose them. It changes the *justification*. The feature-level reasons
given for those two names in the report's table should not be repeated in the thesis.

### 3.3 CONFIRMED with three exceptions: the dos content block is zero

Of the twelve content features, **nine are identically zero across all 45,927 dos Flows**:
`num_failed_logins`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations`, `num_shells`,
`num_access_files`, `is_host_login`, `is_guest_login`.

Three are not: `logged_in` (2.08 %), `hot` (2.06 %), `num_compromised` (1.92 %). **Every non-zero
value belongs to `back`**, a dos attack carried over http that really does complete a login. So the
report's objection to IDSGAN — that freeing the content block for dos writes application-layer
activity that never happened — holds for nine features and needs the `back` exception stated for
three. The model keeps content `fixed` for dos and records the exception.

---

## 4. Bounds for the direct levers

Increase-only (Apruzzese, TETCI 2020) now has data-backed ceilings rather than invented ones. p99 is
the plausible ceiling; max is the hardest wall the sensor ever recorded.

| Category | `duration` p50 / p90 / p99 / max | `src_bytes` p50 / p90 / p99 / max |
|---|---|---|
| `normal` | 0 / 1 / 6,381 / 40,504 | 233 / 1,182 / 16,787 / 89,581,520 |
| `dos` | 0 / 0 / **0** / **14** | 0 / 28 / 54,540 / 54,540 |
| `probe` | 0 / 6 / 40,142 / 42,908 | 1 / 8 / 215 / 1,379,963,888 |
| `r2l` | 0 / 134 / 12,546 / 15,168 | 334 / 1,269 / 5,135,678 / 5,135,678 |
| `u2r` | 47 / 179 / 321 / 708 | 277 / 2,402 / 2,628 / 6,274 |

The sharpest result: **for dos, `duration` has p99 = 0 and max = 14 seconds.** "Add a small latency"
is essentially unavailable to a dos attacker in NSL-KDD — any duration above 14 s is outside
everything the sensor has ever seen for that Category. The report's claim that dos keeps `duration`
as a lever survives only in a 0–14 s band.

For r2l the band is wide (up to 15,168 s), so added latency is a real lever there.

`src_bytes` maxima for `normal` and `probe` are absurd (89 MB, 1.38 GB) and are single outliers;
p99 is the number to use.

---

## 5. Constant and near-constant features

One feature is **constant**: `num_outbound_cmds` (single value, 100 %).

Twelve are **near-constant** at the 99 % threshold — their modal value covers at least 99 % of the
Pool: `land` (0.9998), `urgent` (0.9999), `is_host_login` (0.99999), `num_shells` (0.9996),
`su_attempted` (0.9994), `num_failed_logins` (0.9990), `root_shell` (0.9987), `num_root` (0.9948),
`num_file_creations` (0.9977), `num_access_files` (0.9971), `wrong_fragment` (0.9913),
`is_guest_login` (0.9906). In every case the modal value is `0`.

Note the tension this creates and do not paper over it: `num_failed_logins` is near-constant *and*
it is the guess_passwd signal. "Carries no information" is a statement about the marginal
distribution, not about discriminative value. A rare feature can be the whole story for a rare
Category.

---

## 6. Deviations from the research report

Also listed in `mutations.json` under `deviations_from_research_report`.

1. **`urgent`: "direct but implausible" → `fixed`.** The role vocabulary has no "implausible" value,
   and the report itself removes the feature through Pierazzi's plausibility constraint. The Pool
   agrees: zero in 99.99 % of Flows.
2. **`dst_bytes`: no dos override.** The report allows `direct` for dos "in botnet settings". That
   scope condition does not hold here — NSL-KDD dos targets a third-party victim that decides its
   own response — so `derived` applies to every Category.
3. **Content features under dos stay `fixed`**, against IDSGAN Table 1, on the evidence of §3.3.
4. **Three of the four predicted couplings are rejected**, on the evidence of §1.

---

## 7. What is still scientifically weak

- **The §4 directions are untested.** Every causal claim about behaviour — slowing down lowers
  `count`, dilutes the rate features, leaves the ten `dst_host_*` near-invariant — is unfalsifiable
  from a static CSV. NSL-KDD has no timestamps and no connection ordering, so the connection log
  cannot be replayed. The couplings are validated; the *directions* rest entirely on the published
  derivation semantics. `mutations.json` marks every one of them `support: synthesis`, and features
  the report gives no direction for are `unspecified` rather than guessed.
- **The r2l Pool is tiny.** 995 Flows over eight names, four of which have fewer than 10 Flows
  (`phf` 4, `spy` 2, `multihop` 7, `ftp_write` 8). Every per-name rate in §3 for those four is one
  or two Flows wide. Prefer KDDTest+ counts when a name is rare in the Pool, and say which file a
  number came from.
- **The Pool/test divergence is unresolved.** The one accepted rate identity degrades from 1.1 % to
  2.9 % violations, and the guess_passwd signal from 98 % to 38 %. NSL-KDD's train and test halves
  do not come from the same distribution (Tavallaee et al., 2009), and this model is fitted on one
  of them.
- **`diff_srv_rate` has no model.** Its identity was rejected and nothing replaces it. A consumer
  that needs to move it has only the marginal distribution to go on.
- **Roles are a three-value approximation.** `direct` / `derived` / `fixed` cannot express
  "settable but conspicuous" (`urgent`) or "derived, but from the victim rather than the attacker"
  (`dst_bytes`). Both were forced into `fixed` and `derived` respectively, and the reasoning is in
  §6 rather than in the vocabulary.
- **Duplicate Flows were not removed before fitting.** Tavallaee et al. report heavy duplication in
  the underlying KDD'99 data. Every rate here is over Flows as the Pool holds them, so frequent
  records weigh more. The couplings are per-Flow identities and are unaffected in kind, but the
  violation *rates* and the lever quantiles are weighted by that duplication.
