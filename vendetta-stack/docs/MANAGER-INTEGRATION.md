# Manager integration

Host endpoint, network, auth and audit logs reach CS3 through Fluent Bit. Left alone, they arrive as flat log lines: no rule ID,
no manager-derived severity, no decoder, no MITRE mapping. This document describes the path that fixes that.

There are two directions and they are deliberately small:

```
host.syslog | host.auth | host.audit
host.network | host.endpoint ────────► manager :5140/udp ──► decoders + rules 10120-10199
                                                                      │
                                                       alerts/alerts.json (level >= log_alert_level)
                                                                      │
                          Fluent Bit tail (manager.alerts) ──► POST /api/cecur/manager/alerts
                                                                      │
                                                     CecurAlert (rule ID, event time, device, level)
```

The manager decides. CS3 only adapts the structured alert it produces.

## Enabling it

Fluent Bit side (`.env.example`):

```dotenv
CS3_MANAGER_ENABLED=true
CS3_MANAGER_HOST=vendetta-manager
CS3_MANAGER_PORT=5140
CS3_ALERT_DEDUP_WINDOW_S=300
```

`CS3_MANAGER_ENABLED=true` requires `CS3_HOST` (alerts out), `CS3_MANAGER_HOST` (logs in) and `CS3_INGEST_KEY_FILE`; the entrypoint
refuses to start without them.

Manager side: nothing. The wiring is the s6 cont-init stage `vendetta/manager/05-cs3-manager-integration.sh`, which compose mounts at
`/etc/cont-init.d`. It runs after `0-wazuh-init` has restored `/var/ossec` and before any service starts, installs the decoders and
rules into `/var/ossec/etc/decoders/0001-cs3-decoder.xml` and `/var/ossec/ruleset/rules/9999-cs3-rules.xml` and splices the
loopback syslog receiver into `ossec.conf`. A wrapper cannot do that work: anything it writes before `/init` is overwritten by the
init restore, which is why `entrypoint.sh` only installs the stage and execs `/init`. The Helm deployment mounts no cont-init
directory, so there the entrypoint copies the stage in first.

**The manager leg is not the same switch as the manager profile.** `--profile manager` runs the bundled manager; `CS3_MANAGER_ENABLED`
points Fluent Bit at *some* manager. A deployment using an existing manager keeps the leg on and leaves the profile off.

## Which streams are analysed

The leg takes `host.syslog`, `host.auth`, `host.audit`, `host.network` and `host.endpoint` — everything that has already been
classified into a host family. Two classifiers feed it, both in `fluent-bit/conf.d/70-filters-global.conf`:

| Classifier | Input | Notes |
|---|---|---|
| `host_source_tagger` (section 0) | `host.syslog` | appliance/network syslog. Ordered `rewrite_tag` rules, first hit wins, `KEEP=false` |
| `host_journal_tagger` (section 2b) | `host.journal` | journald, where endpoint events actually originate: unit failures, kernel OOM/segfault, container/workload output. Runs *after* the leaky bucket, because the bucket keys on `host.journal` and classifying earlier would let a whole-journal burst bypass `CS3_EPS_LIMIT` |

The journal classifier is deliberately not a catch-all: a journal line that matches none of its rules stays on `host.journal`
(console only) instead of pushing the entire journal into the rule engine. `host_journal_shape` promotes `SYSLOG_IDENTIFIER` into
`source` and `HOSTNAME` into `host` first, so the record reaches the manager with a real program name and a real device instead of
`syslog@localhost`.

On the manager side, `systemd` and `kernel` lines hang off the stock grouping rules, and container runtimes (`containerd`,
`dockerd`, `podman`, `crio`, `runc`, `kubelet`, `k3s`) hang off the CS3 parent `10121` — no stock rule owns those program names, so
without it they fall to the generic syslog rule `1002` at level 2, below `log_alert_level`, and are dropped.

## What is preserved, and why

| Field | Where it comes from | Why it survives |
|---|---|---|
| `rule.id` | `rule.id` | it is the identity of the detection; without it an alert is unattributable |
| event time | `timestamp` | ordering and MTTR are measured from when it happened, not when it was shipped |
| device | `predecoder.hostname` for syslog-sourced events, otherwise `agent.name` / `agent.ip` | scope; which host is affected. Remoted attributes a syslog-remote event to the manager itself (agent `000`), so the id is deliberately not trusted alone: the device is the RFC3164 hostname Fluent Bit wrote, and dedup keys on that too, otherwise every endpoint would collapse onto one row |
| severity | `rule.level`, clamped to 1-15 | the manager's own judgement, not a heuristic |
| MITRE, compliance, src/dst/user/path/hash | `rule.mitre`, `rule.pci_dss`, `data.*` | already extracted; re-deriving it would be lossy |

`fullLog` carries the whole alert, so nothing that the alert model has no column for is lost either.

## Deduplication

Key: `ruleId|device|locator` where the locator is the most specific of src IP, path, hash, process, user or decoder. A repeat inside
`CS3_ALERT_DEDUP_WINDOW_S` (default 300 s, `0` disables) increments `count` and `lastSeen` on the existing row and raises `ruleLevel`
if the recurrence is more severe. The cache is pruned on every batch and capped at 5000 entries.

This is also what makes retries safe: Fluent Bit retries a failed batch, and replay lands on the same key.

## Failure modes

| Failure | Behaviour |
|---|---|
| Manager down | the inbound leg's syslog output drops after `Retry_Limit 3`; Fluent Bit's own buffers still deliver to CS3, so logs are not lost, they are just not enriched until the manager returns |
| CS3 down, or the alert route answers 503 | alerts park in the leg's filesystem buffer (`Retry_Limit False`) and replay; deduplication collapses the replay |
| Nothing in a batch is adaptable | the route answers **422**, not 201, so a broken producer is visible instead of a silent empty success |
| Alert route cannot write the audit record | 503 with the accepted IDs, so the caller retries — safely, because of deduplication |
| `ossec.conf` splice fails | warning by default (agents keep reporting); `CS3_MANAGER_STRICT=true` aborts the manager boot instead |
| A CS3 rule ID collides with an existing rule | the manager refuses to start and names the offending file, rather than silently shadowing a rule |

## Rule block

`10120-10199` is reserved for CS3 and enforced by `patch-ossec-conf.sh`: an ID outside the block, or one already defined in the
ruleset, stops the boot. Rules currently use `10120`-`10179`; extend upward.

The block sits low in the stock ID space, and that is not cosmetic. `analysisd` walks rules in load order and stops at the first
rule that matches with a level above zero, so a CS3 rule only wins a line when it is a **child of the stock grouping rule that
owns that line** (sshd `5700`, sudo `5400`, auditd `80700`, systemd `40700`, kernel `5100`/`5108`). The file therefore has to load
after those parents exist, which means `/var/ossec/ruleset/rules/9999-cs3-rules.xml` — not `etc/rules`, which loads before the
entire stock ruleset and leaves every parent unresolvable. The three families the stock ruleset groups with `<decoded_as>` get one
narrow CS3 parent of their own (`10120`), because their stock parent stops matching as soon as a CS3 decoder claims the line.

Two consequences worth knowing before editing the block:

* Do not use `<decoded_as>` for a CS3 decoder. `analysisd` resolves `decoded_as` against stock decoder category names only and
  drops a rule that names a decoder from `etc/decoders` with `(7611) Category was not found`. Rules match on `program_name` and
  `match` instead — both are plain `OS_Regex` fragments, so `program_name` takes a literal or a `|` alternation (`^sshd$|^sudo$`)
  and never a quantifier (`^.*$` matches nothing).
* Keep the IDs ascending and every child above its parent. A rule whose `if_sid` is not yet loaded is dropped (`(7617)`), and a
  grouping parent that never matches blocks all of its children.

The decoder file is `etc/decoders/0001-cs3-decoder.xml`. The `0001-` prefix is load order too: decoders are tried in lexical file
order, and without it the stock broad `sshd`/`sudo`/`audit` decoders claim the line before the CS3 ones can supply
`srcuser`/`dstuser`/`srcip`.

Raising a level is the supported way to make a class of event louder — the CS3 side maps `rule.level` straight onto alert severity.

## CTI / vulnerability feeds

The stock manager image enables the content updater against `cti.wazuh.com` every 60 minutes. A deployment without egress — the
usual CS3 case, with loopback-bound ports — fails that fetch on every interval and fills `ossec.log` with
`wazuh-modulesd:content-updater: ERROR: ... Couldn't resolve host name`. `configure-feeds.sh` (run by the same cont-init stage)
owns that block:

| `CS3_MANAGER_FEED_MODE` | Effect |
|---|---|
| `off` (compose/Helm default) | `<vulnerability-detection><enabled>no</enabled>` — the updater never fetches |
| `mirror` | keeps it enabled and sets `<cti-url>` from `CS3_MANAGER_CTI_URL` (an internal CTI mirror) |
| `auto` | leaves the image default and logs what will happen, so the operator can decide |

`enabled`, `cti-url` and `feed-update-interval` are supported keys, so this is configuration rather than an environment fault. For
online deployments the other half of the fix is manager DNS egress, which the chart's NetworkPolicy does not grant.

## Owning the configuration instead

Set `CS3_MANAGER_CONF_TEMPLATE` to a complete `ossec.conf` and the splice is skipped. The file must contain the
`cs3:manager-integration` marker and the syslog receiver; otherwise the wrapper still installs it but warns that host logs will not
be enriched. Use this when the deployment owns manager configuration through config management, cluster join, or extra `<remote>`
blocks that a patch would flatten.

## Verification

```bash
tests/test_manager_patch.sh                      # splice idempotency, collision and range guards, XML well-formedness
tests/test_manager_leg.sh                        # leg renders only when enabled, both directions, fail-closed settings
docker compose --profile manager config          # rendered wiring: entrypoint, 5140/udp, networks
cd demo/demo-100226 && npm test -- tests/cecur    # adapter mapping, dedup, rejection
```
