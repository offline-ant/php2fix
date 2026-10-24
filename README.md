# php2fix

- Its been 72 hours
- This was literally $10 and having an AI find and extend 9bie's work published on GitHub 60 hours ago.
- A growing number of people is spreading the nonsense this must not be an easy exploit or that it required non-stock options

So for educational purposes only:

> **Scope: mod_php (`apache2handler`) only.** This does not work on PHP-FPM, CGI
> or the built-in server — their request-startup order differs, so the dangling
> state the chain relies on never exists there. Everything else is stock: default
> `php.ini`, default 150-worker prefork, no pre-placed files, no config changes on
> the target.

Two files:

| file | what it is |
|---|---|
| `php2fix.php` | the self-replicating page. `GET` renders a form, `POST` runs the exploit against a target, `?txt` serves its own source **with one lineage line appended**, `?patch` makes this copy raise its own limits, `?d=1` is the self-contained installer a payload fetches, `?learn=` records confirmed offset sets, `?whoami=` returns the serving worker's pid. |
| `chain.sh` | builds a lab with podman from the stock images this was tested on (`php:8.2.34`, `8.3.35`, `8.4.26`, `8.5.11` `-apache`, trixie) and runs a replication chain through them. |

Nothing else is needed: the page is standalone, and `chain.sh` only calls `podman`.

## The chain

`chain.sh` seeds one container by hand ("patient zero", PHP 8.2); after that every
hop is the previous node fixing the next one over plain HTTP:

```
seed 8.2  →  8.2  →  8.3  →  8.4  →  8.5
```

Each installed copy inherits the history it was installed with, so the lineage
grows by one line per hop.  Measured run:

```
  php2fix-a82  (patient zero, seeded by hand)
  ├─ php2fix-b82 php 8.2.34   1-line lineage
  ├─ php2fix-c83 php 8.3.35   2-line lineage
  ├─ php2fix-d84 php 8.4.26   3-line lineage
  └─ php2fix-e85 php 8.5.11   4-line lineage
        * I got fixed by ... (http://10.0.2.2:43104/php2fix.php) at ...
        * I got fixed by ... (http://10.0.2.2:43103/php2fix.php) at ...
        * I got fixed by ... (http://10.0.2.2:43102/php2fix.php) at ...
        * I got fixed by ... (http://10.0.2.2:43101/php2fix.php) at ...
```

Every hop printed `RCE OK` plus a marker such as
`p2f installed:/var/www/html/php2fix.php php=8.5.11 bin=/usr/local/bin/php pid=41 host=...`.
Hops took 8 s, 2 s, 2 s and 42 s; the 8.5 node is slower only because it sweeps
more offsets (see below).  All four nodes were stock: no ini change, no
single-worker override, no pre-placed file.

## Running it

```sh
./chain.sh                 # build, run the 4 hops, print the lineage, tear down
./chain.sh --keep          # leave the containers running
./chain.sh --rebuild       # re-create the containers first
./chain.sh --patch         # each fixed node raises its own limits (see below)
PODMAN="podman --root ~/.local/share/containers/storage" ./chain.sh   # any wrapper with the same args
```

Networking: the containers use `slirp4netns:allow_host_loopback=true`, so each
node reaches the next at `10.0.2.2:<published port>`.  Rootless *pasta* cannot do
container→container at all, which is why this mode is used.  Ports are high
(`43101`+), one per node.

## How the two stages find each other

The exploit is two pairs of requests, and each pair must run in the **same**
worker: `A1` arms a worker, `B1` reads its memory; `A2` arms it again, `B2` writes.

A stock prefork does **not** keep 150 workers busy — it keeps `StartServers` (5 in
the official images) and hands sequential requests to them **round-robin**.
Measured on a fresh stock node, 220 sequential requests produced exactly five
pids, cycling `18,19,17,20,21`.  The pool only grows past five when requests
overlap.

So the two halves of a pair land in the same worker when exactly *pool − 1*
requests sit between them, and the pool size is not observable from outside.
The tool therefore **sweeps the offset** (`gap`), starting at 4 because that is
the stock pool's value, and lets the result decide: the leak says which offset
aligned for `A1/B1`, and the marker does the same for `A2/B2` (the write pair
needs its own offset, because `A2`'s out-of-memory abort keeps its child busy for
a moment and shifts the queue).  The interleaved requests must **not** be PHP:
a PHP request would run in that worker's VM and move the heap the stages depend
on, so they hit a non-existent path.

### Refreshing the pool, and why "cold" matters

8.5's dangling struct sits at one page index only on a worker whose per-request
state is pristine; once the worker has served a request the index moves.  A
prefork child that faults is replaced by the master, so **faulting every child
turns a warm pool into a cold one** — that is what `refresh()` does before each
attempt (eight writes with a deliberately bogus fake-array address; they crash
the children and the master respawns fresh ones).

Measured on the same warmed node: the leak succeeded **1/18** attempts before the
refresh and **3/3** at the stock offset after it.  "Cold" here means the
heap/per-request state, not opcache — a respawned child still shares the master's
opcache, which is why the tool never warms anything.

## Scope and honest limits

* **mod_php (`apache2handler`) only** — not PHP-FPM, CGI or the built-in server:
  their request-startup order differs, so the dangling-state chain does not exist.
* It exploits PHP **8.2, 8.3, 8.4 and 8.5** on x86-64 NTS builds.  Another
  build of the same version needs its own offsets, which is what `?learn=` is for.
* Every node is **stock**: default `php.ini`, default 150-worker prefork.  The
  only thing the tool needs from a target is what a normal web app needs:
  `file_uploads=On` and `session.upload_progress.enabled=On` (both default).
* `?learn=` writes into its own source, so it is deliberately narrow: the version
  must equal the running `PHP_VERSION`, the offsets must be bare hex, the source
  label is clamped to `[A-Za-z0-9._-]`, and entries only land inside the
  `/* P2F-KNOWN` comment (max 32, never overriding a built-in).  The worst a
  hostile caller can do is add a *candidate* offset set — never code.
* `memory_limit=-1` makes a node permanently un-exploitable (the abort is what
  arms the worker), so a hop never applies it to its **target**.  `--patch` asks
  each *freshly fixed* node to patch **itself** (`GET ?patch`) so that it can act
  as the attacker for the next hop.

## Per-version results (stock containers, warmed, driven from a host controller)

| node | prefork | result | notes |
|---|---|---|---|
| php 8.2.34 | stock, 5→150 workers | **RCE OK** | leak `decoded=786440` |
| php 8.3.35 | stock, 5→150 workers | **RCE OK** | leak `decoded=786440` |
| php 8.4.26 | stock, 5→150 workers | **RCE OK** | leak `decoded=786440` |
| php 8.5.11 | stock, 5→150 workers | **RCE OK** | needs the refresh above; slowest hop |

"Warmed" means each node was given 20 PHP requests before the attempt, i.e. it
looks like a server that has been serving traffic — not a pristine container.
