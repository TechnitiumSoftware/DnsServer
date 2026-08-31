# Development harness

Two Technitium instances in Docker, to develop and verify the console redesign
without touching any real DNS server.

| Instance | Port | What it serves |
|---|---|---|
| `dev` | http://127.0.0.1:5380 | `DnsServerCore/www/` mounted from the repo |
| `ref` | http://127.0.0.1:5381 | the `www` from the official image, untouched |

User `admin`, password `technitium-ui-dev` on both.

```bash
docker compose up -d      # start
./check-paridad.sh        # compare dev's front page against ref
./check-paridad.sh /api/  # compare another path
docker compose down -v    # tear everything down, config included
```

`ref` is the reference truth: the project's constraint is that behaviour must not
change, so any non-visual divergence between the two is a bug.

Port 53 is not mapped (`systemd-resolved` holds it on WSL) and DHCP is not
enabled: only the web console is exercised here.

## Why the comparison normalises line endings

`check-paridad.sh` strips `\r` before hashing, so it compares content and not
bytes. This is necessary, not cosmetic:

Upstream's `.gitattributes` declares `* text=auto`. Git stores **LF** in the
repository blobs and converts on checkout according to the platform. Our tree on
Linux has LF —and `git status` sees it clean, it is byte-correct with respect to
the repository— while **the official Docker image ships CRLF**, because it was
built on Windows.

Without normalising, two files with identical content come out different by one
byte per line: in `index.html` that is 7,426 bytes of difference out of 619,718.
Found when running the first parity check of phase 0.
