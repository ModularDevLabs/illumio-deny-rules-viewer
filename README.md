# Illumio Deny Rules Viewer

Small self-contained Go web UI for inspecting deny rules from an Illumio PCE.

It shows:
- enforcement boundaries
- deny rules inside rulesets
- friendly source, destination, and service names
- service port/protocol details
- matching workloads for a ruleset scope

## Features

- Active-policy focused views for deny rules
- Multiple saved PCE profiles with one active profile
- Embedded templates and static assets
- CSV export
- Click-through workload expansion per ruleset
- Local secret files ignored from git

## Run

```bash
make build
./deny-rules
```

Default address:

```text
http://localhost:8082
```

## Configure PCE Profiles

Open `/config` and create one or more named profiles.

Each profile stores:
- PCE host
- port
- org ID
- API key
- API secret
- TLS verification setting

Saving a profile also activates it. You can switch the active profile later from the saved profiles list.

Profiles are stored locally in:

```text
.pce-profiles.json
```

Legacy `.env.local` values are still read as a fallback if no profile store exists yet.

## Build Outputs

```bash
make build
make dist
```

Artifacts:
- `deny-rules`
- `dist/deny-rules-linux-amd64`
- `dist/deny-rules-linux-arm64`
- `dist/deny-rules-darwin-amd64`
- `dist/deny-rules-darwin-arm64`
- `dist/deny-rules-windows-amd64.exe`

## Security Notes

- `.env` and `.env.local` files are ignored from git.
- The app keeps local PCE credentials in `.pce-profiles.json`.
- Do not commit local credential files.
- If a credential is ever pushed, rotate it immediately.

## Repo Maintenance

After each completed feature change in this workspace:
- rebuild binaries
- commit the change
- push to `main`
