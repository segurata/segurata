<p align="center">
  <img src="site/assets/segurata.webp" alt="Segurata's illustrated security guard" width="168">
</p>

# Segurata

Segurata is a security audit CLI for accounts and computers you manage. It inventories connected
apps, browser extensions, cloud and AI credentials, and secrets on disk. A local tracker shows
what needs attention and records what happened across scans.

[Project website](https://segurata.github.io/segurata/)

## Install

With Go 1.26 or later:

```bash
go install github.com/segurata/segurata/cmd/segurata@latest
```

Or with Homebrew on macOS and Linux (`brew install --cask segurata/tap/segurata`) or Scoop on
Windows (`scoop bucket add segurata https://github.com/segurata/scoop-bucket`, then
`scoop install segurata`). See the [installation guide](docs/releasing.md#installing) for source
builds, release archives for macOS, Linux and Windows, and signature verification.

## Quickstart

```bash
segurata doctor --connector browser-extensions
segurata inventory browser-extensions
segurata status
```

This first scan reads local Brave or Chrome profiles without provider credentials.
Run `segurata connectors` to see the other connectors available on your machine.

Inventories are read-only on the systems they inspect. Findings and tracker state stay on disk.
Supported changes start with a preview. [Read what leaves your machine](docs/user-guide.md#what-leaves-your-machine).

## Documentation

| Task | Guide |
| --- | --- |
| Configure a connector or find a supported provider | [Inventory](docs/inventory.md) |
| Sign in, manage findings, export a report, or schedule a scan | [User guide](docs/user-guide.md) |
| Find and rotate exposed credentials | [Secrets guide](docs/secrets.md) |
| Understand how Segurata works or build a connector | [Architecture](docs/architecture.md) · [Connector development](docs/connectors.md) |
| Contribute or report a vulnerability | [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) |

For agents working from a checkout, use [segurata-audit](.agents/skills/segurata-audit/SKILL.md)
for onboarding and inventory, and [segurata-remediate](.agents/skills/segurata-remediate/SKILL.md)
to preview a finding's fix and verify an authorized change.

[Apache License 2.0](LICENSE)

Proudly brought to you by [DjinnFoundry](https://djinnfoundry.com).
