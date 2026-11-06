# Content on the Radar: Microsoft Sentinel Content Hub Change Monitor

**New content. Clear signals. Fewer trips to the Content hub.**

Microsoft Sentinel's Content hub keeps growing. Your browser-refresh habit
doesn't have to.

Content on the Radar checks the catalog, remembers what it has seen, and flags
what deserves a look: new packages, published-version changes, installed-version
gaps, and deprecation. Think of it as a lookout for your content library, not
another source of incident noise.

A portable Python 3.10+ program that detects newly available Content hub packages,
published-version changes, installed-version gaps, and deprecation. This is a
working local program, not a deployed Logic App or Power App. It never installs,
updates, or enables Sentinel content.

## What comes into view

| Signal | What it means |
| --- | --- |
| New package | A solution or standalone package appeared since a successful baseline |
| Published version changed | A known package has a different available version |
| Installed-version gap | An installed package differs from the available version |
| Deprecation | A package is newly marked deprecated |

The first run takes attendance. Later runs report the changes. No opening-day
notification avalanche, no automatic deployments, and no surprise enabled rules.

**The short version:** scheduled Python program → Sentinel catalog API →
SQLite inventory and outbox → optional Logic App/Power Automate notification.

## Get it on your radar

Clone the repository, then run in its directory:

```powershell
git clone https://github.com/homelabber/content-on-the-radar.git
Set-Location content-on-the-radar
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item config.example.json config.json
```

Edit `config.json` with your subscription, resource group, and Sentinel workspace.
The database path is relative to the configuration file. Keep one database per
workspace. Leave `publisher_filter` empty to monitor all publishers; otherwise
provide exact publisher names (case-insensitive). Filtering affects notification
selection, not inventory or history; changes already filtered are not replayed
when filters are changed.

For an interactive local run, sign in with `az login`, select the appropriate
tenant/subscription, then:

```powershell
.\.venv\Scripts\python.exe monitor.py check
.\.venv\Scripts\python.exe monitor.py status
.\.venv\Scripts\python.exe monitor.py history --limit 50
```

Default authentication uses `az account get-access-token` through the installed
Azure CLI and requires no third-party Python libraries. Set `authentication` to
`azure_identity` and install `requirements-azure.txt` to use Azure Identity's
`DefaultAzureCredential` for managed identity or environment-based credentials.
The optional SDK needs compatible cryptography wheels or native build tools;
the default mode works with ARM Windows Python without those tools.
No credentials are stored in the configuration file. Use read-only Azure RBAC
access to the Sentinel workspace (start with Microsoft Sentinel Reader); verify
that the principal can list `Microsoft.SecurityInsights/contentProductPackages`.
No Contributor access is required by this program.

The first complete successful check establishes a quiet baseline, including any
pre-existing installed-version gaps. Subsequent checks detect new changes and
print pending notification JSON without sending it. Version differences are
review advisories, not proof that an installed version is older or that an
upgrade is safe.

## Deliver the signal, not the noise

Notifications are opt-in. Until you configure a destination and use `--send`,
the monitor keeps its observations local.

Create a Logic App or Power Automate flow with an HTTP request trigger accepting
JSON. Connect its action to your chosen Teams channel or email recipients.
Use the incoming `text` field as the plain-text message body. The payload also
contains `schema_version`, `digest_id`, `workspace`, `content_hub_url`, and an
`events` array. Use `events` for a SharePoint/Dataverse review list if desired.
Treat catalog strings as data; escape them if rendering HTML or Markdown.

The endpoint is a generic JSON receiver, **not** a legacy Teams Incoming Webhook
or an Adaptive Card endpoint. The receiving workflow must translate the payload
into its Teams/email action. HTTP-trigger availability, licensing, and endpoint
authentication depend on your tenant. This client supports a secret-bearing
HTTPS trigger URL, not an Entra-authenticated trigger. Use an access-controlled
workflow and keep its URL in the configured environment variable, never in source
control. If organizational policy requires an Entra-authenticated trigger, extend
the notification authentication before enabling delivery.

Set `SENTINEL_CONTENT_WEBHOOK_URL` securely in the environment of the executing
account. Preview a normal `check`, approve the destination and its content, then
enable sending explicitly:

```powershell
.\.venv\Scripts\python.exe monitor.py check --send
```

Each sending run sends at most 25 pending events as a digest. Larger backlogs are
drained by subsequent runs. A successful 2xx response marks the batch delivered;
for asynchronous workflows, this means accepted by the receiver, not confirmed
Teams/email delivery. Monitor the receiving workflow for downstream failures.
The program does not send errors through the content webhook; failures go to
stderr with exit code 1. Add scheduler/host monitoring for failed runs and stale
`last_success` values.

## Put the lookout on a schedule

In Task Scheduler, create a daily task under the same account/environment that
has Azure access:

- Program: `C:\Windows\System32\cmd.exe`
- Arguments: `/c ""C:\FULL-PATH\content-on-the-radar\run.cmd""`
- For approved notifications, arguments:
  `/c ""C:\FULL-PATH\content-on-the-radar\run.cmd" --send"`
- Select **Do not start a new instance** if the task is already running.

Replace `C:\FULL-PATH` with the actual project parent directory. `run.cmd` resolves
its own working directory and propagates the monitor's exit code. For unattended
hosting, do not rely on an interactive Azure CLI session remaining signed in:
use a dedicated identity configured according to organizational policy. On an
Azure VM, set `authentication` to `azure_identity` and install the optional SDK,
or sign the Azure CLI in using managed identity (`az login --identity`).

## Guardrails: a radar, not an autopilot

Useful automation should be boring about data integrity. This monitor keeps
the baseline intact when a refresh fails and records changes before delivery.

- Uses the workspace-scoped ARM Product Packages API, version `2025-09-01`,
  requesting expanded installed metadata.
- Follows all `nextLink` pages and rejects off-resource continuations, redirects,
  duplicate package identifiers, malformed responses, and empty catalogs.
- Commits catalog and changes atomically in SQLite only after a complete fetch.
  Failed refreshes preserve the previous successful baseline.
- Retains previously seen packages so temporary disappearance/reappearance does
  not produce another new-package alert. It does not infer removals from absence.
- Stores an outbox before sending. Failed sends remain pending. Overlapping local
  processes are serialized by database transactions.
- Delivery is **at least once**, not exactly once: a timeout or crash after receiver
  acceptance but before database commit can produce a duplicate. Use `digest_id`
  for receiver-side deduplication if needed.
- SQLite must be on a local disk, not a network share or a database concurrently
  edited by OneDrive synchronization. For production, set `database` to a local,
  nonsynced absolute path; use Azure storage/SQL for distributed runners.
- Detects package-level changes, not individual connector/rule changes within a
  package. Missing installed-version metadata cannot identify an update gap.
- "New" means newly available to this monitor, not necessarily newly published
  worldwide. Workspace visibility changes can introduce older packages.
- History contains workspace context and catalog metadata. Protect its access.

## Take a synthetic test flight

No Azure access is needed for the offline examples. The sample packages are
fictional; the detection and persistence paths are real.

Use the included **separate** `demo.config.json` and demo database; do not seed a
live workspace database with synthetic data. Placeholder workspace settings are
acceptable for fixture runs:

```powershell
python monitor.py --config demo.config.json check --fixture demo-baseline.json
python monitor.py --config demo.config.json check --fixture demo-changes.json
python monitor.py --config demo.config.json check --fixture demo-changes.json
python monitor.py --config demo.config.json history
python -m unittest discover -s tests -v
```

The first command establishes a baseline; the second detects three events
(version change, installed-version gap, new package); repeating it detects zero
additional changes. Pending events remain visible until delivered. Fixture mode
cannot send notifications.

## Scope and project status

This initial implementation is a command-line monitor with JSON history and
notification integration points. A visual dashboard, Power App, hosted Logic
App deployment, and component-level package comparisons are not included.

This is an independent project, not an official Microsoft product. Microsoft
Sentinel and Azure are trademarks of Microsoft. Validate permissions, hosting,
and notification behavior in your environment before production use.

## Straight from the source

- [Product Packages - List](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list)
- [Discover and manage Sentinel Content hub](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-deploy)
- [Azure Identity for Python](https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme)
