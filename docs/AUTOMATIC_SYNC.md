# Automatic submodule synchronization

An upstream push to `main` runs the kit's checks. When that workflow succeeds,
`Notify fleet consumers` sends an authenticated `repository_dispatch` event to
each enrolled consumer. The consumer verifies the exact upstream commit again,
advances the matching gitlink on its default branch, runs its commit gates, and
pushes a normal commit. That push runs the consumer's existing CI.

The event type is `fleet-submodule-update`. This uses GitHub's dispatch API as
the webhook receiver, without an external server. Do not add a repository push
webhook pointing directly at `/dispatches`: GitHub's ordinary webhook delivery
does not attach the API authentication or dispatch payload that endpoint needs.

The implementation is shared by fleet-guards and fleet-style. Consumers install
one small workflow from [the template](../templates/fleet-sync.yml). The reusable
workflow and synchronization script live in fleet-guards. The reusable workflow's
`@main` reference is an intentional trust decision: enrolled consumers automatically
accept workflow updates. Both dispatcher and consumer checkouts pin the Python
updater to a reviewed, immutable commit, so a newer unverified script cannot run
while an earlier notification is being processed. After changing the updater,
run its tests and review it, commit it, then advance both workflow checkout pins
to that commit in a separate commit.

## Enroll a consumer

1. Install the kit as a submodule using its public HTTPS URL. The `.gitmodules`
   entry must track `main`, or omit `branch` to use `main`. Other branches are
   rejected rather than silently moved; a custom upstream tracks its declared
   branch instead, see [Private or custom upstreams](#private-or-custom-upstreams).
   Submodule paths are read from
   `.gitmodules`; they do not have to be named `guards` or `style`.
2. Complete the fleet-guards hook installation. Commit `.githooks/pre-commit`
   and `.githooks/pre-push` forwarding shims that fail if the guard kit is absent.
   Set `core.hooksPath` to `.githooks`, never directly to the submodule directory.
   Commit both shims with executable Git mode `100755`; on Windows use
   `git add --chmod=+x .githooks/pre-commit .githooks/pre-push`. Synchronization
    checks both the Git mode and the runner's executable permission before committing.
    If the consumer also needs the optional machine-level commit-message rule, install the
    `.githooks/commit-msg` shim from the [installation instructions](../README.md#install),
    with executable Git mode `100755`. This optional shim does not change the two required
    security shims or their directory.
3. Copy `guards/templates/fleet-sync.yml` to `.github/workflows/fleet-sync.yml`
   and commit it on the consumer's default branch. Adjust the copy source if
   the guard submodule has another path. The job runs on `ubuntu-latest` unless
   the caller passes the optional `runs-on` input, a JSON string holding one label
   or a label array, for example `runs-on: '["self-hosted","linux"]'` under `with:`.
   A self-hosted runner needs git, bash, outbound HTTPS to github.com and
   api.github.com, and a Python 3 that `actions/setup-python` can resolve from its
   tool cache. The GitHub CLI is not used; the updater calls the REST API directly.
4. Create the consumer Actions secret `FLEET_SYNC_TOKEN`. Use a dedicated GitHub
   App token or a fine-grained token with Contents read/write for that consumer,
   and Actions read access to the two public kit repositories. A classic token
   needs `repo` access. Do not put credentials in a workflow, URL, or git config.
   This token performs the push so the resulting commit triggers ordinary CI;
   pushes made with the built-in `GITHUB_TOKEN` would suppress those workflows.
5. Enroll the consumer in each kit it actually uses, as described below. Ensure
   repository Actions policy allows the shared workflow and checkout/setup-python
   actions. Branch protection still applies; grant the automation the appropriate
   repository permission if direct default-branch updates are protected.
   If a separate CI gate restricts commit identities, register
   `github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>`
   as an allowed automation service before the first synchronization.
6. Run `Sync fleet submodules` manually once. Verify its run, the resulting
   gitlinks, and the consumer CI on the new commit. A dispatch API response of
   HTTP 204 only means the event was accepted, not that synchronization completed.

Only the declared kit gitlinks can enter an update commit. Missing kits, missing
hook shims, unknown sources, failed CI, divergent git history, and unrelated staged
changes stop the run. No force-push is used. Automation commits use the GitHub
Actions bot's noreply identity and explicitly configure the hook's supported
expected-identity setting for that checkout.

## Configure each upstream

Each kit needs two Actions secrets. Keep their source configuration in a private,
versioned administration repository. Consumer names can disclose private projects;
the public kit repository must not contain a real subscriber inventory.

`FLEET_SYNC_TARGETS` is a nonempty JSON array. This is a synthetic example:

```json
[
  {"repository": "example/consumer", "credential": "primary"}
]
```

`FLEET_SYNC_CREDENTIALS` is a JSON object mapping each credential key to its token.
The `primary` token in this example needs Contents write access to `example/consumer`
to send repository dispatch events. Different entries may select different keys;
each key must exist and contain a token. Enter the real values through GitHub's
Actions secret UI or `gh secret set`, never through a public configuration file.

Use `gh secret set FLEET_SYNC_TARGETS --repo example/upstream < private-targets.json`
from a shell that supports input redirection. Set `FLEET_SYNC_CREDENTIALS` through
standard input in the same way. Keep the inventory in a private administration
repository. Credential material belongs in a credential store or a PRIVATE
administration repository whose policy explicitly permits credential backups.
Never commit either secret to a public repository or print it in CI. Rotating a
versioned credential requires revoking or replacing the credential itself; editing
the current file does not remove it from history.

The dispatcher validates every subscription and credential before sending. It
sends up to four notifications concurrently, checks HTTP errors, and fails if any
notification fails. Its public output contains aggregate counts, never subscriber
names or credential values. Duplicate subscriptions and an empty list are errors.

## Private or custom upstreams

The two kits are built in: they are always followed on `main` through their own
gate workflows, and no declaration can change that. Any other repository, public
or private, can join the same path as a custom upstream. Nothing about it is
recorded in this kit; the upstream and each consumer declare it themselves. The
names below are synthetic: `example/upstream` publishes from `master` and gates
every push with `.github/workflows/ci.yml`, whose `name:` is `ci`.

A private upstream belongs only in PRIVATE consumers. A public consumer publishes the upstream's name in its `.gitmodules`, in the `sources` declaration of its workflow file, and in its Actions logs, which anyone can read (the checkout and fetch steps print the submodule URL, and the step environment shows the `sources` value). Keeping the upstream private does not hide its name once a public repository follows it. A public upstream can be followed from any consumer.

On the upstream:

1. Run a gate workflow on every push to the published branch. Only a successful
   `push` run of that workflow on the branch tip qualifies, exactly as for the
   kits; a failed or still-running latest attempt blocks notification.
2. Copy [the notify template](../templates/upstream-notify.yml) to
   `.github/workflows/fleet-notify.yml`. Set the `workflow_run` name and branch
   filter, and pass the gate's file name and the branch as the `workflow` and
   `branch` inputs of the reusable `dispatch-consumers.yml`. The dispatcher
   verifies the tip of that branch against that workflow before sending anything.
3. Create the `FLEET_SYNC_TARGETS` and `FLEET_SYNC_CREDENTIALS` Actions secrets on
   the upstream, in the same format as for the kits above. The dispatch output
   still contains only aggregate counts.

On each consumer:

1. Add the upstream as a submodule. Its `.gitmodules` entry must name the declared
   branch; a missing `branch` means `main`, so an upstream that publishes from
   `master` needs `branch = master`. A mismatch stops the run instead of tracking
   the wrong branch.

   Each submodule path belongs to exactly one `.gitmodules` entry. Two entries on the same path, or one nested inside another's path (compared without regard to case), stop every run. A declared upstream can never sit at, inside or around a built-in kit's path: the commit gate runs the code found at the fleet-guards path, so another repository's commit must never be checked out there. The fleet-guards path must also be a tracked gitlink.
2. Declare the upstream in `.github/workflows/fleet-sync.yml`:

   ```yaml
   jobs:
     sync:
       uses: DaizeDong/fleet-guards/.github/workflows/sync-consumer.yml@main
       with:
         sources: '{"example/upstream": {"workflow": "ci.yml", "branch": "master"}}'
       secrets:
         sync-token: ${{ secrets.FLEET_SYNC_TOKEN }}
   ```

   The value is a JSON object keyed by `owner/repo`; each entry has exactly the fields `workflow` (a file name, no path) and `branch` (a short branch name). Malformed JSON, unknown fields, invalid names, duplicate entries and any attempt to redeclare a built-in kit with other settings are errors. A full ref such as `refs/heads/master` is rejected, and so is a branch name that is also a 40- or 64-character hexadecimal object id, because git and the API would read it as a commit. Declaring a kit with its own settings is accepted and changes nothing: the entry is dropped, so no declared upstream ever has a kit's URL.
3. `FLEET_SYNC_TOKEN` must be able to read the private upstream: Contents read and Actions read on it, in addition to the consumer permissions listed earlier. It is used for the initial `actions/checkout` with submodules, for the API checks, and for the fetch. The updater gives git that credential only through the environment of each fetch command, never in a URL, an argument or a persisted config file. That environment first empties the extra headers persisted for github.com, both the header `actions/checkout` writes into submodule configs and any unscoped one, so each request carries exactly one Authorization header. One limitation remains: a header persisted for a narrower scope, such as one repository's URL, outranks these settings, and git then sends that header instead of the updater's credential (never both). Do not leave such a setting in a consumer checkout.

A notification names one upstream. A payload naming a repository that is neither
built in nor declared by the consumer is rejected; it never falls back to
reconciling everything. Scheduled and manual runs reconcile every built-in and
declared upstream. Ancestry checks and obsolete-notification handling are the same
as for the kits.

Scheduled and manual runs commit everything or nothing, so a declared upstream is coupled to the kits there and the coupling fails closed. If any declared upstream fails during such a run (its gate is red or still running, its `.gitmodules` branch differs from the declaration, the branch no longer exists, or the token cannot read the repository), the run stops before committing and the built-in kits do not advance either. A malformed `sources` value, including one that redeclares a kit with other settings, and a `.gitmodules` file in which two entries share or nest a path stop every run, kit notifications included. A notification from a kit selects only that kit, so a declared upstream's own failures do not block it, but the daily reconciliation stays red until the declaration is repaired. To recover, fix the upstream (make its gate pass, or grant the token read access) or correct the declaration and the `.gitmodules` branch, then rerun `Sync fleet submodules`. If the upstream should no longer be followed, remove its entry from `sources`; remove the submodule as well if the consumer no longer needs it.

GitHub Actions minutes on private repositories are billed to their owner. The gate,
the notify workflow and each consumer's sync job all count.

## Verification and recovery

The source gate is `pii-guard.yml` for fleet-guards and `style.yml` for fleet-style, and the declared workflow for a custom upstream. Only a successful `push` run for the current commit of the tracked branch (`main` for the kits) qualifies. The current commit is read from the repository's branch endpoint, which resolves only a branch, so a tag or commit spelled like the branch cannot stand in for it; an answer that names another branch (a renamed branch redirects) stops the run. A failed or still-running latest attempt does not borrow a previous run's success. Notifications for older commits become no-ops, and git ancestry checks prevent rollback.

Consumer runs are serialized. A daily schedule reconciles every installed kit and declared upstream,
covering missed or coalesced notifications. Public scheduled workflows may be
disabled by GitHub after prolonged repository inactivity; dispatch and manual runs
remain the primary triggers. Repeated runs at the same pins make no commit.

If a concurrent push changes the consumer branch, the normal non-fast-forward
rejection preserves that work. Rerun the workflow to reconcile from the new head.
If upstream CI fails, fix the upstream first. If the consumer's commit gate fails,
repair that finding before rerunning. If its post-push CI fails, the failed run is
visible in the consumer; the automation does not silently roll back or claim that
the consumer's application tests passed.

Use the source's `Notify fleet consumers` workflow for a full redispatch after
repairing credentials or subscriptions. For one consumer, run `Sync fleet submodules`.
To opt out, disable that workflow and remove its entries from the upstream secrets.
Rotate an expired token in every secret that uses it. Remove credentials when
decommissioning the automation.
