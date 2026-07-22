# 9/10 Execution Backlog

This page is the tracked entry point for Evydence's 9/10 production and open
source execution programme. It is implementation tracking, not a production claim,
release criterion, or evidence of external completion.

The ticket record is maintained in
[`.EVYDENCE_CODEX_BACKLOG.md`](../../.EVYDENCE_CODEX_BACKLOG.md). Ticket
status is trustworthy only when its completion evidence names the checks that
ran and the repository tracking record identifies the resulting commit.

## Issue Tracking

Create an issue only after checking that its ticket ID is not already present:

```sh
gh issue list --repo aatuh/evydence --state all --search 'EVY-101 in:title'
```

Use the [backlog ticket template](../../.github/ISSUE_TEMPLATE/backlog-ticket.md)
and labels from [Issue labels](issue-labels.md). The issue must contain the
ticket ID, dependencies, acceptance criteria, validation plan, compatibility
impact, and completion evidence. Creating an issue never marks a backlog ticket
complete.

Repository settings, release publication, independent review, and design
partner evidence remain maintainer or external-owner work. Record their proof
in the issue and leave the ticket incomplete until that proof is available.
