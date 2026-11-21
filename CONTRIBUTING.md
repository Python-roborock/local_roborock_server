# Contributing

If you would like to contribute there are a few ways that would be great!

1. Code is always welcome that you have fully tested.
2. Video walkthroughs of how to actually set this up would be great.
3. Documentation. Human-written documentation always 'feels' better than what AI produces.

## Where does my report go?

Choose the form that matches your contribution:

- **Found a bug?** → Open an [Issue](https://github.com/Python-roborock/local_roborock_server/issues/new/choose).
  Use the bug report form for a problem you need help investigating.
- **Confirming (or ruling out) that the server runs on your vacuum?** → Open a
  [compatibility report](https://github.com/Python-roborock/local_roborock_server/issues/new?template=compatibility.yml).
  Include your exact model, firmware, server version, certificate issuer, and what worked or failed.
  Mention any workarounds needed for the result.
- **Have a confirmed, reproducible result to record?** → Open a pull request adding a row to
  [Tested Vacuums.md](/docs/tested_vacuums.md) so the next person can find it quickly.

Feature ideas are welcome as Issues too — use the feature request form.

## Opening a pull request

When you open a PR, the template will ask you to:

1. **Show proof that it works.** Logs, test output, a video, or a clear description of what you ran on your vacuum and what happened.
2. **Include screenshots for any UI change**, ideally before and after.

Optional, but very helpful given how many PRs come in:

3. **Check for duplicates first.** Search open PRs and issues so we don't end up with two versions of the same fix.
4. **Review 1–2 other open PRs.** Try them on your own vacuum and comment with what you tested and whether it worked. Every vacuum and firmware is a little different, so testing on more devices helps everyone.
