# Release Checklist

## Pre-release

- [ ] `gofmt -w ./cmd ./pkg`
- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `./scripts/validate-action.sh`
- [ ] Verify README examples still match CLI flags and action inputs
- [ ] Verify `action.yml` references current recommended tag in README snippets

## Version + tag

- [ ] Decide version bump (`vMAJOR.MINOR.PATCH`)
- [ ] Update README status release value
- [ ] Commit release-ready changes
- [ ] `git tag <version>`
- [ ] `git push origin main --tags`

## GitHub release

- [ ] `gh release create <version> --repo agent19710101/shell-sentinel --generate-notes`
- [ ] Sanity check release notes for private/internal data leakage
- [ ] Confirm release page links/examples use current version
