# Releasing ldapgate

1. Bump the version in `pyproject.toml`, `ldapgate/__init__.py`, and `uv.lock` in a pull request, and merge it.
2. Run the **Release** workflow from `main` with `publish` enabled.
3. The workflow runs the tests and lint, checks the lockfile, builds the wheel and source distribution, smoke-tests the wheel, publishes to PyPI through trusted publishing, then creates the `v<version>` tag and GitHub Release.
4. To preview, run with `publish` off. The distributions are kept as the `ldapgate-dist` artifact. Nothing is tagged or published.

## PyPI trusted publishing

The `pypi-publish` job uses OIDC. Configure the publisher on PyPI with:

- Owner: `anudeepd`
- Repository: `ldapgate`
- Workflow name: `release.yml`
- Environment: `pypi`

Create the `pypi` environment in the GitHub repository settings if it does not exist. No PyPI API token is stored in GitHub Actions.
