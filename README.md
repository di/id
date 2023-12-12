id
==

<!--- @begin-badges@ --->
![CI](https://github.com/di/id/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/id.svg)](https://pypi.org/project/id)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/di/id/badge)](https://api.securityscorecards.dev/projects/github.com/di/id)
[![SLSA](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/)
<!--- @end-badges@ --->

`id` is a Python tool for generating OIDC identities. It can automatically
detect and produce OIDC credentials on a number of environments, including
GitHub Actions, GitLab pipelines and Google Cloud.

## Installation

`id` requires Python 3.8 or newer, and can be installed directly via `pip`:

```console
python -m pip install id
```

## Usage

You can run `id` as a Python module via `python -m`:

```console
python -m id --help
```

Top-level:

<!-- @begin-id-help@ -->
```
usage: id [-h] [-V] [-v] audience

a tool for generating OIDC identities

positional arguments:
  audience       the OIDC audience to use

optional arguments:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit
  -v, --verbose  run with additional debug logging; supply multiple times to
                 increase verbosity (default: 0)
```
<!-- @end-id-help@ -->

For Python API usage, there is a single importable function, `detect_credential`:

```pycon
>>> from id import detect_credential
>>> detect_credential(audience='something')
'<OIDC token>'
```

This function requires an `audience` parameter, which is used when generating
the OIDC token. This should be set to the intended audience for the token.

If no supported environment is found, `detect_credential` returns `None`. If a supported
environment is found but `detect_credential` fails to retrieve a token, it raises
`AmbientCredentialError`.

## Supported environments

`id` currently supports ambient credential detection in the following environments:

* [GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
* Google Cloud
  * [Cloud Run](https://cloud.google.com/run/docs/securing/service-identity)
  * [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
  * [Compute Engine](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances)
  * and more
* [Buildkite](https://buildkite.com/docs/agent/v3/cli-oidc)
* [GitLab](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html) (See _environment variables_ below)
* [CircleCI](https://circleci.com/docs/oidc-tokens-with-custom-claims/)

### Tokens in environment variables

GitLab provides OIDC tokens through environment variables. The variable name must be
`<AUD>_ID_TOKEN`  where `<AUD>` is the uppercased audience argument where all
characters outside of ASCII letters and digits are replaced with "\_". A leading digit
must also be replaced with a "\_".

## Licensing

`id` is licensed under the Apache 2.0 License.

## Contributing

See [the contributing docs](https://github.com/di/id/blob/main/CONTRIBUTING.md) for details.

### SLSA Provenance
This project emits a SLSA provenance on its release! This enables you to verify the integrity
of the downloaded artifacts and ensured that the binary's code really comes from this source code.

To do so, please follow the instructions [here](https://github.com/slsa-framework/slsa-github-generator#verification-of-provenance).
