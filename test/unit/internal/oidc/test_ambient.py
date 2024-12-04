# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

import pretend
import pytest
from requests import HTTPError, Timeout

from id import detect_credential
from id._internal.oidc import ambient


def test_detect_credential_none(monkeypatch):
    detect_none = pretend.call_recorder(lambda audience: None)
    monkeypatch.setattr(ambient, "detect_github", detect_none)
    monkeypatch.setattr(ambient, "detect_gcp", detect_none)
    monkeypatch.setattr(ambient, "detect_buildkite", detect_none)
    assert detect_credential("some-audience") is None


def test_detect_credential(monkeypatch):
    detect_github = pretend.call_recorder(lambda audience: "fakejwt")
    monkeypatch.setattr(ambient, "detect_github", detect_github)

    assert detect_credential("some-audience") == "fakejwt"


def test_detect_github_bad_env(monkeypatch):
    # We might actually be running in a CI, so explicitly remove this.
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_github("some-audience") is None
    assert logger.debug.calls == [
        pretend.call("GitHub: looking for OIDC credentials"),
        pretend.call("GitHub: environment doesn't look like a GH action; giving up"),
    ]


def test_detect_github_bad_request_token(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GitHub: missing or insufficient OIDC token permissions?",
    ):
        ambient.detect_github("some-audience")
    assert logger.debug.calls == [
        pretend.call("GitHub: looking for OIDC credentials"),
    ]


def test_detect_github_bad_request_url(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GitHub: missing or insufficient OIDC token permissions?",
    ):
        ambient.detect_github("some-audience")
    assert logger.debug.calls == [
        pretend.call("GitHub: looking for OIDC credentials"),
    ]


def test_detect_github_request_fails(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(
        raise_for_status=pretend.raiser(HTTPError),
        status_code=999,
        content=b"something",
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError)
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GitHub: OIDC token request failed \(code=999, body='something'\)",
    ):
        ambient.detect_github("some-audience")
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "some-audience"},
            headers={"Authorization": "bearer faketoken"},
            timeout=30,
        )
    ]


def test_detect_github_request_timeout(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(raise_for_status=pretend.raiser(Timeout))
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp),
        HTTPError=HTTPError,
        Timeout=Timeout,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GitHub: OIDC token request timed out",
    ):
        ambient.detect_github("some-audience")
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "some-audience"},
            headers={"Authorization": "bearer faketoken"},
            timeout=30,
        )
    ]


def test_detect_github_invalid_json_payload(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(raise_for_status=lambda: None, json=pretend.raiser(json.JSONDecodeError))
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GitHub: malformed or incomplete JSON",
    ):
        ambient.detect_github("some-audience")
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "some-audience"},
            headers={"Authorization": "bearer faketoken"},
            timeout=30,
        )
    ]


@pytest.mark.parametrize("payload", [{}, {"notvalue": None}, {"value": None}, {"value": 1234}])
def test_detect_github_bad_payload(monkeypatch, payload):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(raise_for_status=lambda: None, json=pretend.call_recorder(lambda: payload))
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GitHub: malformed or incomplete JSON",
    ):
        ambient.detect_github("some-audience")
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "some-audience"},
            headers={"Authorization": "bearer faketoken"},
            timeout=30,
        )
    ]
    assert resp.json.calls == [pretend.call()]


def test_detect_github(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(
        raise_for_status=lambda: None,
        json=pretend.call_recorder(lambda: {"value": "fakejwt"}),
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    assert ambient.detect_github("some-audience") == "fakejwt"
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "some-audience"},
            headers={"Authorization": "bearer faketoken"},
            timeout=30,
        )
    ]
    assert resp.json.calls == [pretend.call()]


def test_gcp_impersonation_access_token_request_fail(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    resp = pretend.stub(
        raise_for_status=pretend.raiser(HTTPError),
        status_code=999,
        content=b"something",
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError)
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: access token request failed \(code=999, body='something'\)",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
    ]


def test_gcp_impersonation_access_token_request_timeout(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    resp = pretend.stub(raise_for_status=pretend.raiser(Timeout))
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp),
        HTTPError=HTTPError,
        Timeout=Timeout,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: access token request timed out",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
    ]


def test_gcp_impersonation_access_token_missing(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    resp = pretend.stub(raise_for_status=lambda: None, json=lambda: {})
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: access token missing from response",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
    ]


def test_gcp_impersonation_identity_token_request_fail(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    access_token = pretend.stub()
    get_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"access_token": access_token}
    )
    post_resp = pretend.stub(
        raise_for_status=pretend.raiser(HTTPError),
        status_code=999,
        content=b"something",
    )
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: get_resp),
        post=pretend.call_recorder(lambda url, **kw: post_resp),
        HTTPError=HTTPError,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token request failed \(code=999, body='something'\)",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
        pretend.call("GCP: requesting OIDC token"),
    ]


def test_gcp_impersonation_identity_token_request_timeout(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    access_token = pretend.stub()
    get_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"access_token": access_token}
    )
    post_resp = pretend.stub(raise_for_status=pretend.raiser(Timeout))
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: get_resp),
        post=pretend.call_recorder(lambda url, **kw: post_resp),
        HTTPError=HTTPError,
        Timeout=Timeout,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token request timed out",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
        pretend.call("GCP: requesting OIDC token"),
    ]


def test_gcp_impersonation_identity_token_missing(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    access_token = pretend.stub()
    get_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"access_token": access_token}
    )
    post_resp = pretend.stub(raise_for_status=lambda: None, json=lambda: {})
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: get_resp),
        post=pretend.call_recorder(lambda url, **kw: post_resp),
        HTTPError=HTTPError,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token missing from response",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
        pretend.call("GCP: requesting OIDC token"),
    ]


def test_gcp_impersonation_succeeds(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    access_token = pretend.stub()
    oidc_token = pretend.stub()
    get_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"access_token": access_token}
    )
    post_resp = pretend.stub(raise_for_status=lambda: None, json=lambda: {"token": oidc_token})
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: get_resp),
        post=pretend.call_recorder(lambda url, **kw: post_resp),
        HTTPError=HTTPError,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    assert ambient.detect_gcp("some-audience") == oidc_token

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
        pretend.call("GCP: requesting OIDC token"),
        pretend.call("GCP: successfully requested OIDC token"),
    ]


def test_gcp_bad_env(monkeypatch):
    oserror = pretend.raiser(OSError)
    monkeypatch.setitem(ambient.__builtins__, "open", oserror)  # type: ignore

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_gcp("some-audience") is None
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME not set; skipping impersonation"),
        pretend.call("GCP: environment doesn't have GCP product name file; giving up"),
    ]


def test_gcp_wrong_product(monkeypatch):
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: "Unsupported Product"),
        __exit__=lambda *a: None,
    )
    monkeypatch.setitem(ambient.__builtins__, "open", lambda fn: stub_file)  # type: ignore

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_gcp("some-audience") is None

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME not set; skipping impersonation"),
        pretend.call(
            "GCP: product name file exists, but product name is 'Unsupported Product'; giving up"
        ),
    ]


def test_detect_gcp_request_fails(monkeypatch):
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: "Google"),
        __exit__=lambda *a: None,
    )
    monkeypatch.setitem(ambient.__builtins__, "open", lambda fn: stub_file)  # type: ignore

    resp = pretend.stub(
        raise_for_status=pretend.raiser(HTTPError),
        status_code=999,
        content=b"something",
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError)
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token request failed \(code=999, body='something'\)",
    ):
        ambient.detect_gcp("some-audience")
    assert requests.get.calls == [
        pretend.call(
            ambient._GCP_IDENTITY_REQUEST_URL,
            params={"audience": "some-audience", "format": "full"},
            headers={"Metadata-Flavor": "Google"},
            timeout=30,
        )
    ]


def test_detect_gcp_request_timeout(monkeypatch):
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: "Google"),
        __exit__=lambda *a: None,
    )
    monkeypatch.setitem(ambient.__builtins__, "open", lambda fn: stub_file)  # type: ignore

    resp = pretend.stub(raise_for_status=pretend.raiser(Timeout))
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp),
        HTTPError=HTTPError,
        Timeout=Timeout,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token request timed out",
    ):
        ambient.detect_gcp("some-audience")
    assert requests.get.calls == [
        pretend.call(
            ambient._GCP_IDENTITY_REQUEST_URL,
            params={"audience": "some-audience", "format": "full"},
            headers={"Metadata-Flavor": "Google"},
            timeout=30,
        )
    ]


@pytest.mark.parametrize("product_name", ("Google", "Google Compute Engine"))
def test_detect_gcp(monkeypatch, product_name):
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: product_name),
        __exit__=lambda *a: None,
    )
    monkeypatch.setitem(ambient.__builtins__, "open", lambda fn: stub_file)  # type: ignore

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    resp = pretend.stub(
        raise_for_status=lambda: None,
        text="fakejwt",
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    assert ambient.detect_gcp("some-audience") == "fakejwt"
    assert requests.get.calls == [
        pretend.call(
            ambient._GCP_IDENTITY_REQUEST_URL,
            params={"audience": "some-audience", "format": "full"},
            headers={"Metadata-Flavor": "Google"},
            timeout=30,
        )
    ]
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME not set; skipping impersonation"),
        pretend.call("GCP: requesting OIDC token"),
        pretend.call("GCP: successfully requested OIDC token"),
    ]


def test_buildkite_no_agent(monkeypatch):
    monkeypatch.setenv("BUILDKITE", "true")

    # Mock out the `which` call. We don't expect this to exist in the `PATH` but
    # just in case someone is running these tests on a Buildkite host...
    shutil = pretend.stub(which=pretend.call_recorder(lambda bin: None))
    monkeypatch.setattr(ambient, "shutil", shutil)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"Buildkite: could not find Buildkite agent in Buildkite environment",
    ):
        ambient.detect_buildkite("some-audience")

    assert shutil.which.calls == [pretend.call("buildkite-agent")]


def test_buildkite_agent_error(monkeypatch):
    monkeypatch.setenv("BUILDKITE", "true")

    # Mock out the `which` call to show that we have a `buildkite-agent` in our `PATH`.
    shutil = pretend.stub(which=pretend.call_recorder(lambda bin: "/usr/bin/buildkite-agent"))
    monkeypatch.setattr(ambient, "shutil", shutil)

    # Mock out `run` call to emulate getting a non-zero return code from the `buildkite-agent`.
    resp = pretend.stub(
        returncode=-1,
        stdout="mock error message",
    )
    subprocess = pretend.stub(run=pretend.call_recorder(lambda run_args, **kw: resp), PIPE=None)
    monkeypatch.setattr(ambient, "subprocess", subprocess)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"Buildkite: the Buildkite agent encountered an error: mock error message",
    ):
        ambient.detect_buildkite("some-audience")

    assert shutil.which.calls == [pretend.call("buildkite-agent")]
    assert subprocess.run.calls == [
        pretend.call(
            ["buildkite-agent", "oidc", "request-token", "--audience", "some-audience"],
            capture_output=True,
            text=True,
        )
    ]


def test_buildkite(monkeypatch):
    monkeypatch.setenv("BUILDKITE", "true")

    # Mock out the `which` call to show that we have a `buildkite-agent` in our `PATH`.
    shutil = pretend.stub(which=pretend.call_recorder(lambda bin: "/usr/bin/buildkite-agent"))
    monkeypatch.setattr(ambient, "shutil", shutil)

    # Mock out `run` call to emulate getting a successful return code from the `buildkite-agent`.
    resp = pretend.stub(
        returncode=0,
        stdout="fakejwt",
    )
    subprocess = pretend.stub(run=pretend.call_recorder(lambda run_args, **kw: resp), PIPE=None)
    monkeypatch.setattr(ambient, "subprocess", subprocess)

    assert ambient.detect_buildkite("some-audience") == "fakejwt"
    assert shutil.which.calls == [pretend.call("buildkite-agent")]
    assert subprocess.run.calls == [
        pretend.call(
            ["buildkite-agent", "oidc", "request-token", "--audience", "some-audience"],
            capture_output=True,
            text=True,
        )
    ]


def test_buildkite_bad_env(monkeypatch):
    monkeypatch.delenv("BUILDKITE", False)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_buildkite("some-audience") is None
    assert logger.debug.calls == [
        pretend.call("Buildkite: looking for OIDC credentials"),
        pretend.call("Buildkite: environment doesn't look like BuildKite; giving up"),
    ]


def test_gitlab_bad_env(monkeypatch):
    monkeypatch.delenv("GITLAB_CI", False)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_gitlab("some-audience") is None
    assert logger.debug.calls == [
        pretend.call("GitLab: looking for OIDC credentials"),
        pretend.call("GitLab: environment doesn't look like GitLab CI/CD; giving up"),
    ]


def test_gitlab_no_variable(monkeypatch):
    monkeypatch.setenv("GITLAB_CI", "true")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GitLab: Environment variable SOME_AUDIENCE_ID_TOKEN not found",
    ):
        ambient.detect_gitlab("some-audience")

    assert logger.debug.calls == [
        pretend.call("GitLab: looking for OIDC credentials"),
    ]


def test_gitlab(monkeypatch):
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("SOME_AUDIENCE_ID_TOKEN", "fakejwt")
    monkeypatch.setenv("_1_OTHER_AUDIENCE_ID_TOKEN", "fakejwt2")

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_gitlab("some-audience") == "fakejwt"
    assert ambient.detect_gitlab("11 other audience") == "fakejwt2"
    assert logger.debug.calls == [
        pretend.call("GitLab: looking for OIDC credentials"),
        pretend.call("GitLab: Found token in environment variable SOME_AUDIENCE_ID_TOKEN"),
        pretend.call("GitLab: looking for OIDC credentials"),
        pretend.call("GitLab: Found token in environment variable _1_OTHER_AUDIENCE_ID_TOKEN"),
    ]


def test_circleci_bad_env(monkeypatch):
    monkeypatch.delenv("CIRCLECI", False)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_circleci("some-audience") is None
    assert logger.debug.calls == [
        pretend.call("CircleCI: looking for OIDC credentials"),
        pretend.call("CircleCI: environment doesn't look like CircleCI; giving up"),
    ]


def test_circleci_no_circleci_cli(monkeypatch):
    monkeypatch.setenv("CIRCLECI", "true")

    # Mock out the `which` call. We don't expect this to exist in the `PATH` but
    # just in case someone is running these tests on a Buildkite host...
    shutil = pretend.stub(which=pretend.call_recorder(lambda bin: None))
    monkeypatch.setattr(ambient, "shutil", shutil)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"CircleCI: could not find `circleci` in the environment",
    ):
        ambient.detect_circleci("some-audience")

    assert shutil.which.calls == [pretend.call("circleci")]


def test_circleci_circlecli_error(monkeypatch):
    monkeypatch.setenv("CIRCLECI", "true")

    # Mock out the `which` call to show that we have a `circleci` in our `PATH`.
    shutil = pretend.stub(which=pretend.call_recorder(lambda bin: "/usr/bin/circleci"))
    monkeypatch.setattr(ambient, "shutil", shutil)

    # Mock out `run` call to emulate getting a non-zero return code from the `circleci`.
    resp = pretend.stub(
        returncode=-1,
        stdout="mock error message",
    )
    subprocess = pretend.stub(run=pretend.call_recorder(lambda run_args, **kw: resp), PIPE=None)
    monkeypatch.setattr(ambient, "subprocess", subprocess)
    payload = json.dumps({"aud": "some-audience"})

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"CircleCI: the `circleci` tool encountered an error: mock error message",
    ):
        ambient.detect_circleci("some-audience")

    assert shutil.which.calls == [pretend.call("circleci")]
    assert subprocess.run.calls == [
        pretend.call(
            ["circleci", "run", "oidc", "get", "--claims", payload],
            capture_output=True,
            text=True,
        )
    ]


def test_circleci(monkeypatch):
    monkeypatch.setenv("CIRCLECI", "true")

    # Mock out the `which` call to show that we have a `circleci` in our `PATH`.
    shutil = pretend.stub(which=pretend.call_recorder(lambda bin: "/usr/bin/circleci"))
    monkeypatch.setattr(ambient, "shutil", shutil)

    # Mock out `run` call to emulate getting a successful return code from the `circleci`.
    resp = pretend.stub(
        returncode=0,
        stdout="fakejwt",
    )
    subprocess = pretend.stub(run=pretend.call_recorder(lambda run_args, **kw: resp), PIPE=None)
    monkeypatch.setattr(ambient, "subprocess", subprocess)
    payload = json.dumps({"aud": "some-audience"})

    assert ambient.detect_circleci("some-audience") == "fakejwt"
    assert shutil.which.calls == [pretend.call("circleci")]
    assert subprocess.run.calls == [
        pretend.call(
            ["circleci", "run", "oidc", "get", "--claims", payload],
            capture_output=True,
            text=True,
        )
    ]
