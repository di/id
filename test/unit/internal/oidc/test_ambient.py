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

import pretend
import pytest
from requests import HTTPError

from id import DEFAULT_TIMEOUT, detect_credential
from id._internal.oidc import ambient


def test_detect_credential_none(monkeypatch):
    detect_none = pretend.call_recorder(lambda audience, timeout: None)
    monkeypatch.setattr(ambient, "detect_github", detect_none)
    monkeypatch.setattr(ambient, "detect_gcp", detect_none)
    assert detect_credential("some-audience") is None


def test_detect_credential(monkeypatch):
    detect_github = pretend.call_recorder(lambda audience, timeout: "fakejwt")
    monkeypatch.setattr(ambient, "detect_github", detect_github)

    assert detect_credential("some-audience") == "fakejwt"


def test_detect_credential_timeout(monkeypatch):
    # Check that we forward the timeout to each credential detector.
    detect_github = pretend.call_recorder(lambda audience, timeout: None)
    detect_gcp = pretend.call_recorder(lambda audience, timeout: None)

    monkeypatch.setattr(ambient, "detect_github", detect_github)
    monkeypatch.setattr(ambient, "detect_gcp", detect_gcp)

    assert detect_credential("some-audience", 0.1) is None
    assert detect_github.calls == [pretend.call("some-audience", 0.1)]
    assert detect_gcp.calls == [pretend.call("some-audience", 0.1)]


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

    resp = pretend.stub(raise_for_status=pretend.raiser(HTTPError), status_code=999)
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GitHub: OIDC token request failed \(code=999\)",
    ):
        ambient.detect_github("some-audience")
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "some-audience"},
            headers={"Authorization": "bearer faketoken"},
            timeout=DEFAULT_TIMEOUT,
        )
    ]


def test_detect_github_bad_payload(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(
        raise_for_status=lambda: None, json=pretend.call_recorder(lambda: {})
    )
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
            timeout=DEFAULT_TIMEOUT,
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
            timeout=DEFAULT_TIMEOUT,
        )
    ]
    assert resp.json.calls == [pretend.call()]


def test_detect_github_timeout(monkeypatch):
    # Check that the configured timeout is used for all `requests` calls.
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(
        raise_for_status=lambda: None,
        json=pretend.call_recorder(lambda: {"value": "fakejwt"}),
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    assert ambient.detect_github("some-audience", 0.1) == "fakejwt"
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "some-audience"},
            headers={"Authorization": "bearer faketoken"},
            timeout=0.1,
        )
    ]
    assert resp.json.calls == [pretend.call()]


def test_gcp_impersonation_access_token_request_fail(monkeypatch):
    monkeypatch.setenv(
        "GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com"
    )

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    resp = pretend.stub(raise_for_status=pretend.raiser(HTTPError), status_code=999)
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: access token request failed \(code=999\)",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
    ]


def test_gcp_impersonation_access_token_missing(monkeypatch):
    monkeypatch.setenv(
        "GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com"
    )

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
    monkeypatch.setenv(
        "GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com"
    )

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    access_token = pretend.stub()
    get_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"access_token": access_token}
    )
    post_resp = pretend.stub(
        raise_for_status=pretend.raiser(HTTPError), status_code=999
    )
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: get_resp),
        post=pretend.call_recorder(lambda url, **kw: post_resp),
        HTTPError=HTTPError,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token request failed \(code=999\)",
    ):
        ambient.detect_gcp("some-audience")

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
        pretend.call("GCP: requesting OIDC token"),
    ]


def test_gcp_impersonation_identity_token_missing(monkeypatch):
    monkeypatch.setenv(
        "GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com"
    )

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
    monkeypatch.setenv(
        "GOOGLE_SERVICE_ACCOUNT_NAME", "identity@project.iam.gserviceaccount.com"
    )

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    access_token = pretend.stub()
    oidc_token = pretend.stub()
    get_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"access_token": access_token}
    )
    post_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"token": oidc_token}
    )
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


def test_gcp_impersonation_timeout(monkeypatch):
    # Check that the configured timeout is used for all `requests` calls.
    service_account_name = "identity@project.iam.gserviceaccount.com"
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_NAME", service_account_name)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    access_token = pretend.stub()
    oidc_token = pretend.stub()
    get_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"access_token": access_token}
    )
    post_resp = pretend.stub(
        raise_for_status=lambda: None, json=lambda: {"token": oidc_token}
    )
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: get_resp),
        post=pretend.call_recorder(lambda url, **kw: post_resp),
        HTTPError=HTTPError,
    )
    monkeypatch.setattr(ambient, "requests", requests)

    assert ambient.detect_gcp("some-audience", 0.1) == oidc_token
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: GOOGLE_SERVICE_ACCOUNT_NAME set; attempting impersonation"),
        pretend.call("GCP: requesting access token"),
        pretend.call("GCP: requesting OIDC token"),
        pretend.call("GCP: successfully requested OIDC token"),
    ]
    assert requests.get.calls == [
        pretend.call(
            ambient._GCP_TOKEN_REQUEST_URL,
            params={"scopes": "https://www.googleapis.com/auth/cloud-platform"},
            headers={"Metadata-Flavor": "Google"},
            timeout=0.1,
        )
    ]
    assert requests.post.calls == [
        pretend.call(
            ambient._GCP_GENERATEIDTOKEN_REQUEST_URL.format(service_account_name),
            json={"audience": "some-audience", "includeEmail": True},
            headers={
                "Authorization": f"Bearer {access_token}",
            },
            timeout=0.1,
        )
    ]


def test_gcp_bad_env(monkeypatch):
    oserror = pretend.raiser(OSError)
    monkeypatch.setitem(ambient.__builtins__, "open", oserror)  # type: ignore

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_gcp("some-audience") is None
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call(
            "GCP: GOOGLE_SERVICE_ACCOUNT_NAME not set; skipping impersonation"
        ),
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
        pretend.call(
            "GCP: GOOGLE_SERVICE_ACCOUNT_NAME not set; skipping impersonation"
        ),
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

    resp = pretend.stub(raise_for_status=pretend.raiser(HTTPError), status_code=999)
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token request failed \(code=999\)",
    ):
        ambient.detect_gcp("some-audience")
    assert requests.get.calls == [
        pretend.call(
            ambient._GCP_IDENTITY_REQUEST_URL,
            params={"audience": "some-audience", "format": "full"},
            headers={"Metadata-Flavor": "Google"},
            timeout=DEFAULT_TIMEOUT,
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
            timeout=DEFAULT_TIMEOUT,
        )
    ]
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call(
            "GCP: GOOGLE_SERVICE_ACCOUNT_NAME not set; skipping impersonation"
        ),
        pretend.call("GCP: requesting OIDC token"),
        pretend.call("GCP: successfully requested OIDC token"),
    ]


def test_detect_gcp_timeout(monkeypatch):
    # Check that the configured timeout is used for all `requests` calls.
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: "Google"),
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

    assert ambient.detect_gcp("some-audience", 0.1) == "fakejwt"
    assert requests.get.calls == [
        pretend.call(
            ambient._GCP_IDENTITY_REQUEST_URL,
            params={"audience": "some-audience", "format": "full"},
            headers={"Metadata-Flavor": "Google"},
            timeout=0.1,
        )
    ]
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call(
            "GCP: GOOGLE_SERVICE_ACCOUNT_NAME not set; skipping impersonation"
        ),
        pretend.call("GCP: requesting OIDC token"),
        pretend.call("GCP: successfully requested OIDC token"),
    ]
