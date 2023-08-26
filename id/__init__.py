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

"""
API for retrieving OIDC tokens.
"""

from __future__ import annotations

from typing import Callable, List, Optional

__version__ = "1.1.0"


class IdentityError(Exception):
    """
    Raised on any OIDC token format or claim error.
    """

    pass


class AmbientCredentialError(IdentityError):
    """
    Raised when an ambient credential should be present, but
    can't be retrieved (e.g. network failure).
    """

    pass


class GitHubOidcPermissionCredentialError(AmbientCredentialError):
    """
    Raised when the current GitHub Actions environment doesn't have permission
    to retrieve an OIDC token.
    """

    pass


def detect_credential(audience: str) -> Optional[str]:
    """
    Try each ambient credential detector, returning the first one to succeed
    or `None` if all fail.

    Raises `AmbientCredentialError` if any detector fails internally (i.e.
    detects a credential, but cannot retrieve it).
    """
    from ._internal.oidc.ambient import (
        detect_buildkite,
        detect_gcp,
        detect_github,
    )

    detectors: List[Callable[..., Optional[str]]] = [
        detect_github,
        detect_gcp,
        detect_buildkite,
    ]
    for detector in detectors:
        credential = detector(audience)
        if credential is not None:
            return credential
    return None
