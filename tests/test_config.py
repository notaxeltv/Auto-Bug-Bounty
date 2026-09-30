"""Test per autobb.config.Target.ensure_authorized."""

from __future__ import annotations

import pytest

from autobb.config import Target, UnauthorizedTargetError


def test_ensure_authorized_raises_when_not_authorized():
    target = Target(name="unauth-target", domains=["example.com"], authorized=False)

    with pytest.raises(UnauthorizedTargetError):
        target.ensure_authorized()


def test_ensure_authorized_does_not_raise_when_authorized():
    target = Target(name="auth-target", domains=["example.com"], authorized=True)

    # Non deve lanciare alcuna eccezione.
    target.ensure_authorized()
