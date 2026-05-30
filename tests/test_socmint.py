"""Tests for the SOCMINT pipeline — consent gate + seed routing."""

from __future__ import annotations

import pytest

from src.pipelines.socmint import (
    SocmintPipeline,
    ConsentError,
    classify_seed,
    derive_usernames,
)


def test_consent_required():
    pipe = SocmintPipeline()
    with pytest.raises(ConsentError):
        pipe.run("johndoe", consent_confirmed=False)


def test_consent_required_by_default():
    pipe = SocmintPipeline()
    with pytest.raises(ConsentError):
        pipe.run("johndoe")


def test_classify_seed():
    assert classify_seed("john.doe@example.com") == "email"
    assert classify_seed("John Doe") == "name"
    assert classify_seed("johndoe") == "username"
    # bare token with no space and no @ is a username
    assert classify_seed("j_doe99") == "username"


def test_derive_usernames_from_email():
    assert derive_usernames("jdoe@example.com", "email") == ["jdoe"]


def test_derive_usernames_from_name():
    names = derive_usernames("John Doe", "name")
    assert "johndoe" in names
    assert "john.doe" in names
    assert "jdoe" in names  # first-initial + last
    # no duplicates
    assert len(names) == len(set(names))


def test_derive_usernames_from_username_passthrough():
    assert derive_usernames("nullbyte", "username") == ["nullbyte"]


def test_dry_run_no_consent_needed():
    """dry_run previews tools without running — no consent required."""
    pipe = SocmintPipeline()
    info = pipe.dry_run(["jdoe@example.com"])
    names = [i["name"] for i in info]
    assert "sherlock" in names
    assert "maigret" in names
    assert "holehe" in names


def test_dry_run_holehe_optional_for_nonemail():
    """holehe is optional when the seed is not an email."""
    pipe = SocmintPipeline()
    info = pipe.dry_run(["johndoe"])  # username seed
    holehe = next(i for i in info if i["name"] == "holehe")
    assert holehe.get("optional") is True
