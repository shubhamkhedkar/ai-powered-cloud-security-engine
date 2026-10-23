"""Pluggable check registry. Decorate a function with @check to register it.

A check receives (session, region) and yields Finding objects.
Global checks (IAM, S3) run once; regional checks run per region.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from cloudsec.models import Finding


@dataclass
class Check:
    id: str
    service: str
    func: Callable[..., Iterable[Finding]]
    regional: bool


REGISTRY: list[Check] = []


def check(id: str, service: str, regional: bool = True):
    def deco(fn):
        REGISTRY.append(Check(id, service, fn, regional))
        return fn

    return deco


def load_all() -> list[Check]:
    from cloudsec.checks import compute, iam, logging_checks, s3, storage  # noqa: F401

    return REGISTRY
