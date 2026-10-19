"""Finite observation contract, independent of the broker and its error codes.

This is a sequential abstract machine, not a language interpreter or formal proof.
Its phases are externally controlled fixture barriers, not production API calls.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Observation:
    delivered: bool = False
    dispatches: int = 0
    quota: int = 0
    uncertain: bool = False


def predict(write, approved, available, phase, change):
    authority = {'session': True, 'grant': True, 'version': True,
                 'plan_time': True, 'grant_time': True, 'audit': True}
    def at(barrier):
        if phase == barrier and change != 'none':
            authority[{'replace': 'grant', 'revoke': 'grant', 'reissue': 'grant'}.get(change, change)] = False
    def current(include_plan=False):
        return all(authority[key] for key in
                   ('session', 'grant', 'version', 'grant_time') + (('plan_time',) if include_plan else ()))

    at('before')
    # Nonces, grant identity/expiry and session are checked at redemption.
    if not all(authority[k] for k in ('session', 'grant', 'grant_time', 'plan_time')):
        return Observation()
    if write:
        at('approval')
        if not approved:
            return Observation()
    if not current(include_plan=True) or not available:
        return Observation()
    # A reservation is an attempt, including later failures before sending.
    if write:
        at('intent')
        if not authority['audit']:
            return Observation(quota=1)
    if not current(include_plan=True):
        return Observation(quota=1)
    at('upstream')
    if not current():
        return Observation(dispatches=1, quota=1, uncertain=write)
    at('outcome')
    if (write and not authority['audit']) or not current():
        return Observation(dispatches=1, quota=1, uncertain=write)
    # Read audit is best effort; its failure does not authorize or revoke access.
    return Observation(True, 1, 1)
