"""ZenShield release ordering that retains a compatible bridge offer.

Used by the Zentryc OTA service. Other product channels keep their own policy.
"""
import re

def newest_compatible_release(releases, current_version):
    def version(value):
        if not isinstance(value,str) or not re.fullmatch(r'\d+\.\d+\.\d+',value):
            return None
        return tuple(map(int,value.split('.')))
    current=version(current_version)
    if current is None:return None
    candidates=[]
    for release in releases:
        target=version(release.version)
        minimum=version(release.min_version) if release.min_version else (0,0,0)
        if target is not None and minimum is not None and minimum<=current<target:
            candidates.append((target,release))
    return max(candidates,key=lambda item:item[0])[1] if candidates else None
