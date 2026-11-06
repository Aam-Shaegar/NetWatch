"""Deterministic split assignment of complete independent capture groups."""
import random

def split_groups(records: list[dict], seed: int = 42) -> dict[str,list[dict]]:
    groups={}
    hashes={}
    for record in records:
        group=record['group_id']
        digest=record['sha256']
        if digest in hashes and hashes[digest]!=group:
            raise ValueError('identical captures assigned to different independent groups')
        hashes[digest]=group
        groups.setdefault(group,[]).append(record)
    keys=sorted(groups)
    if len(keys)<10:
        raise ValueError('at least 10 independent groups required for this initial split policy')
    random.Random(seed).shuffle(keys)
    n=len(keys); counts=[n*6//10,n//10,n//10]; counts.append(n-sum(counts))
    result={}; offset=0
    for name,count in zip(['train','validation','calibration','test'],counts):
        result[name]=[r for k in keys[offset:offset+count] for r in groups[k]]
        offset+=count
    return result
