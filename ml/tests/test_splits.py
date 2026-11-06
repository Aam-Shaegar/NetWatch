import pytest
from netwatch_ml.data.splits import split_groups

def records():return [{'group_id':f'run-{i}','sha256':f'hash-{i}'} for i in range(20)]
def test_groups_never_cross_splits():
    rows=records()+[dict(records()[0])]
    result=split_groups(rows)
    seen=set()
    for part in result.values():
        groups={r['group_id'] for r in part}
        assert not groups&seen
        seen|=groups
    assert len(seen)==20
    assert result==split_groups(rows)
def test_duplicate_capture_cannot_leak():
    rows=records();rows[1]['sha256']=rows[0]['sha256']
    with pytest.raises(ValueError):split_groups(rows)
def test_tiny_dataset_not_silently_split():
    with pytest.raises(ValueError):split_groups(records()[:3])
