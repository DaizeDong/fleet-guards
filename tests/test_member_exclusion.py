"""The shared native primitive excludes writes through any member hard link."""
import os
import pytest
from fleet_guards import filesystem as fs


@pytest.mark.skipif(os.name != 'nt', reason='Windows native handle contract')
def test_group_exclusion_holds_write_delete_and_allows_read(tmp_path):
    member = tmp_path / 'member'
    member.write_bytes(b'Synthetic member')
    alias = tmp_path / 'alias'
    os.link(member, alias)
    with fs.exclude_file_writes([member]) as opened:
        assert opened[member] == fs.identity(member)
        assert fs.read_bounded(member, 100) == b'Synthetic member'
        for path in (member, alias):
            with pytest.raises(OSError):
                path.write_bytes(b'edit')
        with pytest.raises(OSError):
            member.unlink()
        # NTFS may remove a different hard-link name without deleting the pinned
        # member. Writes through that alias still conflict with the held handle.
        assert member.exists()
    member.write_bytes(b'accepted after release')
    assert alias.read_bytes() == b'accepted after release'


@pytest.mark.skipif(os.name != 'nt', reason='Windows native handle contract')
def test_identity_delete_preserves_equal_byte_foreign_file(tmp_path):
    path = tmp_path / 'member'
    path.write_bytes(b'Synthetic')
    owned = fs.identity(path)
    path.rename(tmp_path / 'original')
    path.write_bytes(b'Synthetic')
    assert not fs.delete_if_identity_matches(path, owned)
    assert path.read_bytes() == b'Synthetic'
    assert fs.delete_if_identity_matches(path, fs.identity(path))
    assert not path.exists()
