import os

import pytest

from etipitaka_mcp import canon_registry as reg


def test_edition_for_ios_and_android():
    assert reg.edition_for('ios', 1) == 'thai'
    assert reg.edition_for('ios', 6) == 'thaiwn'
    assert reg.edition_for('android', 0) == 'thai'


def test_edition_for_unknown_platform_or_code():
    with pytest.raises(reg.RegistryError):
        reg.edition_for('pc', 1)
    with pytest.raises(reg.RegistryError):
        reg.edition_for('ios', 999)


def test_edition_path_missing_file(tmp_path):
    with pytest.raises(reg.RegistryError):
        reg.edition_path(str(tmp_path), 'thai')


def test_edition_path_present(tmp_path):
    (tmp_path / 'thai.sqlite').write_text('x')
    assert reg.edition_path(str(tmp_path), 'thai').endswith('thai.sqlite')


def test_dictionary_metadata():
    assert reg.DICTIONARIES['pali_thai']['table'] == 'p2t'
    assert reg.DICTIONARIES['pali_thai']['head'] == 'headword'
    assert reg.DICTIONARIES['thai']['head'] == 'head'


@pytest.mark.skipif(
    not os.path.exists(
        '/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/constants.py'),
    reason='PC app constants.py not present')
def test_code_tables_match_pc_app():
    import importlib.util
    path = '/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/constants.py'
    spec = importlib.util.spec_from_file_location('pc_constants', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert reg.IOS_CODE_TABLE == mod.IOS_CODE_TABLE
    assert reg.ANDROID_CODE_TABLE == mod.ANDROID_CODE_TABLE
    assert set(reg.EDITIONS) >= set(mod.CODES)
