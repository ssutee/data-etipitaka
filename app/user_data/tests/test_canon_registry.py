# -*- coding: utf-8 -*-
import os

import pytest

from user_data import canon_registry as reg


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


PC_CONSTANTS = '/Users/sutee/Works/watnapahpong/E-Tipitaka-PC/constants.py'


def _pc_literals(path, names):
    """Extract module-level literal assignments without importing the module.

    The PC app's constants.py imports wx (not installed here), so we parse it
    with ast and literal_eval only the assignments we need. This file is on the
    developer host, not in the container, so the test below is skipped in CI.
    """
    import ast
    with open(path, encoding='utf-8') as f:
        tree = ast.parse(f.read())
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names:
                    out[target.id] = ast.literal_eval(node.value)
    return out


@pytest.mark.skipif(not os.path.exists(PC_CONSTANTS),
                    reason='PC app constants.py not present (expected in container/CI)')
def test_code_tables_match_pc_app():
    vals = _pc_literals(PC_CONSTANTS,
                        {'IOS_CODE_TABLE', 'ANDROID_CODE_TABLE', 'CODES'})
    assert reg.IOS_CODE_TABLE == vals['IOS_CODE_TABLE']
    assert reg.ANDROID_CODE_TABLE == vals['ANDROID_CODE_TABLE']
    assert set(reg.EDITIONS) >= set(vals['CODES'])
