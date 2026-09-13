# -*- coding: utf-8 -*-
"""Canon edition / dictionary registry.

Maps edition keys and per-platform integer codes to the SQLite files that back
the public canon API. Values are copied from the E-Tipitaka-PC app's
constants.py (the *_DB constants, LANGS, and *_CODE_TABLE); that app is
intentionally NOT imported (it depends on wx).
"""
import os

# Edition key -> file + display name.
EDITIONS = {
    'thai':    {'filename': 'thai.sqlite',    'name': 'ไทย (ฉบับหลวง)'},
    'pali':    {'filename': 'pali.sqlite',    'name': 'บาลี (สยามรัฐ)'},
    'palinew': {'filename': 'palinew.sqlite', 'name': 'บาลี (สยามรัฐ ฉบับใหม่)'},
    'palimc':  {'filename': 'palimc.sqlite',  'name': 'บาลี (มหาจุฬาฯ)'},
    'thaimm':  {'filename': 'thaimm.sqlite',  'name': 'ไทย (มหามกุฏฯ)'},
    'thaimc':  {'filename': 'thaimc.sqlite',  'name': 'ไทย (มหาจุฬาฯ ๑)'},
    'thaimc2': {'filename': 'thaimc2.sqlite', 'name': 'ไทย (มหาจุฬาฯ ๒)'},
    'thaibt':  {'filename': 'thaibt.sqlite',  'name': 'พุทธวจน (ชุดจากพระโอษฐ์)'},
    'thaipb':  {'filename': 'thaipb.sqlite',  'name': 'ไทย (ฉบับพกพา)'},
    'thaims':  {'filename': 'thaims.sqlite',  'name': 'ไทย (เฉลิมพระเกียรติ ๒๕๔๙)'},
    'thaivn':  {'filename': 'thaivn.sqlite',  'name': 'อริยวินัย'},
    'thaiwn':  {'filename': 'thaiwn.sqlite',  'name': 'พุทธวจน (วัดนาป่าพง)'},
    'thaict':  {'filename': 'thaict.sqlite',  'name': 'ไทย (อักษรไทย)'},
    'romanct': {'filename': 'romanct.sqlite', 'name': 'Roman Script'},
}

# Integer code -> edition key, per client platform (from constants.py).
IOS_CODE_TABLE = {1: 'thai', 2: 'pali', 3: 'thaimm', 4: 'thaimc', 5: 'thaibt',
                  6: 'thaiwn', 7: 'thaipb', 8: 'romanct', 9: 'palimc',
                  10: 'thaims', 11: 'thaivn', 12: 'thaimc2'}
ANDROID_CODE_TABLE = {0: 'thai', 1: 'pali', 2: 'thaimm', 3: 'thaimc', 4: 'thaibt',
                      5: 'thaiwn', 6: 'thaipb', 7: 'romanct', 8: 'palimc',
                      9: 'thaivn'}

DICTIONARIES = {
    'pali_thai': {'filename': 'p2t_dict.sqlite', 'table': 'p2t',
                  'head': 'headword',
                  'columns': ['headword', 'content', 'type', 'gender', 'vachana',
                              'viphat', 'category', 'read', 'note', 'roman',
                              'eng_content', 'source']},
    'pali_english': {'filename': 'pali-english.sqlite', 'table': 'english',
                     'head': 'head', 'columns': ['head', 'translation']},
    'thai': {'filename': 'thaidict.sqlite', 'table': 'thai',
             'head': 'head', 'columns': ['head', 'translation']},
}


class RegistryError(Exception):
    pass


def edition_for(platform, code):
    table = {'ios': IOS_CODE_TABLE, 'android': ANDROID_CODE_TABLE}.get(platform)
    if table is None:
        raise RegistryError('code resolution unsupported for platform %r' % platform)
    try:
        return table[int(code)]
    except (KeyError, ValueError, TypeError):
        raise RegistryError('unknown code %r for platform %s' % (code, platform))


def edition_path(resources_dir, edition_key):
    meta = EDITIONS.get(edition_key)
    if not meta:
        raise RegistryError('unknown edition: %r' % edition_key)
    path = os.path.join(resources_dir, meta['filename'])
    if not os.path.exists(path):
        raise RegistryError('edition file not found: %s' % path)
    return path


def dictionary_path(resources_dir, dictionary_key):
    meta = DICTIONARIES.get(dictionary_key)
    if not meta:
        raise RegistryError('unknown dictionary: %r' % dictionary_key)
    path = os.path.join(resources_dir, meta['filename'])
    if not os.path.exists(path):
        raise RegistryError('dictionary file not found: %s' % path)
    return path
