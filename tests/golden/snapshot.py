import json
import os

SNAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapshots")


def _path(case_id):
    return os.path.join(SNAP_DIR, case_id + ".json")


def save_snapshot(case_id, data):
    if not os.path.isdir(SNAP_DIR):
        os.makedirs(SNAP_DIR)
    with open(_path(case_id), "w") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)


def load_snapshot(case_id):
    with open(_path(case_id)) as handle:
        return json.load(handle)
