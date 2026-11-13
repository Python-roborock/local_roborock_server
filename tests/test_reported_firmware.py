from roborock_local_server import firmware_versions as fw


class Store:
    def __init__(self, versions):
        self.versions = versions

    def get(self, duid, include_map=False):
        version = self.versions.get(duid)
        return {"firmware_version": version} if version else None


INFO = {"version": "02.35.52", "updatable": True, "currentVersion": "02.33.48", "forceUpdate": False}


def test_a_robot_on_the_offered_version_is_not_offered_it_again() -> None:
    fixed = fw.reconcile(INFO, "robot", Store({"robot": "02.35.52"}))
    assert fixed["updatable"] is False and fixed["currentVersion"] == "02.35.52"
    assert INFO["updatable"] is True


def test_an_older_report_keeps_the_update_offered_but_shows_the_real_version() -> None:
    fixed = fw.reconcile(INFO, "robot", Store({"robot": "02.33.48"}))
    assert fixed["updatable"] is True and fixed["currentVersion"] == "02.33.48"


def test_numbers_are_compared_not_text() -> None:
    assert fw.at_least("02.100.1", "02.35.52") is True
    assert fw.at_least("02.9.0", "02.35.52") is False


def test_nothing_changes_when_the_robot_has_not_reported() -> None:
    assert fw.reconcile(INFO, "robot", Store({})) == INFO
    assert fw.reconcile(INFO, "robot", None) == INFO


def test_both_answer_shapes_are_corrected() -> None:
    store = Store({"a": "02.35.52"})
    rows = [{"duid": "a", "firmwareUpdateResponse": dict(INFO)}, {"duid": "b", "firmwareUpdateResponse": dict(INFO)}]
    fixed = fw.reconcile_result(rows, "", store)
    assert fixed[0]["firmwareUpdateResponse"]["updatable"] is False and fixed[1]["firmwareUpdateResponse"]["updatable"] is True
    assert fw.reconcile_result(dict(INFO), "a", store)["updatable"] is False
