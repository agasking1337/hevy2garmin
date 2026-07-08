"""Tests for sync orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hevy2garmin.sync import fetch_workouts, sync


def _iso(dt):
    return dt.isoformat()


@patch("hevy2garmin.sync.db")
@patch("hevy2garmin.sync.get_client")
@patch("hevy2garmin.sync.HevyClient")
@patch("hevy2garmin.sync.attempt_merge")
def test_grace_defers_too_new_workout(mock_merge, mock_hevy_cls, mock_gclient, mock_db):
    now = datetime.now(timezone.utc)
    fresh = {
        "id": "w1", "title": "Push",
        "start_time": _iso(now - timedelta(minutes=30)),
        "end_time": _iso(now - timedelta(minutes=10)),
        "updated_at": _iso(now), "exercises": [],
    }
    h = MagicMock()
    h.get_workout_count.return_value = 1
    h.get_workouts.return_value = {"workouts": [fresh], "page_count": 1}
    mock_hevy_cls.return_value = h
    mock_gclient.return_value = MagicMock()
    mock_db.is_synced.return_value = False
    from hevy2garmin.sync import sync
    stats = sync(config={"hevy_api_key": "t", "merge_mode": True,
                         "sync": {"grace_period_minutes": 120}}, limit=1)
    assert stats["deferred"] == 1
    assert stats["synced"] == 0
    mock_merge.assert_not_called()
    mock_db.mark_synced.assert_not_called()


@patch("hevy2garmin.sync.db")
@patch("hevy2garmin.sync.get_client")
@patch("hevy2garmin.sync.HevyClient")
@patch("hevy2garmin.sync.attempt_merge")
def test_grace_processes_old_enough_workout(mock_merge, mock_hevy_cls, mock_gclient, mock_db):
    from hevy2garmin.merge import MergeResult
    now = datetime.now(timezone.utc)
    old = {"id": "w1", "title": "Push",
           "start_time": _iso(now - timedelta(hours=5)),
           "end_time": _iso(now - timedelta(hours=4)),
           "updated_at": _iso(now), "exercises": []}
    h = MagicMock(); h.get_workout_count.return_value = 1
    h.get_workouts.return_value = {"workouts": [old], "page_count": 1}
    mock_hevy_cls.return_value = h; mock_gclient.return_value = MagicMock()
    mock_db.is_synced.return_value = False
    mock_merge.return_value = MergeResult(merged=True, activity_id=99)
    from hevy2garmin.sync import sync
    stats = sync(config={"hevy_api_key": "t", "merge_mode": True,
                         "sync": {"grace_period_minutes": 120}}, limit=1)
    assert stats["deferred"] == 0
    assert stats["synced"] == 1


@patch("hevy2garmin.sync.db")
@patch("hevy2garmin.sync.get_client")
@patch("hevy2garmin.sync.HevyClient")
@patch("hevy2garmin.sync.attempt_merge")
def test_manual_run_bypasses_grace(mock_merge, mock_hevy_cls, mock_gclient, mock_db):
    from hevy2garmin.merge import MergeResult
    now = datetime.now(timezone.utc)
    fresh = {"id": "w1", "title": "Push",
             "start_time": _iso(now - timedelta(minutes=20)),
             "end_time": _iso(now - timedelta(minutes=5)),
             "updated_at": _iso(now), "exercises": []}
    h = MagicMock(); h.get_workout_count.return_value = 1
    h.get_workouts.return_value = {"workouts": [fresh], "page_count": 1}
    mock_hevy_cls.return_value = h; mock_gclient.return_value = MagicMock()
    mock_db.is_synced.return_value = False
    mock_merge.return_value = MergeResult(merged=True, activity_id=99)
    from hevy2garmin.sync import sync
    stats = sync(config={"hevy_api_key": "t", "merge_mode": True,
                         "sync": {"grace_period_minutes": 120}},
                 limit=1, respect_grace=False)
    assert stats["deferred"] == 0
    assert stats["synced"] == 1


class TestFetchWorkouts:
    def test_with_limit(self) -> None:
        hevy = MagicMock()
        hevy.get_workouts.return_value = {
            "workouts": [{"id": f"w{i}"} for i in range(5)],
            "page_count": 1,
        }
        result = fetch_workouts(hevy, limit=3)
        assert len(result) == 3

    def test_with_since_date(self) -> None:
        hevy = MagicMock()
        hevy.get_workouts.return_value = {
            "workouts": [
                {"id": "w1", "start_time": "2026-04-01T20:00:00+00:00"},
                {"id": "w2", "start_time": "2026-03-15T20:00:00+00:00"},
                {"id": "w3", "start_time": "2026-03-01T20:00:00+00:00"},
            ],
            "page_count": 1,
        }
        result = fetch_workouts(hevy, since="2026-03-10")
        assert len(result) == 2  # w1 and w2, w3 is before since

    def test_pagination(self) -> None:
        hevy = MagicMock()
        hevy.get_workouts.side_effect = [
            {"workouts": [{"id": "w1", "start_time": "2026-04-01"}], "page_count": 2},
            {"workouts": [{"id": "w2", "start_time": "2026-03-31"}], "page_count": 2},
        ]
        result = fetch_workouts(hevy, fetch_all=True)
        assert len(result) == 2

    def test_empty_response(self) -> None:
        hevy = MagicMock()
        hevy.get_workouts.return_value = {"workouts": [], "page_count": 0}
        result = fetch_workouts(hevy, fetch_all=True)
        assert result == []


class TestSync:
    def test_dry_run_no_garmin_calls(self, sample_workout: dict) -> None:
        with patch("hevy2garmin.sync.HevyClient") as MockHevy, \
             patch("hevy2garmin.sync.get_client") as mock_garmin, \
             patch("hevy2garmin.sync.db") as mock_db:
            mock_hevy = MockHevy.return_value
            mock_hevy.get_workout_count.return_value = 1
            mock_hevy.get_workouts.return_value = {"workouts": [sample_workout], "page_count": 1}
            mock_db.is_synced.return_value = False

            result = sync(dry_run=True, limit=1, hevy_api_key="test")

            mock_garmin.assert_not_called()
            assert result["synced"] == 1

    def test_skips_already_synced(self, sample_workout: dict) -> None:
        with patch("hevy2garmin.sync.HevyClient") as MockHevy, \
             patch("hevy2garmin.sync.db") as mock_db, \
             patch("hevy2garmin.sync.get_client"):
            mock_hevy = MockHevy.return_value
            mock_hevy.get_workout_count.return_value = 1
            mock_hevy.get_workouts.return_value = {"workouts": [sample_workout], "page_count": 1}
            mock_db.is_synced.return_value = True

            result = sync(dry_run=True, limit=1, hevy_api_key="test")
            assert result["skipped"] == 1
            assert result["synced"] == 0

    def test_reports_unmapped_exercises(self, sample_workout_unmapped: dict) -> None:
        with patch("hevy2garmin.sync.HevyClient") as MockHevy, \
             patch("hevy2garmin.sync.db") as mock_db, \
             patch("hevy2garmin.sync.get_client"):
            mock_hevy = MockHevy.return_value
            mock_hevy.get_workout_count.return_value = 1
            mock_hevy.get_workouts.return_value = {"workouts": [sample_workout_unmapped], "page_count": 1}
            mock_db.is_synced.return_value = False

            result = sync(dry_run=True, limit=1, hevy_api_key="test")
            assert "Invented Exercise 99" in result["unmapped"]

    def test_handles_fit_generation_failure(self) -> None:
        bad_workout = {
            "id": "bad",
            "title": "Bad",
            "start_time": "invalid",
            "end_time": "also-invalid",
            "exercises": [],
        }
        with patch("hevy2garmin.sync.HevyClient") as MockHevy, \
             patch("hevy2garmin.sync.db") as mock_db, \
             patch("hevy2garmin.sync.get_client"):
            mock_hevy = MockHevy.return_value
            mock_hevy.get_workout_count.return_value = 1
            mock_hevy.get_workouts.return_value = {"workouts": [bad_workout], "page_count": 1}
            mock_db.is_synced.return_value = False

            result = sync(dry_run=True, limit=1, hevy_api_key="test")
            assert result["failed"] == 1

    def test_records_to_db_after_success(self, sample_workout: dict) -> None:
        with patch("hevy2garmin.sync.HevyClient") as MockHevy, \
             patch("hevy2garmin.sync.db") as mock_db, \
             patch("hevy2garmin.sync.get_client") as mock_garmin_client, \
             patch("hevy2garmin.sync.upload_fit") as mock_upload, \
             patch("hevy2garmin.sync.rename_activity"), \
             patch("hevy2garmin.sync.set_description"):
            mock_hevy = MockHevy.return_value
            mock_hevy.get_workout_count.return_value = 1
            mock_hevy.get_workouts.return_value = {"workouts": [sample_workout], "page_count": 1}
            mock_db.is_synced.return_value = False
            mock_upload.return_value = {"upload_id": "123", "activity_id": 456}

            result = sync(limit=1, hevy_api_key="test", garmin_email="e", garmin_password="p")
            mock_db.mark_synced.assert_called_once()
            assert result["synced"] == 1
