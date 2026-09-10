"""/v1/gpu 端点与 healthz 的 gpu 概况。

通过向监控器注入假快照读取，避免依赖真实 GPU 与采样线程。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autorun.gpu import GpuInfo, GpuSnapshot  # noqa: E402

from conftest import TEST_KEY_ADMIN, TEST_KEY_CI  # noqa: E402


def _snap(*utils):
    gpus = tuple(GpuInfo(i, u, 1000, 81920, 40) for i, u in enumerate(utils))
    return GpuSnapshot(ok=True, sampled_at="2026-09-10T00:00:00+08:00",
                       gpus=gpus, idle_util_threshold=20)


def test_gpu_endpoint_requires_auth(ctx, client):
    status, body, _ = client.get("/v1/gpu", key=None)
    assert status == 401


def test_gpu_endpoint_returns_snapshot(ctx, client):
    ctx.gpu_monitor._last_snapshot = _snap(10, 90, 0)
    status, body, _ = client.get("/v1/gpu")
    assert status == 200
    snap = body["data"]["snapshot"]
    assert snap["count"] == 3
    assert snap["avg_util"] == pytest.approx(33.3, abs=0.1)
    assert snap["idle_count"] == 2       # 10 和 0 都 < 20


def test_gpu_endpoint_no_snapshot_yet(ctx, client):
    status, body, _ = client.get("/v1/gpu")
    assert status == 200
    assert body["data"]["snapshot"] is None


def test_healthz_includes_gpu_summary(ctx, client):
    ctx.gpu_monitor._last_snapshot = _snap(50, 50)
    status, body, _ = client.get("/healthz")
    assert status == 200
    gpu = body["data"]["gpu"]
    assert gpu["avg_util"] == 50.0
    assert gpu["idle_count"] == 0
    assert gpu["ok"] is True


def test_healthz_omits_gpu_when_no_sample(ctx, client):
    status, body, _ = client.get("/healthz")
    assert status == 200
    assert "gpu" not in body["data"]
