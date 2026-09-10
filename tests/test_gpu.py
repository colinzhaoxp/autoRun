"""gpu.sample 的输出解析、异常降级，与 GpuSnapshot 的派生指标。

用临时脚本冒充 nvidia-smi，覆盖真实的 subprocess 路径（正常 / 非零 / 超时 / 乱码），
不依赖真实 GPU。派生指标（avg/idle/max）直接构造 GpuSnapshot 断言。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autorun import gpu  # noqa: E402
from autorun.gpu import GpuInfo, GpuSnapshot  # noqa: E402


def _fake_smi(tmp_path: Path, name: str, body: str) -> str:
    """写一个可执行的假 nvidia-smi 脚本，返回其路径。"""
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    os.chmod(p, 0o755)
    return str(p)


# --- 派生指标 -------------------------------------------------------------


def _snap(*utils: float, threshold: float = 20.0) -> GpuSnapshot:
    gpus = tuple(
        GpuInfo(index=i, util=u, mem_used=1000 * (i + 1), mem_total=81920, temp=40 + i)
        for i, u in enumerate(utils)
    )
    return GpuSnapshot(ok=True, sampled_at="2026-09-10T00:00:00+08:00",
                       gpus=gpus, idle_util_threshold=threshold)


def test_avg_util():
    assert _snap(0, 50, 100, 50).avg_util == 50.0


def test_idle_count_uses_threshold():
    snap = _snap(5, 15, 25, 100, threshold=20)
    # 低于 20 的：5、15 两张
    assert snap.idle_count == 2


def test_min_max_and_temp():
    snap = _snap(10, 90, 40)
    assert snap.min_gpu_util == 10.0
    assert snap.max_gpu_util == 90.0
    assert snap.max_temp == 42.0  # 40 + index2


def test_mem_util_computed():
    snap = _snap(100, 100)
    # gpu0: 1000/81920, gpu1: 2000/81920
    assert snap.gpus[0].mem_util == pytest.approx(1.2, abs=0.1)
    assert snap.max_mem_util == snap.gpus[1].mem_util


def test_metric_dispatch():
    snap = _snap(0, 40, 80, threshold=50)
    assert snap.metric("avg_util") == 40.0
    assert snap.metric("idle_count") == 2.0  # 0 和 40 都 < 50
    assert snap.metric("min_gpu_util") == 0.0
    assert snap.metric("max_gpu_util") == 80.0


def test_empty_snapshot_no_divzero():
    snap = GpuSnapshot(ok=False, sampled_at="t", error="boom")
    assert snap.avg_util == 0.0
    assert snap.idle_count == 0
    assert snap.max_temp == 0.0
    assert snap.to_dict()["ok"] is False


# --- sample() 的真实 subprocess 路径 --------------------------------------


def test_sample_ok(tmp_path):
    body = (
        "#!/bin/sh\n"
        'echo "0, 100, 24912, 81920, 42"\n'
        'echo "1, 0, 100, 81920, 40"\n'
    )
    smi = _fake_smi(tmp_path, "smi_ok.sh", body)
    snap = gpu.sample(smi, timeout=5, idle_util_threshold=20)
    assert snap.ok
    assert snap.count == 2
    assert snap.avg_util == 50.0
    assert snap.idle_count == 1          # gpu1 利用率 0 < 20
    assert snap.gpus[0].mem_total == 81920


def test_sample_missing_binary():
    snap = gpu.sample(None, timeout=5)
    assert not snap.ok
    assert "nvidia-smi" in snap.error


def test_sample_nonzero_exit(tmp_path):
    smi = _fake_smi(tmp_path, "smi_fail.sh", "#!/bin/sh\necho 'driver error' >&2\nexit 9\n")
    snap = gpu.sample(smi, timeout=5)
    assert not snap.ok
    assert "9" in snap.error


def test_sample_timeout(tmp_path):
    smi = _fake_smi(tmp_path, "smi_hang.sh", "#!/bin/sh\nsleep 5\n")
    snap = gpu.sample(smi, timeout=0.3)
    assert not snap.ok
    assert "超时" in snap.error


def test_sample_garbage_output(tmp_path):
    smi = _fake_smi(tmp_path, "smi_junk.sh", "#!/bin/sh\necho 'not,csv'\n")
    snap = gpu.sample(smi, timeout=5)
    assert not snap.ok
    assert "解析" in snap.error


def test_sample_na_values_degrade(tmp_path):
    # 部分设备利用率显示 [N/A]，float() 失败应整体降级而非抛异常。
    smi = _fake_smi(tmp_path, "smi_na.sh", "#!/bin/sh\necho '0, [N/A], 100, 81920, 42'\n")
    snap = gpu.sample(smi, timeout=5)
    assert not snap.ok


def test_resolve_prefers_configured():
    assert gpu.resolve_nvidia_smi("/custom/path") == "/custom/path"


def test_render_table_ok_and_fail():
    assert "采样失败" in gpu.render_table(GpuSnapshot(ok=False, sampled_at="t", error="x"))
    assert "平均利用率" in gpu.render_table(_snap(100, 100))
