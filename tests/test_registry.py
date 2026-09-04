"""任务登记表测试：原子写、并发安全、PID 复用防护、清理策略。"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta

from autorun.config import RegistryConfig
from autorun.registry import JobRecord, Registry, render_table


def make_record(job_id: str, **kw) -> JobRecord:
    defaults = dict(
        job_id=job_id,
        pid=12345,
        pgid=12345,
        alias="demo",
        command_display="echo demo",
        argv=["/bin/echo", "demo"],
        cwd="/",
        start_time=datetime.now().astimezone().isoformat(timespec="seconds"),
        log_file="/tmp/x.log",
    )
    defaults.update(kw)
    return JobRecord(**defaults)


def test_add_and_get_roundtrip(tmp_path):
    reg = Registry(tmp_path / "state", RegistryConfig())
    try:
        reg.add(make_record("j-1"))
        got = reg.get("j-1")
        assert got is not None and got.pid == 12345
        assert (tmp_path / "state" / "processes.json").is_file()
        assert (tmp_path / "state" / "processes.txt").is_file()
    finally:
        reg.close()


def test_state_survives_reopen(tmp_path):
    """服务重启后必须还能看到上次的任务，否则孤儿进程就彻底失联了。"""
    reg = Registry(tmp_path / "state", RegistryConfig())
    reg.add(make_record("j-1", status="running"))
    reg.close()

    reg2 = Registry(tmp_path / "state", RegistryConfig())
    try:
        assert reg2.get("j-1") is not None
        assert reg2.running_count() == 1
    finally:
        reg2.close()


def test_concurrent_writers_never_produce_torn_json(tmp_path):
    """并发写入下，外部读者永远看到完整 JSON（原子替换的直接验证）。"""
    reg = Registry(tmp_path / "state", RegistryConfig())
    path = tmp_path / "state" / "processes.json"
    errors: list[str] = []
    stop = threading.Event()

    def writer(idx: int) -> None:
        for i in range(30):
            reg.add(make_record(f"j-{idx}-{i}"))

    def reader() -> None:
        while not stop.is_set():
            if path.is_file():
                try:
                    json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    errors.append(f"读到半截 JSON: {exc}")

    try:
        readers = [threading.Thread(target=reader) for _ in range(3)]
        for t in readers:
            t.start()
        writers = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in writers:
            t.start()
        for t in writers:
            t.join()
        stop.set()
        for t in readers:
            t.join()
        assert not errors, errors[:3]
        assert len(reg.all()) == 120
    finally:
        reg.close()


def test_corrupt_state_file_does_not_block_startup(tmp_path):
    """状态文件损坏时不能让服务起不来：备份后从空表开始。"""
    state = tmp_path / "state"
    state.mkdir(parents=True)
    (state / "processes.json").write_text("{not valid json", encoding="utf-8")
    reg = Registry(state, RegistryConfig())
    try:
        assert reg.all() == []
        assert list(state.glob("processes.corrupt.*")), "损坏文件应被备份留证"
    finally:
        reg.close()


def test_singleton_check(tmp_path):
    reg = Registry(tmp_path / "state", RegistryConfig())
    try:
        reg.add(make_record("j-1", alias="deploy", status="running"))
        assert reg.has_running_alias("deploy")
        reg.update("j-1", status="exited")
        assert not reg.has_running_alias("deploy")
    finally:
        reg.close()


def test_find_by_pid_only_matches_running(tmp_path):
    reg = Registry(tmp_path / "state", RegistryConfig())
    try:
        reg.add(make_record("j-1", pid=999, status="running"))
        assert reg.find_by_pid(999) is not None
        reg.update("j-1", status="exited")
        # 已结束任务的 PID 可能已被系统复用给别的进程，不能再按它定位。
        assert reg.find_by_pid(999) is None
    finally:
        reg.close()


def test_prune_keeps_running_and_drops_old_finished(tmp_path):
    reg = Registry(tmp_path / "state", RegistryConfig(retain_finished_hours=1, max_records=100))
    try:
        old = (datetime.now().astimezone() - timedelta(hours=5)).isoformat(timespec="seconds")
        reg.add(make_record("j-old", status="exited", end_time=old, start_time=old))
        reg.add(make_record("j-run", status="running"))
        reg.add(make_record("j-new", status="exited"))
        ids = {r.job_id for r in reg.all()}
        assert "j-old" not in ids, "超过保留期的已结束任务应被清理"
        assert {"j-run", "j-new"} <= ids
    finally:
        reg.close()


def test_prune_respects_max_records_but_never_drops_running(tmp_path):
    reg = Registry(tmp_path / "state", RegistryConfig(max_records=5))
    try:
        for i in range(10):
            reg.add(make_record(f"j-run-{i}", status="running"))
        for i in range(10):
            reg.add(make_record(f"j-done-{i}", status="exited"))
        records = reg.all()
        assert sum(1 for r in records if r.is_running) == 10, "运行中的任务永不清理"
        assert sum(1 for r in records if not r.is_running) == 0
    finally:
        reg.close()


def test_transaction_batches_writes(tmp_path):
    reg = Registry(tmp_path / "state", RegistryConfig())
    try:
        with reg.transaction() as r:
            r.stage(make_record("j-a", status="running"))
            r.stage(make_record("j-b", status="running"))
        assert reg.running_count() == 2
        data = json.loads((tmp_path / "state" / "processes.json").read_text())
        assert set(data["jobs"]) == {"j-a", "j-b"}
    finally:
        reg.close()


def test_text_view_contains_pid_and_command(tmp_path):
    """processes.txt 要能直接 cat 出"在跑什么、PID 多少"。"""
    reg = Registry(tmp_path / "state", RegistryConfig())
    try:
        reg.add(make_record("j-1", pid=4242, command_display="sleep 300", status="running"))
        text = (tmp_path / "state" / "processes.txt").read_text()
        assert "JOB_ID" in text and "4242" in text and "sleep 300" in text
    finally:
        reg.close()


def test_render_table_matches_file_view(tmp_path):
    """CLI 直接从 JSON 渲染，因此 txt 镜像过期时 CLI 仍准确。"""
    reg = Registry(tmp_path / "state", RegistryConfig())
    try:
        reg.add(make_record("j-1", pid=777, status="running"))
        assert "777" in render_table(reg.all())
    finally:
        reg.close()


def test_file_permissions_are_owner_only(tmp_path):
    """状态文件含命令行内容，不应对其他用户可读。"""
    reg = Registry(tmp_path / "state", RegistryConfig())
    try:
        reg.add(make_record("j-1"))
        for name in ("processes.json", "processes.txt"):
            mode = (tmp_path / "state" / name).stat().st_mode & 0o777
            assert mode == 0o600, f"{name} 权限为 {oct(mode)}"
    finally:
        reg.close()
