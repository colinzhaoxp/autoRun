"""端到端 API 测试：真实 socket、真实进程，覆盖完整的"提交 → 查询 → 终止"链路。"""

from __future__ import annotations

import json

from conftest import TEST_KEY_ADMIN, TEST_KEY_CI, read_audit, wait_until


def test_healthz_needs_no_key(client):
    status, body, headers = client.get("/healthz", key=None)
    assert status == 200
    assert body["data"]["status"] == "ok"
    assert "X-Request-Id" in headers


def test_response_envelope_and_request_id(client):
    status, body, headers = client.get("/healthz")
    assert body["ok"] is True
    assert body["request_id"] == headers["X-Request-Id"]


def test_sync_exec_returns_output_inline(client):
    status, body, _ = client.post("/v1/exec", {"alias": "hello"})
    assert status == 200
    data = body["data"]
    assert data["exit_code"] == 0
    assert "hello" in data["output_tail"]


def test_background_exec_returns_202_with_pid(client):
    status, body, _ = client.post("/v1/exec/raw", {"command": "sleep 20"})
    assert status == 202
    data = body["data"]
    assert data["pid"] > 0 and data["pgid"] == data["pid"]
    assert data["job_id"].startswith("j-")
    assert data["log_file"].endswith(".log")


def test_full_lifecycle_submit_query_kill(client):
    """核心用户场景：起一个长任务，从跟踪表里看到它，再关掉它。"""
    _, body, _ = client.post("/v1/exec/raw", {"command": "sleep 60"})
    job_id, pid = body["data"]["job_id"], body["data"]["pid"]

    # 列表能查到，且状态为 running
    _, listing, _ = client.get("/v1/processes?status=running")
    assert any(j["job_id"] == job_id and j["pid"] == pid for j in listing["data"]["jobs"])

    # 单任务详情
    _, detail, _ = client.get(f"/v1/processes/{job_id}")
    assert detail["data"]["status"] == "running"

    # 终止
    status, killed, _ = client.post(f"/v1/processes/{job_id}/kill", {"signal": "TERM"})
    assert status == 200 and killed["data"]["signalled"] is True

    assert wait_until(
        lambda: client.get(f"/v1/processes/{job_id}")[1]["data"]["status"] == "killed"
    )
    # 重复 kill 得到 409，而不是给可能已被复用的 PID 发信号
    assert client.post(f"/v1/processes/{job_id}/kill", {})[0] == 409


def test_output_endpoint_supports_incremental_read(client):
    _, body, _ = client.post(
        "/v1/exec/raw", {"command": "for i in 1 2 3 4 5; do echo line-$i; sleep 0.2; done"}
    )
    job_id = body["data"]["job_id"]
    assert wait_until(
        lambda: "line-5" in client.get(f"/v1/processes/{job_id}/output")[1]["data"]["content"]
    )
    _, first, _ = client.get(f"/v1/processes/{job_id}/output?offset=0&max_bytes=50")
    assert first["data"]["offset"] == 0
    assert first["data"]["next_offset"] == 50
    _, rest, _ = client.get(
        f"/v1/processes/{job_id}/output?offset={first['data']['next_offset']}"
    )
    assert rest["data"]["eof"] is True


def test_singleton_conflict(client):
    assert client.post("/v1/exec", {"alias": "slow"})[0] == 202
    status, body, _ = client.post("/v1/exec", {"alias": "slow"})
    assert status == 409
    assert body["error"]["code"] == "CONFLICT"


def test_idempotency_replay_returns_same_job(client):
    headers = {"X-Idempotency-Key": "deploy-run-42"}
    _, first, _ = client.post("/v1/exec/raw", {"command": "sleep 20"}, headers=headers)
    _, second, _ = client.post("/v1/exec/raw", {"command": "sleep 20"}, headers=headers)
    assert first["data"]["job_id"] == second["data"]["job_id"]
    assert second["data"]["idempotent_replay"] is True
    running = client.get("/v1/processes?status=running")[1]["data"]["jobs"]
    assert len([j for j in running if j["command"] == "sleep 20"]) == 1


def test_kill_by_pid_requires_tracked_pid(client):
    _, body, _ = client.post("/v1/exec/raw", {"command": "sleep 30"})
    pid = body["data"]["pid"]
    assert client.post("/v1/processes/kill-by-pid", {"pid": pid})[0] == 200
    # 未被跟踪的 PID（本测试进程自己）必须被拒绝，否则服务就成了任意进程杀手
    import os

    status, denied, _ = client.post("/v1/processes/kill-by-pid", {"pid": os.getpid()})
    assert status == 403
    assert os.getpid() > 0  # 自己还活着


def test_concurrency_limit_returns_503_with_retry_after(client, ctx):
    object.__setattr__(ctx.cfg.execution, "max_concurrent_jobs", 1)
    try:
        assert client.post("/v1/exec/raw", {"command": "sleep 30"})[0] == 202
        status, body, headers = client.post("/v1/exec/raw", {"command": "sleep 30"})
        assert status == 503
        assert headers.get("Retry-After")
    finally:
        object.__setattr__(ctx.cfg.execution, "max_concurrent_jobs", 5)


def test_unknown_job_returns_404(client):
    assert client.get("/v1/processes/j-does-not-exist")[0] == 404


def test_unknown_path_and_method(client):
    assert client.get("/nope")[0] == 404
    assert client.call("DELETE", "/v1/exec")[0] == 405
    assert client.get("/v1/exec")[0] == 405


def test_oversized_body_rejected_with_413(client, cfg):
    big = json.dumps({"alias": "hello", "pad": "x" * (cfg.server.max_request_body_bytes + 100)})
    status, _, _ = client.post("/v1/exec", raw_body=big.encode())
    assert status == 413


def test_malformed_json_rejected(client):
    assert client.post("/v1/exec", raw_body=b"{not json")[0] == 400


def test_non_object_body_rejected(client):
    assert client.post("/v1/exec", raw_body=b"[1,2,3]")[0] == 400


def test_wrong_content_type_rejected(client):
    status, _, _ = client.call(
        "POST", "/v1/exec", raw_body=b'{"alias":"hello"}', headers={"Content-Type": "text/plain"}
    )
    assert status == 415


def test_invalid_signal_rejected(client):
    _, body, _ = client.post("/v1/exec/raw", {"command": "sleep 20"})
    job_id = body["data"]["job_id"]
    # SIGSTOP 会让任务挂起却不结束，状态机会陷入中间态，因此不在白名单内
    status, err, _ = client.post(f"/v1/processes/{job_id}/kill", {"signal": "STOP"})
    assert status == 422
    assert client.post(f"/v1/processes/{job_id}/kill", {"signal": "KILL"})[0] == 200


def test_audit_trail_correlates_request_and_execution(client, cfg):
    """审计的价值在于关联性：从"谁发的请求"能追到"实际执行了什么、结果如何"。"""
    _, body, headers = client.post("/v1/exec", {"alias": "hello"})
    request_id = body["request_id"]
    job_id = body["data"]["job_id"]
    assert wait_until(lambda: any(e["event"] == "command_exit" for e in read_audit(cfg)))

    events = read_audit(cfg)
    by_request = [e for e in events if e.get("request_id") == request_id]
    kinds = {e["event"] for e in by_request}
    assert {"request", "command_start", "response"} <= kinds

    start = next(e for e in by_request if e["event"] == "command_start")
    assert start["job_id"] == job_id
    assert start["argv"] == ["/bin/echo", "hello"]
    assert start["key_id"] == "admin"

    exit_event = next(e for e in events if e["event"] == "command_exit" and e["job_id"] == job_id)
    assert exit_event["exit_code"] == 0
    assert exit_event["status"] == "exited"

    resp = next(e for e in by_request if e["event"] == "response")
    assert resp["status"] == 200 and resp["duration_ms"] >= 0


def test_audit_redacts_secrets_in_commands(client, cfg):
    client.post("/v1/exec/raw", {"command": "mysql --password=hunter2 -e 'select 1'"})
    text = "\n".join(json.dumps(e, ensure_ascii=False) for e in read_audit(cfg))
    assert "hunter2" not in text
    assert "[REDACTED]" in text


def test_processes_text_file_is_human_readable(client, cfg):
    _, body, _ = client.post("/v1/exec/raw", {"command": "sleep 30"})
    pid = body["data"]["pid"]
    text = (cfg.paths.state_dir / "processes.txt").read_text()
    assert "JOB_ID" in text and str(pid) in text and "sleep 30" in text


def test_list_filters_by_alias_and_limit(client):
    client.post("/v1/exec", {"alias": "hello"})
    client.post("/v1/exec/raw", {"command": "true", "mode": "sync"})
    _, body, _ = client.get("/v1/processes?alias=hello")
    assert all(j["alias"] == "hello" for j in body["data"]["jobs"])
    _, limited, _ = client.get("/v1/processes?limit=1")
    assert len(limited["data"]["jobs"]) <= 1


def test_invalid_query_param_rejected(client):
    assert client.get("/v1/processes?limit=abc")[0] == 400


def test_commands_endpoint_does_not_leak_command_bodies(client):
    """列表只暴露别名与参数规格。回显服务端脚本路径会给攻击者提供侦察信息。"""
    _, body, _ = client.get("/v1/commands")
    text = json.dumps(body)
    assert "/bin/echo" not in text
    rollback = next(c for c in body["data"]["commands"] if c["alias"] == "rollback")
    assert "tag" in rollback["params"]


def test_internal_error_does_not_leak_details(client, ctx, monkeypatch):
    """500 只返回通用信息 + request_id，堆栈只进服务日志。"""
    def boom(*a, **k):
        raise RuntimeError("internal detail /secret/path should not leak")

    monkeypatch.setattr(ctx.registry, "all", boom)
    status, body, _ = client.get("/v1/processes")
    assert status == 500
    assert "secret" not in json.dumps(body)
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert body["request_id"]
