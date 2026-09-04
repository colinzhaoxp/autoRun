# autoRun

在本机常驻的后台服务，监听一个端口；其他机器通过 HTTP 携带密钥调用，即可在本机执行
预先定义好的 shell 命令（或裸命令）。命令在后台执行并记录 PID，可随时查看正在跑什么、
以及关掉它。所有收到的请求与实际执行的命令全部落盘审计。

## 快速开始

```bash
# 1. 安装依赖（唯一依赖是 PyYAML）
/root/miniconda3/bin/pip install -r requirements.txt

# 2. 准备配置
cp config/config.example.yaml config/config.yaml
chmod 600 config/config.yaml            # 必须：权限过宽时服务拒绝启动

# 3. 准备密钥文件
cp .env.example .env
chmod 600 .env                          # 必须：权限过宽时服务拒绝启动
# 编辑 .env，把 AUTORUN_KEY_ADMIN 换成一个强密钥：
python -c 'import secrets;print(secrets.token_urlsafe(32))'

# 4. 校验配置
export PYTHONPATH=$PWD/src
python -m autorun validate

# 5. 前台运行（调试）或后台启动
python -m autorun foreground
python -m autorun start
```

## 密钥管理

密钥统一放在项目根目录的 `.env`，服务启动时自动读取，**不需要手动 export**：

```bash
# .env
AUTORUN_KEY_ADMIN=nGx8...token_urlsafe(32)的输出
AUTORUN_KEY_CI=7Kp2...
```

`config.yaml` 里用 `${变量名}` 引用，因此**密钥本身永远不会写进 YAML**，配置文件可以
安全地拿去 review 或做模板：

```yaml
auth:
  keys:
    - id: "admin"
      key: "${AUTORUN_KEY_ADMIN}"
```

几条规则：

- `.env` 权限必须是 600，否则服务拒绝启动。`.env` 与 `config/config.yaml` 都在 `.gitignore` 中，
  只有 `.env.example` 入库。
- **已存在的环境变量优先**，`.env` 不覆盖它们。所以 `AUTORUN_KEY_ADMIN=xxx python -m autorun foreground`
  可以临时压过文件里的值，便于调试。
- 值中含空格、`#` 或首尾空白时必须加引号（`KEY="a b # c"`）。单引号内是完全字面量，
  适合含 `$`、`\` 的密钥。支持 `export KEY=value` 写法，同一个文件也能被 shell `source`。
- 变量名重复定义、引号未闭合、缺少 `=` 都会带行号报错，不静默跳过 —— 密钥出错时
  静默容错比报错更难排查。
- `${VAR}` 未定义时，报错信息会直接告诉你去 `.env` 里加哪个变量。

**密钥可以热轮换**：改完 `.env` 执行 `python -m autorun reload` 即可生效，不用重启：

```bash
# 改 .env 里的 AUTORUN_KEY_ADMIN，然后
python -m autorun reload
# 旧密钥立即失效（401），新密钥生效（200）
```

重载只覆盖上次确实由 `.env` 提供的变量，不会踩掉你在 shell 里显式指定的值。

其他用法：`--env-file /path/to/other.env` 指定别的文件（不存在则报错），
`--no-env-file` 完全不读文件、只用当前环境变量（适合 systemd 用 `EnvironmentFile` 注入的场景）。

**密钥不会传给被执行的命令。** 子进程的环境只包含 `execution.env_passthrough` 白名单里的
变量（默认 `PATH`/`LANG`/`HOME`）加上 `env_extra`，所以 `AUTORUN_KEY_*` 不会泄露给任务脚本。
这一点有专门的测试覆盖。


调用：

```bash
curl -s localhost:8770/healthz

# 执行预定义别名
curl -s -XPOST localhost:8770/v1/exec \
  -H "X-Auth-Key: $AUTORUN_KEY_ADMIN" -H 'Content-Type: application/json' \
  -d '{"alias":"disk_usage"}'

# 查看正在跑什么
cat runtime/state/processes.txt
python -m autorun ps --running

# 关掉某个任务
curl -s -XPOST localhost:8770/v1/processes/<job_id>/kill \
  -H "X-Auth-Key: $AUTORUN_KEY_ADMIN" -H 'Content-Type: application/json' -d '{"signal":"TERM"}'
python -m autorun kill <job_id>          # 本机应急，不经过 HTTP
```

## 威胁模型（先读这一节）

本服务的功能就是**远程执行命令**，因此它本质上是一个受控的 RCE 端点。请按这个前提部署。

标准库的 `http.server` 官方明确说明未针对恶意流量加固。本项目补齐了请求体上限、
socket 超时、拒绝 chunked 编码、有界线程池等防护，但**仍应部署在可信内网、VPN 或
nginx 之后**，不要直接暴露到公网。默认 `bind 127.0.0.1` 就是为了避免误部署即刻可达。

四层控制，按请求处理顺序生效：

1. **IP 白名单** —— 空列表拒绝启动（fail closed）。
2. **限流** —— 令牌桶，未认证请求共享一个桶。
3. **共享密钥认证** —— `hmac.compare_digest` 恒定时间比对。
4. **按 key 授权** —— 每个密钥单独配置可执行的别名、是否允许裸命令、是否允许 kill。

**顺序本身就是安全属性**：白名单在认证之前，所以未授权来源根本走不到密钥比对，
端点无法被当作"密钥探测器"；限流在认证之前，所以暴力破解会被节流。

已知限制，如实列出：

- **未启用 TLS 时，共享密钥以明文穿越网络。** 生产环境请启用 `tls`（或配 `client_ca_file`
  走 mTLS，那是本服务最强的访问控制），或置于 TLS 终结的反向代理之后。
- **裸命令执行（`/v1/exec/raw`）就是无限制 RCE**，没有任何办法让它变"安全"。它默认关闭，
  需要全局开关 + 该 key 的 `allow_raw` 双重许可。`raw_command_denylist` 只是纵深防御：
  它能挡住手滑打出的 `rm -rf /`，挡不住 `rm -fr /`、变量拼接或 base64 解码执行。
  **不要把它当成安全边界。**
- **以 root 运行时所有任务都是 root。** 请配置 `execution.run_as` 降权，或让服务本身
  以非 root 用户运行。启动时会就此告警。
- **`killpg` 覆盖不到自行二次 fork 脱离进程组的守护型子进程。** 这类进程需要自行管理。
- **输出上限是软限制。** 监控线程每 0.5 秒检查一次文件大小，高速输出的命令
  （如 `yes`）在被发现前可能已写入远超上限的数据。它防的是磁盘被慢慢填满，
  不是瞬时爆量。

## 命令注入的防线

客户端**永远无法**提供命令体本身，只能提供别名和已声明的参数值。命令文本、`cwd`、
`run_as` 全部来自服务端配置。

- `argv` 形式的别名以 `shell=False` 执行 —— 没有 shell，就没有元字符可利用。**首选这种形式。**
- `shell` 形式的别名，参数代入**不是**字符串格式化：每个值先经该参数声明的正则
  `fullmatch` 与长度校验，通过后再用 `shlex.quote` 包裹。用 `str.format` 或 f-string
  拼命令是这类服务最典型的 RCE 成因，本项目刻意不提供那条路径。
- 每个参数**必须**声明 `pattern`（正则白名单），否则配置校验失败、服务不启动。
  要接受任意单行文本用 `pattern: "^.*$"`；**不能写 `pattern: ""`** —— 空正则在 `fullmatch`
  下只匹配空字符串，会拒绝所有输入，语义与「不限制」正好相反，因此启动时会直接报错并给出提示。
- 控制字符（NUL、换行、回车、转义符）无论 pattern 多宽松都一律拒绝。

对应的测试在 `tests/test_commands_injection.py`，覆盖 18 类注入载荷，并断言它们
**不产生任何副作用**（而不只是返回 422）。

## API

所有响应为统一 JSON 封装，并带 `X-Request-Id` 响应头：

```json
{"ok": true,  "request_id": "r-...", "data": {}}
{"ok": false, "request_id": "r-...", "error": {"code": "ALIAS_NOT_FOUND", "message": "..."}}
```

| Method | Path | 用途 | 认证 |
|---|---|---|---|
| GET | `/healthz` | 版本、uptime、运行任务数 | 仅 IP |
| GET | `/v1/commands` | 列出该密钥可见的别名与参数规格 | key |
| POST | `/v1/exec` | 执行预定义别名 | key + 别名 ACL |
| POST | `/v1/exec/raw` | 执行裸命令 | key + `allow_raw` + 全局开关 |
| GET | `/v1/processes` | 任务列表，`?status=running&alias=x&limit=50` | key |
| GET | `/v1/processes/{job_id}` | 单任务详情 | key |
| GET | `/v1/processes/{job_id}/output` | 拉取任务输出，`?offset=&max_bytes=` | key |
| POST | `/v1/processes/{job_id}/kill` | 发信号（TERM 后自动升级 KILL） | key + `allow_kill` |
| POST | `/v1/processes/kill-by-pid` | 按 PID 终止（须为本服务跟踪的任务） | key + `allow_kill` |

请求体：

```jsonc
// POST /v1/exec —— mode 可选 background(默认) / sync
{"alias": "rollback", "params": {"tag": "v1.4.2"}, "mode": "background", "timeout_sec": 600}
// POST /v1/exec/raw
{"command": "df -h /var", "cwd": "/", "mode": "sync", "timeout_sec": 20}
// POST /v1/processes/{job_id}/kill
{"signal": "TERM", "kill_group": true, "escalate_after_sec": 10}
```

后台执行返回 `202` + `job_id/pid/pgid/log_file`；`mode:"sync"` 返回 `200` +
`exit_code/output_tail`。同步等待有预算上限（受 socket 超时约束），**超出预算时任务
继续在后台运行**，响应会明确说明这一点而不是谎报结果。

状态码：`400` 请求格式 · `401` 密钥缺失/错误 · `403` IP 或权限 · `404` 别名/任务不存在 ·
`405` 方法 · `409` singleton 冲突或任务已结束 · `413` 请求体超限 · `415` Content-Type ·
`422` 参数校验失败 · `429` 限流（带 `Retry-After`） · `503` 并发已满 · `500` 内部错误
（客户端只得到通用信息 + `request_id`，堆栈只进服务日志）。

**幂等**：可选的 `X-Idempotency-Key` 头在 10 分钟窗口内把重复提交映射回首次的
`job_id`。客户端因超时重试 `deploy` 时不会起第二个部署 —— 这是运维中代价最高的一类事故。

## 定制命令

在 `config.yaml` 的 `commands` 下增加别名。两种形式：

```yaml
commands:
  # 形式一：argv（不经过 shell，最安全，优先使用）
  restart_app:
    description: "重启应用"
    argv: ["/bin/systemctl", "restart", "myapp"]
    timeout_sec: 120

  # 形式二：shell（支持管道与 && 等语法）
  deploy:
    shell: "cd /app && git pull --ff-only && ./restart.sh"
    cwd: "/app"
    timeout_sec: 1800
    singleton: true          # 已有实例在跑时拒绝，避免并发部署

  # 带参数：每个参数必须有正则白名单
  rollback:
    shell: "cd /app && ./rollback.sh {tag}"
    params:
      tag:
        required: true
        pattern: "^v[0-9]+\\.[0-9]+\\.[0-9]+$"
        max_length: 32
    timeout_sec: 600
```

改完配置执行 `python -m autorun reload`（发 SIGHUP）。新配置会先完整校验成一个新对象，
成功后才原子替换，**因此配置写错不会影响正在运行的服务**（错误记入服务日志）。
`commands`、`auth.keys`、`security`、`rate_limit`、`logging.level` 支持热加载；
`server.*`、`tls.*`、`paths.*` 需要重启。

## 日志与审计

三条独立的流：

| 文件 | 内容 |
|---|---|
| `runtime/logs/audit.jsonl` | 审计流水，每行一个 JSON。**出问题时的唯一依据** |
| `runtime/logs/service.log` | 服务自身运行日志与异常堆栈 |
| `runtime/logs/jobs/<job_id>.log` | 每个任务的 stdout+stderr（合并，保持时间顺序） |

审计日志的关联性是刻意设计的：每个请求产生共享 `request_id` 的 `request`/`response`
两条；每个任务产生由 `job_id` 关联的 `command_start`/`command_exit`。于是能从
"谁在什么时候发了什么请求"一路追到"实际执行的 argv 是什么、退出码多少"。

```bash
# 追踪某次请求的完整链路
grep r-a252afb27b09 runtime/logs/audit.jsonl

# 看所有认证失败
grep auth_failure runtime/logs/audit.jsonl
```

密钥本身、`Authorization` 头一律不写入日志。命令文本与参数在落盘前经
`logging.redact_patterns` 脱敏（默认覆盖 `password=`、`token=`、`secret=` 等形态）。
脱敏是尽力而为的兜底 —— 真正的解法是不要把密钥放进命令行。

任务日志与审计日志分离，这样一个话痨任务不会冲淡审计轨迹。

## 进程跟踪

权威数据是 `runtime/state/processes.json`，写入方式为"临时文件 → fsync → `os.replace`"，
全程持有文件锁，因此**直接 `cat` 也永远读不到半截文件**。同时渲染一份人类可读的
`runtime/state/processes.txt`：

```
JOB_ID                     PID     PGID    STATUS    ALIAS       START_TIME          ELAPSED   EXIT  COMMAND
j-20260904-130435-becb     299282  299282  running   long_task   2026-09-04 13:04:35 00:00:03  -     for i in $(seq 1 600); do echo tick $i; sleep 1; done
```

任务状态的区分是刻意做细的 —— 出事时"不知道结果"和"结果是失败"必须能分辨：

| 状态 | 含义 |
|---|---|
| `running` | 正在运行 |
| `exited` | 正常结束，退出码 0 |
| `failed` | 结束，退出码非 0 |
| `killed` | 被信号终止 |
| `timeout` | 超时被终止（TERM 后必要时升级 KILL） |
| `orphaned` | 服务重启前启动，进程仍在跑。**可以 kill，但退出码不可获取** |
| `unknown` | 进程已消失或 PID 已被复用，**实际结果不可知** |

`orphaned` 与 `unknown` 是如实反映"我不知道"，而不是编一个退出码。

**PID 复用防护**：发信号前会校验 PID 与记录的进程启动时刻（`/proc/<pid>/stat` 的
starttime）是否都匹配。不匹配就拒绝发信号并把任务标为 `unknown`。没有这道检查，
重启后按 PID kill 就是在赌是否会误杀无关进程。

## 部署

推荐用 systemd（进程监督、崩溃重启都是现成的）：

```bash
cp deploy/autorun.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now autorun
systemctl reload autorun          # 等价于 SIGHUP，热加载 .env 与 config.yaml
```

unit 直接复用项目根目录的 `.env`（`WorkingDirectory` 指向项目），所以密钥管理方式与手动
运行完全一致。若更倾向 systemd 原生方式，可改用 `EnvironmentFile=/etc/autorun/env`
并给 ExecStart 加上 `--no-env-file`。

unit 中 `KillMode=process` 是关键：默认的 control-group 模式会在服务停止时连带杀死所有
子进程，那样每次重启都会打断正在执行的长任务 —— 与 `kill_jobs_on_shutdown` 默认
`false` 的设计意图相反。

日志轮转：`cp deploy/autorun.logrotate /etc/logrotate.d/autorun`。用 `copytruncate`
而非 `create`，因为服务进程持有文件句柄，改名后它会继续往旧 inode 写。服务收到
SIGHUP 时也会主动重开文件句柄。

## CLI

| 命令 | 说明 |
|---|---|
| `validate` | 只校验配置并打印摘要（含 .env 加载详情），不启动 |
| `foreground` | 前台运行，日志同时打到终端（调试用） |
| `start` / `stop` / `restart` | 双 fork 守护化管理（无 systemd 时用） |
| `reload` | 本地先校验，再向服务发 SIGHUP |
| `status` | 服务是否在运行、任务统计 |
| `ps [--running] [--json]` | 列出任务及 PID，直接从 JSON 渲染 |
| `kill <job_id> [-9]` | 本机应急终止，不经过 HTTP |

全局选项：`-c/--config` 指定配置文件，`--env-file` 指定密钥文件，`--no-env-file` 跳过 `.env`。

单实例由 PID 文件的 `flock` 保证，而不是"写 PID 再检查进程是否存在"—— 后者在 PID
被复用时会误判成"服务已在运行"，而 flock 由内核维护，进程一死锁自动释放。

## 测试

```bash
export PYTHONPATH=$PWD/src
python -m pytest tests/ -v
```

148 个用例。重点分布：

- `test_commands_injection.py` —— 18 类注入载荷，断言无副作用而非仅返回 422
- `test_security.py` —— 中间件顺序（有效密钥 + 非白名单 IP 必须 403）、XFF 伪造、ACL
- `test_executor.py` —— 进程组回收、TERM→KILL 升级、重启对账、密钥不泄漏进子进程环境
- `test_registry.py` —— 并发写入下无半截 JSON、PID 复用、清理策略
- `test_api_e2e.py` —— 真实 socket 与真实进程的完整链路
- `test_envfile.py` —— .env 解析边界、权限校验、优先级、热轮换覆盖范围

## 项目结构

```
src/autorun/
  config.py      配置加载与全量校验（每条规则对应一个真实故障模式）
  commands.py    别名解析与参数校验 —— 注入防线，最需要评审
  executor.py    进程启动、超时看护、整树回收、重启对账
  registry.py    任务登记表：文件锁 + 原子写 + txt 渲染
  security.py    IP 白名单、限流、认证、授权（顺序即安全属性）
  handler.py     HTTP 解析、中间件链、路由、统一响应封装
  routes.py      各端点实现
  server.py      端口绑定、TLS、有界线程池
  daemon.py      双 fork、flock PID 文件、信号处理
  envfile.py     .env 解析与加载（密钥管理）
  cli.py         命令行入口
  audit.py       JSONL 审计与脱敏
  procutil.py    /proc starttime 解析、PID 复用防护
```

