# 固定内网区域主备 DNS（FastAPI + SQLite + dnslib）

为固定内网区域 `internal.local`（可用 `DNS_ZONE` 修改）提供主备两台权威 DNS：

- **主机 (primary)**：通过 REST API 接收一次提交、最多 8 条 A 记录的**完整区域**；
  仅在整份区域校验并落库成功后才把序号 (serial) 加 1。发布不依赖备用机。
- **备用机 (backup)**：从主机 HTTP 拉取**整份版本**，支持手动同步、后台自动同步和
  版本查询；两机各自使用独立 SQLite 数据库（不同文件/卷）。
- 两机都通过 **UDP 53 风格端口（默认 5053）** 回答区域内 A 查询，每个回答只取自
  **一份不可变的完整版本**快照，绝不混版。
- 办公终端只需把这组 DNS 配为唯一 DNS：区域外 **A 查询**由每台机器各自配置的
  **单个 UDP 上游**代答；区域内查询始终由本机完整区域版本回答。转发结果只回给
  发起查询的客户端，**绝不写入区域**。

## 设计要点与需求对应

| 需求 | 实现方式 |
| --- | --- |
| 单次提交 ≤8 条 A 记录的完整区域 | `app/models.py`：非空、≤8、仅 IPv4、名称必须在固定区域内、禁止重名 |
| 发布成功才递增序号 | `Storage.next_publish()`：单事务 `BEGIN IMMEDIATE` 内插入新版本并切换 active 指针；校验失败在进事务前返回 422，序号不变 |
| 两机独立数据库 | 各自 `DB_PATH`（compose 中 `primary-data` / `backup-data` 两个卷） |
| 单次回答只用一份完整版本 | `zone_versions` 存不可变整份快照；DNS 解析前一次性读取 active 版本，再在内存中查表回答 |
| 手动同步 + 版本查询 | `POST /api/sync`、`GET /api/version`、`GET /api/zone` |
| 慢传/断传期间继续回答旧版 | 传输失败（连接拒绝、超时、HTTP 错误、坏报文）不触碰 active 版本，旧版本继续服务；同步状态写入 `state` 表 |
| 断开/重启后自动追到最新版 | 备用机启动即拉取一次，之后按 `SYNC_INTERVAL` 后台循环，直到与上游同序号 |
| 迟到旧传输不得回退 | `commit_version()` 拒绝任何 `serial <= active_serial` 的版本（返回 `ignored_stale`/False），事务保护 |
| 任一方失败仍供原版 | 发布失败保留旧 active；同步失败保留旧 active；DNS 与 HTTP 在同一进程内独立运行 |
| 主机发布无需等待备用 | 主机 API 不调用备用机；e2e 中备用停机时发布仍在毫秒级成功 |
| 区外 A 查询由单 UDP 上游代答 | `app/forwarder.py`；`DNS_UPSTREAM` 每台各配一个，仅转 A/IN/单问题 |
| 转发答复严格匹配来源/端口/ID/问题 | 每次转发独立临时 socket + 新请求 ID，逐项核对后才回给客户端；其余丢弃 |
| 错配/迟到答复不串给其他客户端 | 每个在途转发独占 socket，迟到包只会落回该 socket，核对失败即丢弃，不进入区域 |
| 每台最多 4 个在途转发，超额/超时 SERVFAIL | `BoundedSemaphore(4)` 非阻塞获取；等待上游与整体共用 1 秒 deadline |
| 上游阻塞不影响内网/发布/同步 | 转发在独立 DNS 请求线程内阻塞；HTTP 发布/同步与内网查询路径互不持锁 |
| 转发结果不写入区域 | 转发器只读请求并返回报文，不接触 `storage`；e2e 校验 `/api/zone` 不变 |
| Docker Compose 主备 + 本地示例上游 | compose 中 `upstream` 服务（`app/example_upstream.py`）响应示例区外 A |

### 数据模型（SQLite，WAL 模式）

```
zone_versions(serial INTEGER PRIMARY KEY, records_json TEXT,
              record_count INTEGER, published_at TEXT)   -- 不可变整份版本
state(key TEXT PRIMARY KEY, value TEXT)
        active_serial      当前生效版本指针
        last_sync_*        备用机最近一次同步状态（at/status/error）
        upstream_serial    最近看到的上游序号
```

版本切换 = 插入新版本行 + 更新 `active_serial` 指针，在同一个事务里提交，
因此外部观察到的永远是“某一份完整版本”，不存在中间态。

## 端口与 API

| 角色 | API/Swagger | UDP DNS |
| --- | --- | --- |
| primary | 主机 8080 → 容器 8000 | 主机 5053 → 容器 5053/udp |
| backup  | 主机 8081 → 容器 8000 | 主机 5054 → 容器 5053/udp |
| upstream（示例） | — | 主机 5055 → 容器 53/udp（仅演示用） |

- `GET  /health` 健康检查
- `GET  /api/version` 角色、当前序号、记录数、备用机同步状态，以及转发状态
  （`forward_enabled`、`forward_upstream`、`forward_error`、
  `forward_max_inflight`、`forward_timeout`）
- `GET  /api/zone` 当前完整区域（含 serial、records、published_at）
- `POST /api/zone` **仅主机**，请求体 `{"records":[{"name":"db.internal.local","ip":"10.0.0.11"}]}`，成功返回 201 与新 serial
- `POST /api/sync` **仅备用机**，立即拉取一次，返回 `synced` / `ignored_stale` / `failed`

### DNS 行为

| 查询 | 结果 |
| --- | --- |
| 区域内 A，命中 | `NOERROR` + A（取自一份完整版本快照） |
| 区域内 A，未命中 | `NXDOMAIN` |
| 区域内非 A（如 AAAA） | `NOERROR` NODATA |
| 区域外 A，已配置上游 | 转发给上游；**保留上游应答码与记录**（NOERROR/NXDOMAIN 等原样返回），请求 ID 改写回客户端 |
| 区域外 A，转发在途已满或 1 秒内无有效答复 | `SERVFAIL` |
| 区域外非 A（AAAA/MX/…）、未配置上游 | `REFUSED`（只转发 A） |

转发校验：只接纳**源 IP、源端口、请求 ID、问题（名称/类型/类）**全部与本次转发
匹配的答复；错配、畸形、迟到的答复在该次转发的 socket 上被丢弃，不会交给任何
其他客户端，也不会进入区域。每台机器最多 4 个在途转发（`FORWARD_MAX_INFLIGHT`），
超过立即返回 `SERVFAIL`；从上位机发出到收到有效答复的整体预算为 1 秒
（`FORWARD_TIMEOUT`）。

## 运行方式

### Docker Compose（推荐）

```bash
docker compose up --build
# 主机 Swagger:  http://localhost:8080/docs
# 备用 Swagger:  http://localhost:8081/docs

curl -sX POST http://localhost:8080/api/zone -H 'content-type: application/json' \
  -d '{"records":[{"name":"db.internal.local","ip":"10.0.0.11"},
                  {"name":"web.internal.local","ip":"10.0.0.21"}]}'

# 手动同步（后台也会每 3 秒自动同步）
curl -sX POST http://localhost:8081/api/sync

# 内网查询（主/备都按本机完整区域版本回答）
dig @127.0.0.1 -p 5053 db.internal.local A
dig @127.0.0.1 -p 5054 db.internal.local A   # 备用机

# 外网查询（主/备各自转发给示例上游 upstream:53）
dig @127.0.0.1 -p 5053 www.example.org A     # -> 203.0.113.11
dig @127.0.0.1 -p 5054 api.example.org A     # -> 203.0.113.12
dig @127.0.0.1 -p 5053 www.example.org AAAA  # 非 A -> REFUSED

# 示例上游本身（便于对照）
dig @127.0.0.1 -p 5055 www.example.org A
```

没有 `dig` 时可用容器内的 dnslib 直接发查询：

```bash
python -c "from dnslib import DNSRecord; import socket; \
q=DNSRecord.question('www.example.org','A'); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); \
s.settimeout(2); s.sendto(q.pack(),('127.0.0.1',5053)); print(DNSRecord.parse(s.recvfrom(65535)[0]))"
```

办公终端只需要把这台机器的 5053 配成唯一 DNS：`internal.local` 由本机权威版本
回答，其他名称的 A 查询经上游代答。

### 本地直接运行（无 Docker 时）

```bash
python3 -m venv .venv --without-pip   # 或普通 venv
.venv/bin/pip install -r requirements.txt
DNS_ROLE=primary DB_PATH=./data/primary.db DNS_PORT=15053 API_PORT=18000 \
  DNS_UPSTREAM=127.0.0.1:15353 \
  .venv/bin/python -m uvicorn app.main:app --port 18000
DNS_ROLE=backup  DB_PATH=./data/backup.db  DNS_PORT=15054 API_PORT=18001 \
  PRIMARY_API_URL=http://127.0.0.1:18000 DNS_UPSTREAM=127.0.0.1:15353 \
  .venv/bin/python -m uvicorn app.main:app --port 18001
# 可选：本地示例上游
.venv/bin/python -m app.example_upstream --port 15353
```

## 测试

```bash
.venv/bin/python -m pytest tests/ -q                 # 单元测试（含转发规则）
.venv/bin/python -I tests/e2e_test.py                # 双进程端到端 30 项
.venv/bin/python -I tests/auto_sync_test.py          # 自动同步/幂等/Swagger 8 项
.venv/bin/python -I tests/slow_transfer_test.py      # 慢传期间旧版持续服务
.venv/bin/python -I tests/forwarding_test.py         # 区外转发 32 项
```

端到端覆盖：启动空版本 NXDOMAIN、非法发布不升序号、发布后 UDP 应答、
手动与自动同步、黑洞上游期间旧版持续服务、恢复后自动追平、
迟到旧版本注入被拒且不回退、进程重启持久化与追赶、备用停机时主机照常发布。

`forwarding_test.py` 覆盖：内外网查询分流、上游应答码/记录透传与请求 ID 改写、
错配/错 ID/畸形答复丢弃、迟到答复不会串给后续客户端、并发 8 个查询时上游最多
看到 4 个在途且其余立即 SERVFAIL、上游黑洞时 1 秒超时 SERVFAIL、同期内网
查询/发布/备用同步不受影响、转发不改变区域内容、上游恢复后转发自动恢复。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DNS_ROLE` | `primary` | `primary` 或 `backup` |
| `DNS_ZONE` | `internal.local` | 固定内网区域名 |
| `DB_PATH` | `/data/dns.db` | 本机独立 SQLite 文件 |
| `DNS_PORT` / `API_PORT` | `5053` / `8000` | UDP DNS / HTTP 端口 |
| `PRIMARY_API_URL` | `http://primary:8000` | 备用机指向上机 API |
| `SYNC_INTERVAL` | `5` | 备用机后台同步间隔秒 |
| `HTTP_TIMEOUT` | `10` | 拉取区域 HTTP 超时秒 |
| `MAX_RECORDS` | `8` | 单次区域最大 A 记录数 |
| `DNS_UPSTREAM` | 空 | 本机唯一 UDP 上游，`host` 或 `host:port`（默认 53）；空 = 不转发（区外仍 REFUSED） |
| `FORWARD_MAX_INFLIGHT` | `4` | 每台在途转发上限，超出立即 SERVFAIL |
| `FORWARD_TIMEOUT` | `1` | 单次转发整体预算秒，超时 SERVFAIL |

## 已知边界

- 仅支持 A 记录与 IPv4（题目范围）；区域固定为一个，区域名通过配置设定。
- 只转发区域外 **A/IN、单问题**查询；其他类型仍由本机返回 REFUSED（或区域内 NODATA）。
  上游必须直接返回最终答案，本机不做递归/CNAME 链式解析，也不缓存上游结果。
- 转发并发上限是硬性的：4 个在途时新查询不会排队，立即 SERVFAIL。
- 传输为整份区域拉取（无增量/AXFR 分帧）；区域上限 8 条，单份报文很小。
- 单机内嵌一个 UDP 解析线程与一个 uvicorn 进程；未做水平扩展与 TSIG 鉴权，
  内网部署时应限制 `/api/zone` 的调用来源。
