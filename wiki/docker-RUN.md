1. 创建和进去这个目录
```shell
mkdir epusdt && cd epusdt
```

2. 把配置文件放进去这个目录，只需要改

app_url

tron_grid_api_key

api_rate_url

```shell
cat <<EOF > env
app_name=epusdt
app_uri=https://dujiaoka.com
log_level=info
http_access_log=false
sql_debug=false
http_listen=:8000

static_path=/static
runtime_root_path=/runtime

log_save_path=/logs
log_max_size=32
log_max_age=7
max_backups=3

# supported values: postgres,mysql,sqlite
db_type=sqlite

# sqlite primary database config
sqlite_database_filename=
sqlite_table_prefix=

# postgres config
postgres_host=127.0.0.1
postgres_port=3306
postgres_user=mysql_user
postgres_passwd=mysql_password
postgres_database=database_name
postgres_table_prefix=
postgres_max_idle_conns=10
postgres_max_open_conns=100
postgres_max_life_time=6

# mysql config
mysql_host=127.0.0.1
mysql_port=3306
mysql_user=mysql_user
mysql_passwd=mysql_password
mysql_database=database_name
mysql_table_prefix=
mysql_max_idle_conns=10
mysql_max_open_conns=100
mysql_max_life_time=6

# sqlite runtime store config
runtime_sqlite_filename=epusdt-runtime.db

# background scheduler config
queue_concurrency=10
queue_poll_interval_ms=1000
callback_retry_base_seconds=5

tg_bot_token=
tg_proxy=
tg_manage=

api_auth_token=

order_expiration_time=10
order_notice_max_retry=0
api_rate_url=https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/
tron_grid_api_key=
EOF
```
3. docker compose 创建
```shell
cat <<EOF > docker-compose.yaml
services:
  epusdt:
    image: gmwallet/epusdt:latest
    restart: always
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - ./env:/app/.env
    ports:
      - "8000:8000"
EOF
```
4. 运行
```shell
docker compose up -d
```
5. 配置独角兽后台

商户密钥： http://your_domain/payments/epusdt/v1/order/create-transaction

## 首次安装与反向代理注意事项

- 首次运行的安装向导（`/install`）默认**只监听 `127.0.0.1:8000`**，因为它在安装完成前没有任何认证。官方镜像已显式设置 `EPUSDT_INSTALL_ADDR=:8000`，所以按上面的 compose 部署可以正常通过浏览器访问；如果自行构建镜像或裸机部署，需要通过环境变量显式放开：

```shell
EPUSDT_INSTALL_ADDR=:8000 ./epusdt http start
```

- 初始管理员密码**不再通过 HTTP 响应返回**，只在安装进程的控制台输出一次（`docker compose logs` 可见）。
- 如果网关前面还有一层反向代理（nginx、CDN 等），为了让 API key 的 IP 白名单和后台登录限制拿到真实客户端地址，需要在 `.env` 里声明代理地址：

```shell
trusted_proxies=127.0.0.1,10.0.0.0/8
```

不配置时只采信来自回环 / 内网对端的 `X-Forwarded-For`、`X-Real-IP`，公网客户端自带的这类头会被忽略。

