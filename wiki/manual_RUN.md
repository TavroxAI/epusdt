## 写在前面

- 此教程专为有洁癖的宝宝们准备。不使用任何一键安装脚本。面板党可以退散了！！
- 本人测试环境是 Debian 11 其他的没测试。
## 1.下载源代码
```bash
cd /var/www/
mkdir epusdt
chmod 777 -R /var/www/epusdt
cd epusdt
wget https://github.com/GMWalletApp/epusdt/releases/download/v0.0.3/epusdt_0.0.3_Linux_x86_64.tar.gz
tar -xzf epusdt_0.0.3_Linux_x86_64.tar.gz
rm epusdt_0.0.3_Linux_x86_64.tar.gz
```
## 2.创建数据库
当前版本无需手动导入 SQL 文件。创建数据库并配置连接后，Epusdt 启动时会自动创建和升级所需表结构。

- 创建数据库
```bash
mysql
```
接下来输入命令 
```sql
CREATE DATABASE [这里替换为数据库名] ;
GRANT ALL ON [这里替换为数据库名].* TO '[这里替换为用户名]'@'localhost' IDENTIFIED BY '[这里替换为密码]' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EXIT
```
## 3.配置反向代理
```bash
nano /etc/nginx/sites-enabled/epusdt
```
你可以参考以下我的配置文件，注意更改域名。
```bash
server {
   listen 80;
   server_name domain.com;
   return 301 https://domain.com$request_uri;
 }

server {
   listen 443 ssl http2;
   server_name domain.com;
   ssl_certificate  /etc/nginx/sslcert/cert.crt;
   ssl_certificate_key  /etc/nginx/sslcert/key.key; 
   ssl_prefer_server_ciphers on;

   location / {
        proxy_pass http://127.0.0.1:8000;
}
}

```
## 4.赋予Epusdt执行权限
`linux`服务器需要赋予`Epust`执行权限方可启动。            
执行命令```chmod +x epusdt```赋予权限
## 5、配置Epusdt
执行命令
```bash
mv .env.example .env
nano .env
```

```dotenv
app_name=epusdt
#下面配置你的域名，收银台会需要
app_uri=https://upay.dujiaoka.com
#是否开启debug，默认false
app_debug=false
#http服务监听端口
http_listen=:8000
#静态资源文件目录
static_path=/static
#缓存路径
runtime_root_path=/runtime
#日志配置
log_save_path=/logs
log_max_size=32
log_max_age=7
max_backups=3
# mysql配置
mysql_host=127.0.0.1
mysql_port=3306
mysql_user=mysql账号
mysql_passwd=mysql密码
mysql_database=数据库
mysql_table_prefix=
mysql_max_idle_conns=10
mysql_max_open_conns=100
mysql_max_life_time=6
# redis配置
redis_host=127.0.0.1
redis_port=6379
redis_passwd=
redis_db=5
redis_pool_size=5
redis_max_retries=3
redis_idle_timeout=1000
# 消息队列配置
queue_concurrency=10
queue_level_critical=6
queue_level_default=3
queue_level_low=1
#机器人Apitoken
tg_bot_token=
#telegram代理url(大陆地区服务器可使用一台国外服务器做反代tg的url)，如果运行的本来就是境外服务器，则无需填写
tg_proxy=
#管理员userid
tg_manage=
#api接口认证token(用于发起交易的签名认证，请勿外泄)
api_auth_token=
#订单过期时间(单位分钟)
order_expiration_time=10
#汇率相关配置请在后台“系统配置 -> 汇率配置”中设置
```
⚠️注意：配置文件里面不认识的不要修改，留空即可，不会改又要瞎改，除非你对项目源代码很熟悉很有信心😁

必填配置项：app_uri、mysql配置、redis配置、api_auth_token

选填配置项：tg_bot_token、tg_manage
## 6、配置supervisor
为了保证`Epusdt`常驻后台运行，我们需要配置`supervisor`来实现进程监听  
```bash
nano /etc/supervisor/conf.d/epusdt.conf
```
你可以参考以下我的配置文件，注意更改路径。
```conf
[program:epusdt]
process_name=epusdt
directory=/var/www/epusdt
command=/var/www/epusdt/epusdt http start
autostart=true
autorestart=true
user=www-data
numprocs=1
redirect_stderr=true
stdout_logfile=/var/log/supervisor/epusdt.log
```
接下来输入命令
```bash
supervisorctl reread
supervisorctl update
supervisorctl start epusdt
supervisorctl tail epusdt
```
出现下图，即为配置成功
```bash
  _____                     _ _   
 | ____|_ __  _   _ ___  __| | |_ 
 |  _| | '_ \| | | / __|/ _` | __|
 | |___| |_) | |_| \__ \ (_| | |_ 
 |_____| .__/ \__,_|___/\__,_|\__|
       |_|                        
Epusdt version(0.0.2) Powered by GMWalletApp https://github.com/GMWalletApp/epusdt
⇨ http server started on [::]:8000
```
## 其他注意事项
- 1.所有`.env`配置文件有了修改后都需要重启supervisor进程 `supervisorctl restart epusdt`
- 2.教程所示的目录均为参考，请勿1:1照抄，根据自己实际情况来
- 3.首次运行的安装向导（`/install`）默认只监听 `127.0.0.1:8000`，因为安装完成前它没有认证。裸机安装时直接在本机浏览器打开 `http://127.0.0.1:8000/install` 即可；如果必须从其它机器访问，显式放开端口：
  ```bash
  EPUSDT_INSTALL_ADDR=:8000 ./epusdt http start
  ```
  初始管理员密码不再通过 HTTP 响应返回，只在控制台输出一次，请及时保存。
- 4.如果前面还有一层 nginx 之类的反向代理，为了让商户 API key 的 IP 白名单和后台登录限制拿到真实客户端地址，在 `.env` 里声明代理地址：
  ```dotenv
  trusted_proxies=127.0.0.1,10.0.0.0/8
  ```
  不配置时只采信来自回环 / 内网对端的 `X-Forwarded-For`、`X-Real-IP`。

