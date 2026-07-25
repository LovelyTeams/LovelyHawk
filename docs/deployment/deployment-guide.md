# LovelyRes 服务器部署指南

## 服务器信息

- **IP 地址**: 110.42.47.180
- **操作系统**: Linux (推荐 Ubuntu 20.04+)
- **Node.js 版本**: 18.x 或更高
- **PostgreSQL 版本**: 14.x 或更高

---

## 1. 服务器环境准备

### 1.1 更新系统

```bash
sudo apt update
sudo apt upgrade -y
```

---

### 1.2 安装 Node.js

```bash
# 安装 Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# 验证安装
node --version
npm --version
```

---

### 1.3 安装 PostgreSQL

```bash
# 安装 PostgreSQL 14
sudo apt install -y postgresql postgresql-contrib

# 启动 PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# 验证安装
sudo -u postgres psql --version
```

---

### 1.4 安装 PM2（进程管理器）

```bash
sudo npm install -g pm2

# 验证安装
pm2 --version
```

---

### 1.5 安装 Nginx（可选，用于反向代理）

```bash
sudo apt install -y nginx

# 启动 Nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

---

## 2. 数据库配置

### 2.1 创建数据库用户

```bash
# 切换到 postgres 用户
sudo -u postgres psql

# 在 PostgreSQL 中执行以下命令
CREATE USER lovelyres_user WITH PASSWORD 'your_secure_password_here';
CREATE DATABASE lovelyres OWNER lovelyres_user;
GRANT ALL PRIVILEGES ON DATABASE lovelyres TO lovelyres_user;

# 退出
\q
```

---

### 2.2 配置 PostgreSQL 远程访问（如果需要）

编辑 `/etc/postgresql/14/main/postgresql.conf`:

```bash
sudo nano /etc/postgresql/14/main/postgresql.conf
```

找到并修改：

```
listen_addresses = 'localhost'  # 改为 '*' 允许所有 IP
```

编辑 `/etc/postgresql/14/main/pg_hba.conf`:

```bash
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

添加：

```
host    all             all             0.0.0.0/0               md5
```

重启 PostgreSQL:

```bash
sudo systemctl restart postgresql
```

---

## 3. 部署应用

### 3.1 上传代码到服务器

**方法 1: 使用 Git**

```bash
# 在服务器上
cd /var/www
sudo git clone https://github.com/yourusername/LovelyRes.git
cd LovelyRes/server
```

**方法 2: 使用 SCP**

```bash
# 在本地
cd d:\LovelyRes
scp -r server root@110.42.47.180:/var/www/LovelyRes/
```

---

### 3.2 安装依赖

```bash
cd /var/www/LovelyRes/server
npm install --production
```

---

### 3.3 配置环境变量

```bash
# 复制生产环境配置
cp .env.production .env

# 编辑配置文件
nano .env
```

**重要**: 修改以下配置：

```env
# 数据库密码
DB_PASSWORD=your_secure_password_here

# JWT 密钥（使用强随机字符串）
JWT_SECRET=your_jwt_secret_key_here_change_this_in_production
JWT_REFRESH_SECRET=your_jwt_refresh_secret_key_here_change_this_in_production

# CORS 配置（添加您的域名）
CORS_ORIGIN=http://110.42.47.180:3000,https://yourdomain.com
```

---

### 3.4 生成 RSA 密钥对

```bash
# 创建 keys 目录
mkdir -p keys

# 生成 RSA 密钥对
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# 设置权限
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

---

### 3.5 编译 TypeScript

```bash
npm run build
```

---

### 3.6 初始化数据库

```bash
npm run db:init
```

---

## 4. 启动应用

### 4.1 使用 PM2 启动

```bash
# 启动应用
pm2 start ecosystem.config.js --env production

# 查看状态
pm2 status

# 查看日志
pm2 logs lovelyres-api

# 设置开机自启
pm2 startup
pm2 save
```

---

### 4.2 PM2 常用命令

```bash
# 重启应用
pm2 restart lovelyres-api

# 停止应用
pm2 stop lovelyres-api

# 删除应用
pm2 delete lovelyres-api

# 查看详细信息
pm2 show lovelyres-api

# 监控
pm2 monit
```

---

## 5. 配置 Nginx 反向代理（可选）

### 5.1 创建 Nginx 配置

```bash
sudo nano /etc/nginx/sites-available/lovelyres
```

添加以下内容：

```nginx
server {
    listen 80;
    server_name 110.42.47.180;

    # 日志
    access_log /var/log/nginx/lovelyres-access.log;
    error_log /var/log/nginx/lovelyres-error.log;

    # API 代理
    location /api/ {
        proxy_pass http://localhost:3000/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # 健康检查
    location /health {
        proxy_pass http://localhost:3000/health;
    }
}
```

---

### 5.2 启用配置

```bash
# 创建符号链接
sudo ln -s /etc/nginx/sites-available/lovelyres /etc/nginx/sites-enabled/

# 测试配置
sudo nginx -t

# 重启 Nginx
sudo systemctl restart nginx
```

---

## 6. 配置防火墙

### 6.1 使用 UFW

```bash
# 启用 UFW
sudo ufw enable

# 允许 SSH
sudo ufw allow 22/tcp

# 允许 HTTP
sudo ufw allow 80/tcp

# 允许 HTTPS
sudo ufw allow 443/tcp

# 允许 API 端口（如果不使用 Nginx）
sudo ufw allow 3000/tcp

# 允许 PostgreSQL（如果需要远程访问）
sudo ufw allow 5432/tcp

# 查看状态
sudo ufw status
```

---

## 7. SSL 证书配置（可选）

### 7.1 使用 Let's Encrypt

```bash
# 安装 Certbot
sudo apt install -y certbot python3-certbot-nginx

# 获取证书
sudo certbot --nginx -d yourdomain.com

# 自动续期
sudo certbot renew --dry-run
```

---

## 8. 监控和日志

### 8.1 查看应用日志

```bash
# PM2 日志
pm2 logs lovelyres-api

# 应用日志
tail -f /var/www/LovelyRes/server/logs/app.log

# Nginx 日志
tail -f /var/log/nginx/lovelyres-access.log
tail -f /var/log/nginx/lovelyres-error.log
```

---

### 8.2 监控系统资源

```bash
# PM2 监控
pm2 monit

# 系统资源
htop
```

---

## 9. 更新应用

### 9.1 更新代码

```bash
cd /var/www/LovelyRes/server

# 拉取最新代码
git pull

# 安装依赖
npm install --production

# 编译
npm run build

# 重启应用
pm2 restart lovelyres-api
```

---

## 10. 备份

### 10.1 数据库备份

```bash
# 创建备份脚本
nano /var/www/LovelyRes/server/scripts/backup-db.sh
```

添加以下内容：

```bash
#!/bin/bash

# 备份目录
BACKUP_DIR="/var/backups/lovelyres"
DATE=$(date +%Y%m%d_%H%M%S)

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份数据库
pg_dump -U lovelyres_user -h localhost lovelyres > $BACKUP_DIR/lovelyres_$DATE.sql

# 压缩备份
gzip $BACKUP_DIR/lovelyres_$DATE.sql

# 删除 7 天前的备份
find $BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete

echo "Backup completed: lovelyres_$DATE.sql.gz"
```

设置权限并添加到 crontab:

```bash
chmod +x /var/www/LovelyRes/server/scripts/backup-db.sh

# 添加到 crontab（每天凌晨 2 点备份）
crontab -e
```

添加：

```
0 2 * * * /var/www/LovelyRes/server/scripts/backup-db.sh
```

---

## 11. 故障排查

### 11.1 应用无法启动

```bash
# 查看 PM2 日志
pm2 logs lovelyres-api --lines 100

# 查看应用日志
tail -f /var/www/LovelyRes/server/logs/app.log

# 检查端口占用
sudo netstat -tulpn | grep 3000
```

---

### 11.2 数据库连接失败

```bash
# 检查 PostgreSQL 状态
sudo systemctl status postgresql

# 测试数据库连接
psql -U lovelyres_user -h localhost -d lovelyres

# 查看 PostgreSQL 日志
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

---

### 11.3 Nginx 错误

```bash
# 测试配置
sudo nginx -t

# 查看错误日志
sudo tail -f /var/log/nginx/error.log

# 重启 Nginx
sudo systemctl restart nginx
```

---

## 12. 安全建议

1. **定期更新系统和软件包**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **使用强密码**
   - 数据库密码
   - JWT 密钥
   - 服务器 SSH 密码

3. **禁用 root SSH 登录**
   ```bash
   sudo nano /etc/ssh/sshd_config
   # 设置 PermitRootLogin no
   sudo systemctl restart sshd
   ```

4. **使用 SSH 密钥认证**

5. **定期备份数据库**

6. **监控日志和系统资源**

7. **使用 HTTPS（SSL 证书）**

---

## 13. 测试部署

### 13.1 健康检查

```bash
curl http://110.42.47.180:3000/health
```

预期响应：

```json
{
  "status": "ok",
  "timestamp": 1704902400000
}
```

---

### 13.2 测试 API

```bash
# 注册用户
curl -X POST http://110.42.47.180:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'

# 登录
curl -X POST http://110.42.47.180:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

---

## 14. 客户端配置

修改客户端 API 配置：

**文件**: `src/modules/api/apiService.ts`

```typescript
const API_CONFIG = {
  baseURL: 'http://110.42.47.180:3000/api/v1',
  timeout: 10000,
};
```

---

## 完成！

您的 LovelyRes API 服务器现在已经部署完成！

**访问地址**: http://110.42.47.180:3000

**API 文档**: http://110.42.47.180:3000/api/v1

**健康检查**: http://110.42.47.180:3000/health

