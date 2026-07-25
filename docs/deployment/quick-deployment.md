# LovelyRes 快速部署指南

## 服务器信息

- **IP 地址**: 110.42.47.180
- **操作系统**: Linux (Ubuntu 20.04+)

---

## 方法 1: 自动部署脚本（推荐）

### 1. 上传代码到服务器

```bash
# 在本地
cd d:\LovelyRes
scp -r server root@110.42.47.180:/var/www/LovelyRes/ 
```

---

### 2. 运行部署脚本

```bash
# 在服务器上
cd /var/www/LovelyRes/server
chmod +x scripts/deploy.sh
sudo ./scripts/deploy.sh
```

脚本会自动完成以下操作：
- ✅ 更新系统
- ✅ 安装 Node.js 18.x
- ✅ 安装 PostgreSQL
- ✅ 安装 PM2
- ✅ 创建数据库和用户
- ✅ 配置环境变量
- ✅ 生成 RSA 密钥对
- ✅ 安装依赖
- ✅ 编译 TypeScript
- ✅ 初始化数据库
- ✅ 启动应用
- ✅ 配置防火墙

---

## 方法 2: 手动部署

### 1. 安装依赖

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装 Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# 安装 PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# 安装 PM2
sudo npm install -g pm2
```

---

### 2. 配置数据库

```bash
# 切换到 postgres 用户
sudo -u postgres psql

# 创建用户和数据库
CREATE USER lovelyres_user WITH PASSWORD 'your_password';
CREATE DATABASE lovelyres OWNER lovelyres_user;
GRANT ALL PRIVILEGES ON DATABASE lovelyres TO lovelyres_user;
\q
```

---

### 3. 配置应用

```bash
cd /var/www/LovelyRes/server

# 复制环境配置
cp .env.production .env

# 编辑配置文件
nano .env
```

修改以下配置：
- `DB_PASSWORD`: 数据库密码
- `JWT_SECRET`: JWT 密钥
- `JWT_REFRESH_SECRET`: JWT 刷新密钥
- `CORS_ORIGIN`: 允许的跨域来源

---

### 4. 生成 RSA 密钥

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

---

### 5. 安装和编译

```bash
npm install --production
npm run build
```

---

### 6. 初始化数据库

```bash
npm run db:init
```

---

### 7. 启动应用

```bash
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup
```

---

## 配置 Nginx（可选）

### 1. 安装 Nginx

```bash
sudo apt install -y nginx
```

---

### 2. 配置 Nginx

```bash
# 复制配置文件
sudo cp nginx.conf /etc/nginx/sites-available/lovelyres

# 创建符号链接
sudo ln -s /etc/nginx/sites-available/lovelyres /etc/nginx/sites-enabled/

# 测试配置
sudo nginx -t

# 重启 Nginx
sudo systemctl restart nginx
```

---

## 配置防火墙

```bash
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw allow 3000/tcp # API（如果不使用 Nginx）
sudo ufw enable
```

---

## 测试部署

### 1. 健康检查

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

### 2. 测试注册

```bash
curl -X POST http://110.42.47.180:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

---

### 3. 测试登录

```bash
curl -X POST http://110.42.47.180:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

---

## 更新客户端配置

修改客户端 API 配置：

**文件**: `src/modules/api/apiService.ts`

```typescript
const API_CONFIG = {
  baseURL: 'http://110.42.47.180:3000/api/v1',
  timeout: 10000,
};
```

---

## 常用命令

### PM2 命令

```bash
# 查看状态
pm2 status

# 查看日志
pm2 logs lovelyres-api

# 重启应用
pm2 restart lovelyres-api

# 停止应用
pm2 stop lovelyres-api

# 监控
pm2 monit
```

---

### 数据库命令

```bash
# 连接数据库
psql -U lovelyres_user -h localhost -d lovelyres

# 备份数据库
pg_dump -U lovelyres_user -h localhost lovelyres > backup.sql

# 恢复数据库
psql -U lovelyres_user -h localhost lovelyres < backup.sql
```

---

### Nginx 命令

```bash
# 测试配置
sudo nginx -t

# 重启 Nginx
sudo systemctl restart nginx

# 查看日志
sudo tail -f /var/log/nginx/lovelyres-access.log
sudo tail -f /var/log/nginx/lovelyres-error.log
```

---

## 故障排查

### 应用无法启动

```bash
# 查看 PM2 日志
pm2 logs lovelyres-api --lines 100

# 查看应用日志
tail -f /var/www/LovelyRes/server/logs/app.log

# 检查端口占用
sudo netstat -tulpn | grep 3000
```

---

### 数据库连接失败

```bash
# 检查 PostgreSQL 状态
sudo systemctl status postgresql

# 测试数据库连接
psql -U lovelyres_user -h localhost -d lovelyres

# 查看 PostgreSQL 日志
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

---

## 安全建议

1. **修改默认密码**
   - 数据库密码
   - JWT 密钥
   - 服务器 SSH 密码

2. **配置 SSL 证书**
   ```bash
   sudo apt install -y certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```

3. **定期备份数据库**
   - 使用 cron 定时备份
   - 备份到远程服务器

4. **监控日志**
   - 定期查看应用日志
   - 定期查看 Nginx 日志
   - 定期查看系统日志

5. **更新系统**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

---

## 完成！

您的 LovelyRes API 服务器现在已经部署完成！

**访问地址**: http://110.42.47.180:3000

**API 文档**: 参见 `doc/api-documentation.md`

**健康检查**: http://110.42.47.180:3000/health

---

## 下一步

1. ✅ 配置域名（可选）
2. ✅ 配置 SSL 证书（推荐）
3. ✅ 配置 Nginx 反向代理（推荐）
4. ✅ 设置数据库备份
5. ✅ 配置监控和告警
6. ✅ 更新客户端配置

