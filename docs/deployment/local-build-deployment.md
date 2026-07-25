# 本地构建 + 服务器部署指南

本指南介绍如何在本地构建项目，然后上传到服务器部署。

---

## 优势

相比在服务器上构建，本地构建有以下优势：

✅ **更快的部署速度** - 不需要在服务器上编译 TypeScript  
✅ **减少服务器资源消耗** - 不需要安装开发依赖  
✅ **本地测试** - 可以在本地测试构建结果  
✅ **更小的上传体积** - 只上传必要的文件  

---

## 前置要求

### 本地环境
- Node.js 18.x 或更高
- npm 或 yarn
- SSH 客户端（用于上传文件）

### 服务器环境
- Node.js 18.x 或更高
- PostgreSQL 14.x 或更高
- PM2 进程管理器

---

## 快速部署

### Windows 用户

```powershell
cd server
.\scripts\build-and-deploy.ps1
```

### Linux/Mac 用户

```bash
cd server
chmod +x scripts/build-and-deploy.sh
./scripts/build-and-deploy.sh
```

---

## 自定义参数

### Windows

```powershell
.\scripts\build-and-deploy.ps1 -ServerIP "110.42.47.180" -ServerUser "root" -ServerPath "/var/www/LovelyRes/server"
```

### Linux/Mac

```bash
./scripts/build-and-deploy.sh 110.42.47.180 root /var/www/LovelyRes/server
```

---

## 部署流程详解

### 1. 本地构建

脚本会自动执行以下步骤：

```bash
# 清理旧的构建
rm -rf dist

# 安装依赖
npm install

# 构建项目
npm run build
```

---

### 2. 准备部署文件

脚本会创建临时目录并复制以下文件：

```
deploy-temp/
├── dist/                    # 编译后的 JavaScript 文件
├── package.json             # 依赖配置
├── package-lock.json        # 依赖锁定文件
├── ecosystem.config.js      # PM2 配置
├── .env.production          # 生产环境配置模板
├── keys/                    # RSA 密钥对（如果存在）
│   ├── private.pem
│   └── public.pem
└── scripts/                 # 脚本文件
    └── *.sh
```

---

### 3. 上传到服务器

使用 `scp` 或 `rsync` 上传文件到服务器：

```bash
# Windows (scp)
scp -r deploy-temp\* root@110.42.47.180:/var/www/LovelyRes/server/

# Linux/Mac (rsync，更快)
rsync -avz --delete deploy-temp/ root@110.42.47.180:/var/www/LovelyRes/server/
```

---

### 4. 服务器端配置

脚本会在服务器上自动执行：

```bash
# 安装生产依赖（不包括开发依赖）
npm install --production

# 配置环境变量
if [ ! -f .env ]; then
    cp .env.production .env
fi

# 生成 RSA 密钥对（如果不存在）
if [ ! -f keys/private.pem ]; then
    mkdir -p keys
    openssl genrsa -out keys/private.pem 2048
    openssl rsa -in keys/private.pem -pubout -out keys/public.pem
    chmod 600 keys/private.pem
    chmod 644 keys/public.pem
fi

# 初始化数据库
npm run db:init

# 启动应用
pm2 delete lovelyres-api 2>/dev/null || true
pm2 start ecosystem.config.js --env production
pm2 save
```

---

## 手动部署步骤

如果不想使用自动脚本，可以手动执行以下步骤：

### 1. 本地构建

```bash
cd server
npm install
npm run build
```

---

### 2. 上传文件

**Windows (PowerShell)**:

```powershell
# 上传 dist 目录
scp -r dist root@110.42.47.180:/var/www/LovelyRes/server/

# 上传配置文件
scp package.json root@110.42.47.180:/var/www/LovelyRes/server/
scp package-lock.json root@110.42.47.180:/var/www/LovelyRes/server/
scp ecosystem.config.js root@110.42.47.180:/var/www/LovelyRes/server/
scp .env.production root@110.42.47.180:/var/www/LovelyRes/server/

# 上传 keys 目录（如果存在）
scp -r keys root@110.42.47.180:/var/www/LovelyRes/server/
```

**Linux/Mac**:

```bash
# 使用 rsync 一次性上传所有文件
rsync -avz --include='dist/' --include='package*.json' --include='ecosystem.config.js' --include='.env.production' --include='keys/' --exclude='*' ./ root@110.42.47.180:/var/www/LovelyRes/server/
```

---

### 3. 服务器端配置

```bash
# SSH 连接到服务器
ssh root@110.42.47.180

# 进入项目目录
cd /var/www/LovelyRes/server

# 安装生产依赖
npm install --production

# 配置环境变量
cp .env.production .env
nano .env  # 编辑配置

# 生成 RSA 密钥对（如果不存在）
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem
chmod 644 keys/public.pem

# 初始化数据库
npm run db:init

# 启动应用
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup
```

---

## 配置环境变量

部署后，需要修改服务器上的 `.env` 文件：

```bash
ssh root@110.42.47.180
cd /var/www/LovelyRes/server
nano .env
```

**必须修改的配置**:

```env
# 数据库密码
DB_PASSWORD=your_secure_password_here

# JWT 密钥（使用强随机字符串）
JWT_SECRET=your_jwt_secret_key_here
JWT_REFRESH_SECRET=your_jwt_refresh_secret_key_here

# CORS 配置
CORS_ORIGIN=http://110.42.47.180:3000,https://yourdomain.com
```

**生成随机密钥**:

```bash
# 生成 JWT 密钥
openssl rand -base64 32

# 生成 JWT 刷新密钥
openssl rand -base64 32
```

修改完成后，重启应用：

```bash
pm2 restart lovelyres-api
```

---

## 更新应用

当代码有更新时，重新运行部署脚本即可：

### Windows

```powershell
cd server
.\scripts\build-and-deploy.ps1
```

### Linux/Mac

```bash
cd server
./scripts/build-and-deploy.sh
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

### 2. 测试 API

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

## 常用命令

### 查看应用状态

```bash
ssh root@110.42.47.180 'pm2 status'
```

---

### 查看日志

```bash
ssh root@110.42.47.180 'pm2 logs lovelyres-api'
```

---

### 重启应用

```bash
ssh root@110.42.47.180 'pm2 restart lovelyres-api'
```

---

### 停止应用

```bash
ssh root@110.42.47.180 'pm2 stop lovelyres-api'
```

---

## 故障排查

### 1. 上传失败

**问题**: `scp: Permission denied`

**解决方案**:
- 检查 SSH 密钥是否配置正确
- 检查服务器用户权限
- 尝试使用密码登录

---

### 2. 应用无法启动

**问题**: PM2 显示应用状态为 `errored`

**解决方案**:
```bash
# 查看日志
ssh root@110.42.47.180 'pm2 logs lovelyres-api --lines 100'

# 检查配置
ssh root@110.42.47.180 'cat /var/www/LovelyRes/server/.env'
```

---

### 3. 数据库连接失败

**问题**: `Error: connect ECONNREFUSED`

**解决方案**:
```bash
# 检查 PostgreSQL 状态
ssh root@110.42.47.180 'sudo systemctl status postgresql'

# 测试数据库连接
ssh root@110.42.47.180 'psql -U lovelyres_user -h localhost -d lovelyres'
```

---

## 安全建议

1. **使用 SSH 密钥认证**
   ```bash
   # 生成 SSH 密钥
   ssh-keygen -t rsa -b 4096
   
   # 复制公钥到服务器
   ssh-copy-id root@110.42.47.180
   ```

2. **使用强密码**
   - 数据库密码
   - JWT 密钥
   - 服务器 SSH 密码

3. **定期更新**
   - 定期更新系统
   - 定期更新依赖
   - 定期备份数据库

---

## 完成！

您的 LovelyRes API 服务器现在已经部署完成！

**访问地址**: http://110.42.47.180:3000

**API 文档**: 参见 `doc/api-documentation.md`

**健康检查**: http://110.42.47.180:3000/health

