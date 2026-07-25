# LovelyRes 部署检查清单

## 服务器准备

### 环境检查
- [ ] 服务器 IP: 110.42.47.180
- [ ] 操作系统: Ubuntu 20.04+ 或其他 Linux 发行版
- [ ] SSH 访问正常
- [ ] Root 或 sudo 权限

---

## 软件安装

### 必需软件
- [ ] Node.js 18.x 或更高
- [ ] PostgreSQL 14.x 或更高
- [ ] PM2 进程管理器
- [ ] Git（可选）

### 可选软件
- [ ] Nginx（推荐用于反向代理）
- [ ] Certbot（用于 SSL 证书）

---

## 数据库配置

### PostgreSQL
- [ ] PostgreSQL 服务已启动
- [ ] 创建数据库用户 `lovelyres_user`
- [ ] 创建数据库 `lovelyres`
- [ ] 授予用户权限
- [ ] 测试数据库连接

### 数据库密码
- [ ] 使用强密码
- [ ] 记录密码（安全存储）

---

## 应用配置

### 环境变量 (.env)
- [ ] 复制 `.env.production` 到 `.env`
- [ ] 设置数据库密码 `DB_PASSWORD`
- [ ] 生成并设置 JWT 密钥 `JWT_SECRET`
- [ ] 生成并设置 JWT 刷新密钥 `JWT_REFRESH_SECRET`
- [ ] 配置 CORS 来源 `CORS_ORIGIN`
- [ ] 检查其他配置项

### RSA 密钥对
- [ ] 生成 RSA 私钥 `keys/private.pem`
- [ ] 生成 RSA 公钥 `keys/public.pem`
- [ ] 设置私钥权限 `chmod 600`
- [ ] 设置公钥权限 `chmod 644`

### 客户端配置
- [ ] 更新 `src/config/api.config.ts` 中的生产环境 API 地址
- [ ] 重新编译客户端应用

---

## 应用部署

### 代码上传
- [ ] 上传代码到服务器 `/var/www/LovelyRes/server`
- [ ] 检查文件权限

### 依赖安装
- [ ] 运行 `npm install --production`
- [ ] 检查是否有错误

### 编译
- [ ] 运行 `npm run build`
- [ ] 检查 `dist` 目录是否生成

### 数据库初始化
- [ ] 运行 `npm run db:init`
- [ ] 检查数据库表是否创建成功
- [ ] 检查是否有初始数据

---

## 应用启动

### PM2 配置
- [ ] 检查 `ecosystem.config.js` 配置
- [ ] 启动应用 `pm2 start ecosystem.config.js --env production`
- [ ] 检查应用状态 `pm2 status`
- [ ] 查看日志 `pm2 logs lovelyres-api`
- [ ] 设置开机自启 `pm2 startup` 和 `pm2 save`

---

## Nginx 配置（可选）

### 安装和配置
- [ ] 安装 Nginx
- [ ] 复制配置文件到 `/etc/nginx/sites-available/lovelyres`
- [ ] 创建符号链接到 `/etc/nginx/sites-enabled/`
- [ ] 修改配置中的 `server_name`
- [ ] 测试配置 `sudo nginx -t`
- [ ] 重启 Nginx `sudo systemctl restart nginx`

---

## 防火墙配置

### UFW 规则
- [ ] 允许 SSH (22/tcp)
- [ ] 允许 HTTP (80/tcp)
- [ ] 允许 HTTPS (443/tcp)
- [ ] 允许 API 端口 (3000/tcp) - 如果不使用 Nginx
- [ ] 启用防火墙 `sudo ufw enable`
- [ ] 检查状态 `sudo ufw status`

---

## SSL 证书（可选但推荐）

### Let's Encrypt
- [ ] 安装 Certbot
- [ ] 获取 SSL 证书 `sudo certbot --nginx -d yourdomain.com`
- [ ] 测试自动续期 `sudo certbot renew --dry-run`
- [ ] 更新 Nginx 配置使用 HTTPS

---

## 功能测试

### API 测试
- [ ] 健康检查: `curl http://110.42.47.180:3000/health`
- [ ] 注册用户: 测试 `/api/v1/auth/register`
- [ ] 登录: 测试 `/api/v1/auth/login`
- [ ] 获取用户信息: 测试 `/api/v1/users/me`
- [ ] 设备绑定: 测试 `/api/v1/devices/bind`

### 加密测试
- [ ] 公钥获取: 测试 `/api/v1/crypto/public-key`
- [ ] 密钥交换: 测试 `/api/v1/crypto/exchange-key`
- [ ] 加密请求: 测试加密的 API 请求
- [ ] 加密响应: 验证响应是否加密

### 客户端测试
- [ ] 更新客户端 API 配置
- [ ] 重新编译客户端
- [ ] 测试登录功能
- [ ] 测试设备绑定
- [ ] 测试其他功能

---

## 监控和日志

### 日志配置
- [ ] 创建日志目录 `mkdir -p logs`
- [ ] 检查应用日志 `tail -f logs/app.log`
- [ ] 检查 PM2 日志 `pm2 logs lovelyres-api`
- [ ] 检查 Nginx 日志 `tail -f /var/log/nginx/lovelyres-access.log`

### 监控
- [ ] 设置 PM2 监控 `pm2 monit`
- [ ] 配置系统监控（可选）
- [ ] 配置告警（可选）

---

## 备份

### 数据库备份
- [ ] 创建备份脚本 `scripts/backup-db.sh`
- [ ] 设置备份权限 `chmod +x scripts/backup-db.sh`
- [ ] 测试备份脚本
- [ ] 添加到 crontab（每天自动备份）
- [ ] 测试恢复流程

### 代码备份
- [ ] 备份 `.env` 文件（安全存储）
- [ ] 备份 RSA 密钥对（安全存储）
- [ ] 备份应用代码（Git 或其他方式）

---

## 安全加固

### 密码和密钥
- [ ] 使用强密码（数据库、JWT）
- [ ] 定期更换密码
- [ ] 安全存储密钥

### SSH 安全
- [ ] 禁用 root SSH 登录
- [ ] 使用 SSH 密钥认证
- [ ] 修改 SSH 默认端口（可选）

### 应用安全
- [ ] 配置 CORS 白名单
- [ ] 启用 HTTPS
- [ ] 定期更新依赖
- [ ] 定期更新系统

---

## 性能优化

### 应用优化
- [ ] 配置 PM2 集群模式（多实例）
- [ ] 配置 Nginx 缓存
- [ ] 配置 Gzip 压缩
- [ ] 优化数据库查询

### 系统优化
- [ ] 调整系统参数（可选）
- [ ] 配置 swap（如果内存不足）
- [ ] 监控系统资源使用

---

## 文档

### 部署文档
- [ ] 记录部署步骤
- [ ] 记录配置信息
- [ ] 记录常见问题和解决方案

### 运维文档
- [ ] 记录常用命令
- [ ] 记录故障排查步骤
- [ ] 记录备份和恢复流程

---

## 最终检查

### 功能检查
- [ ] 所有 API 端点正常工作
- [ ] 加密功能正常
- [ ] 客户端可以正常连接
- [ ] 数据库操作正常

### 性能检查
- [ ] 响应时间正常
- [ ] 内存使用正常
- [ ] CPU 使用正常
- [ ] 磁盘空间充足

### 安全检查
- [ ] 防火墙配置正确
- [ ] SSL 证书有效（如果使用）
- [ ] 敏感信息已保护
- [ ] 日志记录正常

---

## 上线

### 上线前
- [ ] 通知相关人员
- [ ] 准备回滚方案
- [ ] 备份当前数据

### 上线
- [ ] 启动应用
- [ ] 监控日志
- [ ] 测试关键功能

### 上线后
- [ ] 持续监控 24 小时
- [ ] 收集用户反馈
- [ ] 记录问题和改进点

---

## 维护计划

### 日常维护
- [ ] 每天检查日志
- [ ] 每天检查系统资源
- [ ] 每天检查应用状态

### 定期维护
- [ ] 每周检查备份
- [ ] 每月更新系统
- [ ] 每月更新依赖
- [ ] 每季度审查安全配置

---

## 联系信息

### 技术支持
- 开发者: [您的名字]
- 邮箱: [您的邮箱]
- 电话: [您的电话]

### 服务器信息
- IP: 110.42.47.180
- 服务商: [服务商名称]
- 账号: [账号信息]

---

## 完成日期

- 部署日期: _______________
- 部署人员: _______________
- 验收人员: _______________

---

**祝部署顺利！** 🚀

