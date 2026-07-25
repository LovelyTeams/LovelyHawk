# LovelyRes API 文档

## 基本信息

- **Base URL**: `https://api.lovelyres.com/v1`
- **协议**: HTTPS
- **认证方式**: JWT (JSON Web Token)
- **数据格式**: JSON
- **字符编码**: UTF-8

---

## 通用说明

### 请求头

所有需要认证的接口都需要在请求头中携带 JWT token：

```http
Authorization: Bearer <your_jwt_token>
Content-Type: application/json
```

### 响应格式

所有接口统一返回以下格式：

```json
{
  "code": 200,
  "message": "success",
  "data": {},
  "timestamp": 1704902400000
}
```

### 状态码说明

| HTTP 状态码 | 业务码 | 说明 |
|------------|--------|------|
| 200 | 200 | 请求成功 |
| 201 | 201 | 创建成功 |
| 400 | 400 | 请求参数错误 |
| 401 | 401 | 未认证或 token 失效 |
| 403 | 403 | 无权限访问 |
| 404 | 404 | 资源不存在 |
| 409 | 409 | 资源冲突（如用户名已存在） |
| 429 | 429 | 请求过于频繁 |
| 500 | 500 | 服务器内部错误 |

### 错误响应示例

```json
{
  "code": 400,
  "message": "用户名已存在",
  "error": "USERNAME_EXISTS",
  "timestamp": 1704902400000
}
```

---

## 1. 用户认证 API

### 1.1 用户注册

**接口**: `POST /auth/register`

**描述**: 注册新用户账户

**请求参数**:

```json
{
  "username": "testuser",
  "nickname": "测试用户",
  "email": "test@example.com",
  "password": "password123"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| username | string | 是 | 用户名，3-50字符，唯一 |
| nickname | string | 否 | 昵称，最多100字符 |
| email | string | 是 | 邮箱地址，唯一 |
| password | string | 是 | 密码，至少6字符 |

**响应示例**:

```json
{
  "code": 201,
  "message": "注册成功",
  "data": {
    "user": {
      "id": 1,
      "username": "testuser",
      "nickname": "测试用户",
      "email": "test@example.com",
      "is_vip": false,
      "created_at": "2025-01-10T10:00:00Z"
    },
    "token": {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expires_in": 3600
    }
  },
  "timestamp": 1704902400000
}
```

---

### 1.2 用户登录

**接口**: `POST /auth/login`

**描述**: 用户登录获取 token

**请求参数**:

```json
{
  "username": "testuser",
  "password": "password123"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| username | string | 是 | 用户名或邮箱 |
| password | string | 是 | 密码 |

**响应示例**:

```json
{
  "code": 200,
  "message": "登录成功",
  "data": {
    "user": {
      "id": 1,
      "username": "testuser",
      "nickname": "测试用户",
      "email": "test@example.com",
      "is_vip": true,
      "vip_expire_date": "2025-12-31T23:59:59Z",
      "max_devices": 3,
      "device_rebind_count": 0,
      "max_rebind_count": 5
    },
    "token": {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expires_in": 3600
    }
  },
  "timestamp": 1704902400000
}
```

---

### 1.3 刷新 Token

**接口**: `POST /auth/refresh`

**描述**: 使用 refresh_token 刷新 access_token

**请求参数**:

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**响应示例**:

```json
{
  "code": 200,
  "message": "Token 刷新成功",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600
  },
  "timestamp": 1704902400000
}
```

---

### 1.4 用户登出

**接口**: `POST /auth/logout`

**描述**: 用户登出，使 token 失效

**请求头**: 需要 Authorization

**响应示例**:

```json
{
  "code": 200,
  "message": "登出成功",
  "data": null,
  "timestamp": 1704902400000
}
```

---

## 2. 用户信息 API

### 2.1 获取当前用户信息

**接口**: `GET /users/me`

**描述**: 获取当前登录用户的详细信息

**请求头**: 需要 Authorization

**响应示例**:

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 1,
    "username": "testuser",
    "nickname": "测试用户",
    "email": "test@example.com",
    "is_vip": true,
    "vip_expire_date": "2025-12-31T23:59:59Z",
    "max_devices": 3,
    "device_rebind_count": 2,
    "max_rebind_count": 5,
    "status": "active",
    "email_verified": true,
    "created_at": "2025-01-01T00:00:00Z",
    "last_login_at": "2025-01-10T10:00:00Z"
  },
  "timestamp": 1704902400000
}
```

---

### 2.2 更新用户信息

**接口**: `PATCH /users/me`

**描述**: 更新当前用户的基本信息

**请求头**: 需要 Authorization

**请求参数**:

```json
{
  "nickname": "新昵称",
  "email": "newemail@example.com"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| nickname | string | 否 | 新昵称 |
| email | string | 否 | 新邮箱（需要验证） |

**响应示例**:

```json
{
  "code": 200,
  "message": "更新成功",
  "data": {
    "id": 1,
    "username": "testuser",
    "nickname": "新昵称",
    "email": "newemail@example.com",
    "email_verified": false
  },
  "timestamp": 1704902400000
}
```

---

### 2.3 修改密码

**接口**: `POST /users/me/password`

**描述**: 修改当前用户密码

**请求头**: 需要 Authorization

**请求参数**:

```json
{
  "old_password": "oldpassword123",
  "new_password": "newpassword456"
}
```

**响应示例**:

```json
{
  "code": 200,
  "message": "密码修改成功",
  "data": null,
  "timestamp": 1704902400000
}
```

---

## 3. 设备管理 API

### 3.1 获取设备列表

**接口**: `GET /devices`

**描述**: 获取当前用户绑定的所有设备

**请求头**: 需要 Authorization

**查询参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| status | string | 否 | 筛选状态：active, unbound, expired |
| page | integer | 否 | 页码，默认1 |
| page_size | integer | 否 | 每页数量，默认10 |

**响应示例**:

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "devices": [
      {
        "id": 1,
        "device_code": "ABC123XYZ",
        "device_name": "我的电脑",
        "device_type": "windows",
        "bind_status": "active",
        "is_active": true,
        "offline_license_key": "LICENSE-KEY-HERE",
        "license_expire_date": "2025-12-31T23:59:59Z",
        "bound_at": "2025-01-01T00:00:00Z",
        "last_active_at": "2025-01-10T10:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 10,
      "total": 1,
      "total_pages": 1
    }
  },
  "timestamp": 1704902400000
}
```

---

### 3.2 绑定设备

**接口**: `POST /devices`

**描述**: 绑定新设备

**请求头**: 需要 Authorization

**请求参数**:

```json
{
  "device_code": "ABC123XYZ",
  "device_name": "我的电脑",
  "device_type": "windows",
  "device_fingerprint": {
    "cpu": "Intel Core i7",
    "motherboard": "ASUS Z690",
    "mac_address": "00:11:22:33:44:55"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| device_code | string | 是 | 设备唯一标识码 |
| device_name | string | 否 | 设备名称 |
| device_type | string | 否 | 设备类型：windows, linux, macos |
| device_fingerprint | object | 否 | 设备指纹信息 |

**响应示例**:

```json
{
  "code": 201,
  "message": "设备绑定成功",
  "data": {
    "device": {
      "id": 1,
      "device_code": "ABC123XYZ",
      "device_name": "我的电脑",
      "device_type": "windows",
      "bind_status": "active",
      "offline_license_key": "LICENSE-KEY-HERE",
      "license_expire_date": "2025-12-31T23:59:59Z",
      "bound_at": "2025-01-10T10:00:00Z"
    }
  },
  "timestamp": 1704902400000
}
```

---

### 3.3 解绑设备

**接口**: `DELETE /devices/{device_id}`

**描述**: 解绑指定设备

**请求头**: 需要 Authorization

**路径参数**:

| 参数 | 类型 | 说明 |
|------|------|------|
| device_id | integer | 设备ID |

**响应示例**:

```json
{
  "code": 200,
  "message": "设备解绑成功",
  "data": null,
  "timestamp": 1704902400000
}
```

---

### 3.4 换绑设备

**接口**: `POST /devices/rebind`

**描述**: 将旧设备换绑到新设备

**请求头**: 需要 Authorization

**请求参数**:

```json
{
  "old_device_id": 1,
  "new_device_code": "XYZ789ABC",
  "new_device_name": "新电脑",
  "new_device_type": "windows",
  "reason": "更换了新电脑"
}
```

**响应示例**:

```json
{
  "code": 200,
  "message": "设备换绑成功",
  "data": {
    "old_device": {
      "id": 1,
      "device_code": "ABC123XYZ",
      "bind_status": "unbound"
    },
    "new_device": {
      "id": 2,
      "device_code": "XYZ789ABC",
      "device_name": "新电脑",
      "bind_status": "active",
      "offline_license_key": "NEW-LICENSE-KEY",
      "license_expire_date": "2025-12-31T23:59:59Z"
    },
    "remaining_rebind_count": 3
  },
  "timestamp": 1704902400000
}
```

---

### 3.5 获取设备详情

**接口**: `GET /devices/{device_id}`

**描述**: 获取指定设备的详细信息

**请求头**: 需要 Authorization

**响应示例**:

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 1,
    "device_code": "ABC123XYZ",
    "device_name": "我的电脑",
    "device_type": "windows",
    "device_fingerprint": {
      "cpu": "Intel Core i7",
      "motherboard": "ASUS Z690"
    },
    "bind_status": "active",
    "is_active": true,
    "offline_license_key": "LICENSE-KEY-HERE",
    "license_expire_date": "2025-12-31T23:59:59Z",
    "last_license_update": "2025-01-10T10:00:00Z",
    "bound_at": "2025-01-01T00:00:00Z",
    "last_active_at": "2025-01-10T10:00:00Z"
  },
  "timestamp": 1704902400000
}
```

---

## 4. 离线授权 API

### 4.1 生成离线授权

**接口**: `POST /licenses/generate`

**描述**: 为指定设备生成离线授权密钥

**请求头**: 需要 Authorization

**请求参数**:

```json
{
  "device_id": 1,
  "valid_days": 365
}
```

**响应示例**:

```json
{
  "code": 200,
  "message": "授权生成成功",
  "data": {
    "license_key": "LOVELYRES-XXXX-XXXX-XXXX-XXXX",
    "device_code": "ABC123XYZ",
    "valid_from": "2025-01-10T10:00:00Z",
    "valid_until": "2026-01-10T10:00:00Z",
    "license_type": "offline"
  },
  "timestamp": 1704902400000
}
```

---

### 4.2 更新离线授权

**接口**: `POST /licenses/update`

**描述**: 更新设备的离线授权

**请求头**: 需要 Authorization

**请求参数**:

```json
{
  "device_id": 1,
  "reason": "授权即将过期"
}
```

**响应示例**:

```json
{
  "code": 200,
  "message": "授权更新成功",
  "data": {
    "license_key": "LOVELYRES-YYYY-YYYY-YYYY-YYYY",
    "device_code": "ABC123XYZ",
    "valid_from": "2025-01-10T10:00:00Z",
    "valid_until": "2026-01-10T10:00:00Z"
  },
  "timestamp": 1704902400000
}
```

---

### 4.3 验证离线授权

**接口**: `POST /licenses/verify`

**描述**: 验证离线授权密钥是否有效（无需认证）

**请求参数**:

```json
{
  "license_key": "LOVELYRES-XXXX-XXXX-XXXX-XXXX",
  "device_code": "ABC123XYZ"
}
```

**响应示例**:

```json
{
  "code": 200,
  "message": "授权有效",
  "data": {
    "valid": true,
    "license_type": "offline",
    "valid_until": "2026-01-10T10:00:00Z",
    "days_remaining": 365,
    "user_info": {
      "username": "testuser",
      "is_vip": true
    }
  },
  "timestamp": 1704902400000
}
```

---

### 4.4 获取授权历史

**接口**: `GET /licenses/history`

**描述**: 获取离线授权更新历史

**请求头**: 需要 Authorization

**查询参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| device_id | integer | 否 | 筛选指定设备 |
| page | integer | 否 | 页码 |
| page_size | integer | 否 | 每页数量 |

**响应示例**:

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "history": [
      {
        "id": 1,
        "device_code": "ABC123XYZ",
        "license_type": "offline",
        "valid_from": "2025-01-10T10:00:00Z",
        "valid_until": "2026-01-10T10:00:00Z",
        "update_method": "manual",
        "status": "active",
        "created_at": "2025-01-10T10:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 10,
      "total": 1
    }
  },
  "timestamp": 1704902400000
}
```

---

## 5. 历史记录 API

### 5.1 获取设备换绑历史

**接口**: `GET /history/device-bindings`

**描述**: 获取设备绑定/换绑历史记录

**请求头**: 需要 Authorization

**查询参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| action_type | string | 否 | 操作类型：bind, unbind, rebind |
| page | integer | 否 | 页码 |
| page_size | integer | 否 | 每页数量 |

**响应示例**:

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "history": [
      {
        "id": 1,
        "action_type": "rebind",
        "old_device_code": "ABC123XYZ",
        "new_device_code": "XYZ789ABC",
        "device_name": "新电脑",
        "reason": "更换了新电脑",
        "ip_address": "192.168.1.100",
        "created_at": "2025-01-10T10:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 10,
      "total": 1
    }
  },
  "timestamp": 1704902400000
}
```

---

## 附录

### A. 错误码列表

| 错误码 | 说明 |
|--------|------|
| USERNAME_EXISTS | 用户名已存在 |
| EMAIL_EXISTS | 邮箱已存在 |
| INVALID_CREDENTIALS | 用户名或密码错误 |
| TOKEN_EXPIRED | Token 已过期 |
| TOKEN_INVALID | Token 无效 |
| DEVICE_LIMIT_EXCEEDED | 设备数量超过限制 |
| REBIND_LIMIT_EXCEEDED | 换绑次数超过限制 |
| DEVICE_NOT_FOUND | 设备不存在 |
| DEVICE_ALREADY_BOUND | 设备已被绑定 |
| LICENSE_EXPIRED | 授权已过期 |
| LICENSE_INVALID | 授权无效 |
| VIP_REQUIRED | 需要 VIP 权限 |
| VIP_EXPIRED | VIP 已过期 |

### B. 速率限制

| 接口类型 | 限制 |
|---------|------|
| 登录/注册 | 5次/分钟 |
| 一般接口 | 60次/分钟 |
| 授权验证 | 100次/分钟 |

### C. API 路由总览

```
认证相关
├── POST   /auth/register          用户注册
├── POST   /auth/login             用户登录
├── POST   /auth/refresh           刷新 Token
└── POST   /auth/logout            用户登出

用户信息
├── GET    /users/me               获取当前用户信息
├── PATCH  /users/me               更新用户信息
└── POST   /users/me/password      修改密码

设备管理
├── GET    /devices                获取设备列表
├── POST   /devices                绑定设备
├── GET    /devices/{id}           获取设备详情
├── DELETE /devices/{id}           解绑设备
└── POST   /devices/rebind         换绑设备

离线授权
├── POST   /licenses/generate      生成离线授权
├── POST   /licenses/update        更新离线授权
├── POST   /licenses/verify        验证离线授权（公开）
└── GET    /licenses/history       获取授权历史

历史记录
└── GET    /history/device-bindings 获取设备换绑历史
```

---

**文档版本**: 1.0.0
**最后更新**: 2025-01-10
**维护者**: LovelyRes Team

