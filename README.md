# 小说网站后端示例

## 项目介绍

#### 重庆邮电大学红岩后端研发部作业
#### 项目仅作为作业示例，不保证稳定性和安全性

## 使用
#### 1. 下载

```bash
go build -o main.exe main.go
# 如需其他平台和构架请自行设置GOOS和GOARCH环境变量
```

## 配置

```yaml
port: 8080 # 服务端口
host: 0.0.0.0 # 服务地址
mode: PROD
admin:
  - user_id # 管理员ID
database:
  user: data/user.db # 用户数据库
  book: data/book.db # 书籍数据库
```

## 接口

#### [接口文档](https://www.yuque.com/yuqueyonghucoerlw/tgo818/al6an95f7b9imygx?singleDoc#10d5064a)

说明

- 本项目使用`gin`作为Web框架，`gorm`作为ORM框架，`sqlite`作为数据库，`jwt`作为鉴权方式
- PUT请求时传参`json`，请求头为`Content-Type: application/json`
- 密码使用`sha256`加密储存
- 支持跨域请求
- 接口采用RESTful风格

## 错误码

#### 请自行查看源代码[lib/status.go](lib/status.go)中的`ErrorCode`