# Docker 外部挂载配置说明

## 概述

本项目已修改为将数据库和日志文件默认挂载到容器外部的主机目录，便于数据管理和备份。

## 目录结构

### 主机目录挂载
```
项目根目录/
├── data/           # 数据库文件 (SQLite)
├── downloads/      # 用户上传和下载的文件
├── logs/           # 应用日志文件
├── configs/        # 配置文件 (只读挂载)
└── certs/          # SSL证书文件 (只读挂载)
```

### 容器内部目录
```
/app/
├── data/           # 挂载到主机 ./data
├── downloads/      # 挂载到主机 ./downloads
├── logs/           # 挂载到主机 ./logs
├── configs/        # 挂载到主机 ./configs (只读)
├── certs/          # 挂载到主机 ./certs (只读)
└── frontend/       # 前端应用文件
```

## 启动命令

### 标准启动
```bash
docker-compose up -d
```

### 清理版本启动
```bash
docker-compose -f docker-compose.clean.yml up -d
```

## 数据持久化

### 优势
1. **数据可见性**: 可以直接在主机上查看和管理数据文件
2. **备份便利**: 可以直接备份主机目录
3. **调试方便**: 可以直接查看日志文件
4. **数据迁移**: 容器重建时数据不会丢失

### 注意事项
1. **权限问题**: 确保主机目录有正确的读写权限
2. **路径存在**: 确保主机目录存在，否则容器启动可能失败
3. **数据安全**: 主机目录的数据在容器删除后仍然保留

## 目录权限

容器内使用非root用户 (appuser:appgroup, UID:1001) 运行，确保主机目录权限正确：

```bash
# 创建目录并设置权限
mkdir -p data downloads logs
chown -R 1001:1001 data downloads logs
chmod -R 755 data downloads logs
```

## 数据备份

### 备份命令
```bash
# 备份所有数据
tar -czf backup-$(date +%Y%m%d).tar.gz data/ downloads/ logs/

# 仅备份数据库
cp data/fileserver.db backup-fileserver-$(date +%Y%m%d).db
```

### 恢复命令
```bash
# 恢复所有数据
tar -xzf backup-20240101.tar.gz

# 恢复数据库
cp backup-fileserver-20240101.db data/fileserver.db
```

## 故障排除

### 权限问题
如果遇到权限错误，检查目录权限：
```bash
ls -la data/ downloads/ logs/
```

### 目录不存在
如果目录不存在，创建它们：
```bash
mkdir -p data downloads logs configs certs
```

### 容器无法启动
检查挂载点是否正确：
```bash
docker-compose logs fileserver
```

## 迁移指南

### 从 Docker 卷迁移到主机目录
1. 停止容器
2. 导出 Docker 卷数据
3. 创建主机目录
4. 复制数据到主机目录
5. 重新启动容器

```bash
# 停止容器
docker-compose down

# 导出数据 (如果之前使用 Docker 卷)
docker run --rm -v fileserver_data:/data -v $(pwd):/backup alpine tar czf /backup/data-backup.tar.gz -C /data .
docker run --rm -v fileserver_downloads:/downloads -v $(pwd):/backup alpine tar czf /backup/downloads-backup.tar.gz -C /downloads .
docker run --rm -v fileserver_logs:/logs -v $(pwd):/backup alpine tar czf /backup/logs-backup.tar.gz -C /logs .

# 创建主机目录
mkdir -p data downloads logs

# 恢复数据
tar xzf data-backup.tar.gz -C data/
tar xzf downloads-backup.tar.gz -C downloads/
tar xzf logs-backup.tar.gz -C logs/

# 重新启动
docker-compose up -d
```
