#!/bin/bash

# Secure File Hub - 数据备份脚本

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# 备份函数
backup_data() {
    local backup_type=$1
    local timestamp=$(date +%Y%m%d-%H%M%S)
    
    case $backup_type in
        "all")
            log_info "创建完整数据备份..."
            local backup_file="backup-full-${timestamp}.tar.gz"
            tar -czf "$backup_file" data/ downloads/ logs/ configs/ certs/
            log_success "完整备份创建完成: $backup_file"
            ;;
        "data")
            log_info "仅备份数据库..."
            local backup_file="backup-database-${timestamp}.db"
            cp data/fileserver.db "$backup_file"
            log_success "数据库备份创建完成: $backup_file"
            ;;
        "files")
            log_info "仅备份用户文件..."
            local backup_file="backup-files-${timestamp}.tar.gz"
            tar -czf "$backup_file" downloads/
            log_success "用户文件备份创建完成: $backup_file"
            ;;
        *)
            log_error "未知的备份类型: $backup_type"
            show_usage
            exit 1
            ;;
    esac
}

# 恢复函数
restore_data() {
    local backup_file=$1
    
    if [[ ! -f "$backup_file" ]]; then
        log_error "备份文件不存在: $backup_file"
        exit 1
    fi
    
    log_warning "恢复操作将覆盖现有数据，确定要继续吗？(y/N)"
    read -r confirm
    if [[ $confirm != [yY] ]]; then
        log_info "恢复操作已取消"
        exit 0
    fi
    
    log_info "停止服务..."
    docker-compose stop
    
    if [[ "$backup_file" == *.tar.gz ]]; then
        log_info "从压缩包恢复数据..."
        tar -xzf "$backup_file"
    elif [[ "$backup_file" == *.db ]]; then
        log_info "恢复数据库文件..."
        cp "$backup_file" data/fileserver.db
    else
        log_error "不支持的备份文件格式"
        exit 1
    fi
    
    log_info "重新设置权限..."
    sudo chown -R 1001:1001 data downloads logs
    
    log_info "重新启动服务..."
    docker-compose start
    
    log_success "数据恢复完成"
}

# 清理旧备份
cleanup_backups() {
    local days=${1:-7}
    
    log_info "清理 ${days} 天前的备份文件..."
    
    find . -name "backup-*" -type f -mtime +${days} -delete
    
    log_success "旧备份文件清理完成"
}

# 显示用法
show_usage() {
    echo "用法: $0 <命令> [选项]"
    echo ""
    echo "命令:"
    echo "  backup <类型>    创建备份"
    echo "    all            完整备份（数据库、文件、配置）"
    echo "    data           仅备份数据库"
    echo "    files          仅备份用户文件"
    echo ""
    echo "  restore <文件>   从备份恢复数据"
    echo ""
    echo "  cleanup [天数]   清理旧备份文件（默认7天）"
    echo ""
    echo "  list            列出所有备份文件"
    echo ""
    echo "示例:"
    echo "  $0 backup all                    # 创建完整备份"
    echo "  $0 backup data                   # 仅备份数据库"
    echo "  $0 restore backup-full-20240101-120000.tar.gz"
    echo "  $0 cleanup 30                    # 清理30天前的备份"
}

# 列出备份文件
list_backups() {
    log_info "现有备份文件:"
    echo ""
    
    local backup_files=(backup-*)
    if [[ -e "${backup_files[0]}" ]]; then
        for file in backup-*; do
            if [[ -f "$file" ]]; then
                local size=$(du -h "$file" | cut -f1)
                local date=$(stat -c %y "$file" | cut -d' ' -f1,2 | cut -d'.' -f1)
                printf "  %-50s %8s  %s\n" "$file" "$size" "$date"
            fi
        done
    else
        log_info "  没有找到备份文件"
    fi
    echo ""
}

# 主函数
main() {
    local command=$1
    
    case $command in
        "backup")
            backup_data $2
            ;;
        "restore")
            restore_data $2
            ;;
        "cleanup")
            cleanup_backups $2
            ;;
        "list")
            list_backups
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"