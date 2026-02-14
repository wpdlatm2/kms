#!/bin/bash
# KMIP 자동 백업 스케줄러
# /backup 디렉토리에 주기적으로 백업하고 오래된 백업 자동 삭제

set -e

# 설정
BACKUP_DIR="/backup"
SOURCE_DATA_DIR="/app/data"
SOURCE_CONFIG_DIR="/app/config"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}  # 기본 30일
MAX_BACKUPS=${MAX_BACKUPS:-10}                # 최대 백업 개수
NODE_ID=${NODE_ID:-"unknown"}
CLUSTER_ID=${CLUSTER_ID:-"default"}

# 로그
LOG_FILE="/app/logs/backup.log"

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 로그 함수
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" | tee -a ${LOG_FILE}
}

log_info() {
    log "INFO" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_warn() {
    log "WARN" "$@"
}

# 백업 디렉토리 생성
ensure_backup_dir() {
    if [ ! -d "${BACKUP_DIR}" ]; then
        mkdir -p "${BACKUP_DIR}"
        log_info "Created backup directory: ${BACKUP_DIR}"
    fi
}

# 백업 실행
perform_backup() {
    local timestamp=$(date '+%Y%m%d-%H%M%S')
    local backup_name="${CLUSTER_ID}-${NODE_ID}-${timestamp}"
    local backup_file="${BACKUP_DIR}/${backup_name}.tar.gz"
    local temp_dir="/tmp/backup-${timestamp}"
    
    log_info "Starting backup: ${backup_name}"
    
    # 임시 디렉토리 생성
    mkdir -p ${temp_dir}
    
    # 데이터 복사
    if [ -d "${SOURCE_DATA_DIR}" ]; then
        cp -r ${SOURCE_DATA_DIR} ${temp_dir}/data
        log_info "Data directory copied"
    else
        log_warn "Data directory not found: ${SOURCE_DATA_DIR}"
    fi
    
    # 설정 복사
    if [ -d "${SOURCE_CONFIG_DIR}" ]; then
        cp -r ${SOURCE_CONFIG_DIR} ${temp_dir}/config
        log_info "Config directory copied"
    fi
    
    # 메타데이터 생성
    cat > ${temp_dir}/backup-metadata.json << EOF
{
  "cluster_id": "${CLUSTER_ID}",
  "node_id": "${NODE_ID}",
  "timestamp": "${timestamp}",
  "backup_date": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "data_size": "$(du -sh ${SOURCE_DATA_DIR} 2>/dev/null | cut -f1 || echo 'N/A')"
}
EOF
    
    # 압축
    log_info "Compressing backup..."
    cd ${temp_dir}
    tar -czf ${backup_file} .
    cd - > /dev/null
    
    # 임시 디렉토리 삭제
    rm -rf ${temp_dir}
    
    # 백업 크기 확인
    local backup_size=$(du -h ${backup_file} | cut -f1)
    log_info "Backup completed: ${backup_file} (${backup_size})"
    
    # 백업 검증
    if tar -tzf ${backup_file} > /dev/null 2>&1; then
        log_info "Backup verification: OK"
        echo ${backup_file}
    else
        log_error "Backup verification: FAILED"
        rm -f ${backup_file}
        return 1
    fi
}

# 오래된 백업 삭제 (날짜 기준)
cleanup_old_backups_by_date() {
    log_info "Cleaning up backups older than ${RETENTION_DAYS} days..."
    
    local deleted_count=0
    
    # RETENTION_DAYS 이전 파일 찾기
    find ${BACKUP_DIR} -name "${CLUSTER_ID}-${NODE_ID}-*.tar.gz" -type f -mtime +${RETENTION_DAYS} | while read file; do
        log_info "Deleting old backup: $(basename ${file})"
        rm -f ${file}
        deleted_count=$((deleted_count + 1))
    done
    
    if [ ${deleted_count} -gt 0 ]; then
        log_info "Deleted ${deleted_count} old backups"
    else
        log_info "No old backups to delete"
    fi
}

# 오래된 백업 삭제 (개수 기준)
cleanup_old_backups_by_count() {
    log_info "Maintaining maximum ${MAX_BACKUPS} backups..."
    
    # 백업 파일 개수 확인
    local backup_count=$(find ${BACKUP_DIR} -name "${CLUSTER_ID}-${NODE_ID}-*.tar.gz" -type f | wc -l)
    
    if [ ${backup_count} -le ${MAX_BACKUPS} ]; then
        log_info "Current backups: ${backup_count}/${MAX_BACKUPS}"
        return
    fi
    
    # 초과된 개수만큼 오래된 백업 삭제
    local to_delete=$((backup_count - MAX_BACKUPS))
    log_info "Deleting ${to_delete} oldest backups..."
    
    find ${BACKUP_DIR} -name "${CLUSTER_ID}-${NODE_ID}-*.tar.gz" -type f -printf '%T+ %p\n' | \
        sort | head -n ${to_delete} | cut -d' ' -f2- | while read file; do
        log_info "Deleting: $(basename ${file})"
        rm -f ${file}
    done
}

# 백업 목록 조회
list_backups() {
    log_info "Available backups for ${CLUSTER_ID}-${NODE_ID}:"
    
    find ${BACKUP_DIR} -name "${CLUSTER_ID}-${NODE_ID}-*.tar.gz" -type f -printf '%T+ %p %s\n' | \
        sort -r | while read timestamp file size; do
        local backup_date=$(echo ${timestamp} | cut -d+ -f1)
        local file_size=$(numfmt --to=iec ${size} 2>/dev/null || echo "${size}B")
        echo "  ${backup_date} - $(basename ${file}) (${file_size})"
    done
}

# 백업 통계
backup_stats() {
    local total_backups=$(find ${BACKUP_DIR} -name "${CLUSTER_ID}-${NODE_ID}-*.tar.gz" -type f | wc -l)
    local total_size=$(du -sh ${BACKUP_DIR} 2>/dev/null | cut -f1 || echo "0")
    local oldest_backup=$(find ${BACKUP_DIR} -name "${CLUSTER_ID}-${NODE_ID}-*.tar.gz" -type f -printf '%T+ %f\n' | sort | head -1 | cut -d' ' -f2-)
    local newest_backup=$(find ${BACKUP_DIR} -name "${CLUSTER_ID}-${NODE_ID}-*.tar.gz" -type f -printf '%T+ %f\n' | sort -r | head -1 | cut -d' ' -f2-)
    
    log_info "=== Backup Statistics ==="
    log_info "Total backups: ${total_backups}"
    log_info "Total size: ${total_size}"
    log_info "Oldest: ${oldest_backup}"
    log_info "Newest: ${newest_backup}"
    log_info "Retention: ${RETENTION_DAYS} days"
    log_info "Max count: ${MAX_BACKUPS}"
}

# 메인 실행
main() {
    local action=${1:-backup}
    
    case ${action} in
        backup)
            ensure_backup_dir
            perform_backup
            cleanup_old_backups_by_date
            cleanup_old_backups_by_count
            backup_stats
            ;;
        cleanup)
            cleanup_old_backups_by_date
            cleanup_old_backups_by_count
            ;;
        list)
            list_backups
            ;;
        stats)
            backup_stats
            ;;
        *)
            echo "Usage: $0 {backup|cleanup|list|stats}"
            exit 1
            ;;
    esac
}

# 실행
main "$@"
