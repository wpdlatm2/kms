#!/bin/bash
# KMIP 로그 로테이션 및 자동 삭제 스크립트

set -e

# 설정
LOG_DIR=${LOG_DIR:-"/app/logs"}
MAX_LOG_SIZE=${MAX_LOG_SIZE:-"100M"}      # 최대 로그 크기
MAX_LOG_AGE=${MAX_LOG_AGE:-7}             # 로그 보관 기간 (일)
MAX_LOG_BACKUPS=${MAX_LOG_BACKUPS:-10}    # 최대 백업 개수
COMPRESS_LOGS=${COMPRESS_LOGS:-"true"}    # 압축 여부

# 로그 파일 패턴
LOG_PATTERNS=("*.log" "node-*.log" "backup.log" "rotation.log")

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 로그 함수
ROTATION_LOG="${LOG_DIR}/rotation.log"

log_rotation() {
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [ROTATION] ${message}" | tee -a ${ROTATION_LOG}
}

# 로그 크기 확인
get_log_size() {
    local file=$1
    if [ -f "${file}" ]; then
        stat -f%z "${file}" 2>/dev/null || stat -c%s "${file}" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# 크기를 바이트로 변환
parse_size() {
    local size=$1
    echo ${size} | awk '
        /[0-9]$/{print $1;next};
        /[0-9][Kk]$/{printf "%.0f", $1 * 1024;next};
        /[0-9][Mm]$/{printf "%.0f", $1 * 1024 * 1024;next};
        /[0-9][Gg]$/{printf "%.0f", $1 * 1024 * 1024 * 1024;next};
    '
}

# 로그 로테이션 실행
rotate_log() {
    local log_file=$1
    local timestamp=$(date '+%Y%m%d-%H%M%S')
    
    if [ ! -f "${log_file}" ]; then
        return
    fi
    
    # 현재 로그 크기 확인
    local current_size=$(get_log_size "${log_file}")
    local max_size_bytes=$(parse_size ${MAX_LOG_SIZE})
    
    if [ ${current_size} -lt ${max_size_bytes} ]; then
        return
    fi
    
    log_rotation "Rotating ${log_file} (size: $(numfmt --to=iec ${current_size}))"
    
    # 백업 파일명
    local rotated_file="${log_file}.${timestamp}"
    
    # 로그 파일 이동
    mv "${log_file}" "${rotated_file}"
    
    # 새 로그 파일 생성
    touch "${log_file}"
    
    # 압축
    if [ "${COMPRESS_LOGS}" = "true" ]; then
        log_rotation "Compressing ${rotated_file}..."
        gzip "${rotated_file}"
        rotated_file="${rotated_file}.gz"
    fi
    
    log_rotation "Rotated to $(basename ${rotated_file})"
}

# 오래된 로그 삭제 (날짜 기준)
cleanup_old_logs_by_date() {
    log_rotation "Cleaning up logs older than ${MAX_LOG_AGE} days..."
    
    local deleted_count=0
    
    # .gz 압축 파일
    find ${LOG_DIR} -name "*.log.*.gz" -type f -mtime +${MAX_LOG_AGE} | while read file; do
        log_rotation "Deleting old log: $(basename ${file})"
        rm -f ${file}
        deleted_count=$((deleted_count + 1))
    done
    
    # 압축되지 않은 백업 로그
    find ${LOG_DIR} -name "*.log.*[0-9]" ! -name "*.gz" -type f -mtime +${MAX_LOG_AGE} | while read file; do
        log_rotation "Deleting old log: $(basename ${file})"
        rm -f ${file}
        deleted_count=$((deleted_count + 1))
    done
    
    if [ ${deleted_count} -gt 0 ]; then
        log_rotation "Deleted ${deleted_count} old logs"
    fi
}

# 오래된 로그 삭제 (개수 기준)
cleanup_old_logs_by_count() {
    for pattern in "${LOG_PATTERNS[@]}"; do
        local base_name=$(echo ${pattern} | sed 's/\*//')
        
        # 각 로그 파일의 백업 개수 확인
        for log_file in ${LOG_DIR}/${pattern}; do
            if [ ! -f "${log_file}" ]; then
                continue
            fi
            
            local backup_count=$(find ${LOG_DIR} -name "$(basename ${log_file}).*" -type f | wc -l)
            
            if [ ${backup_count} -le ${MAX_LOG_BACKUPS} ]; then
                continue
            fi
            
            # 초과된 개수만큼 삭제
            local to_delete=$((backup_count - MAX_LOG_BACKUPS))
            log_rotation "Deleting ${to_delete} oldest backups for $(basename ${log_file})..."
            
            find ${LOG_DIR} -name "$(basename ${log_file}).*" -type f -printf '%T+ %p\n' | \
                sort | head -n ${to_delete} | cut -d' ' -f2- | while read file; do
                log_rotation "Deleting: $(basename ${file})"
                rm -f ${file}
            done
        done
    done
}

# 로그 통계
log_stats() {
    log_rotation "=== Log Statistics ==="
    
    # 현재 로그 파일
    for pattern in "${LOG_PATTERNS[@]}"; do
        for log_file in ${LOG_DIR}/${pattern}; do
            if [ -f "${log_file}" ]; then
                local size=$(get_log_size "${log_file}")
                local size_human=$(numfmt --to=iec ${size} 2>/dev/null || echo "${size}B")
                local backup_count=$(find ${LOG_DIR} -name "$(basename ${log_file}).*" -type f | wc -l)
                log_rotation "$(basename ${log_file}): ${size_human} (${backup_count} backups)"
            fi
        done
    done
    
    # 전체 로그 크기
    local total_size=$(du -sh ${LOG_DIR} 2>/dev/null | cut -f1 || echo "0")
    log_rotation "Total log directory size: ${total_size}"
}

# 모든 로그 로테이션
rotate_all_logs() {
    log_rotation "Starting log rotation..."
    
    for pattern in "${LOG_PATTERNS[@]}"; do
        for log_file in ${LOG_DIR}/${pattern}; do
            if [ -f "${log_file}" ]; then
                rotate_log "${log_file}"
            fi
        done
    done
    
    log_rotation "Log rotation completed"
}

# 메인 실행
main() {
    local action=${1:-rotate}
    
    # 로그 디렉토리 확인
    if [ ! -d "${LOG_DIR}" ]; then
        mkdir -p ${LOG_DIR}
    fi
    
    case ${action} in
        rotate)
            rotate_all_logs
            cleanup_old_logs_by_date
            cleanup_old_logs_by_count
            log_stats
            ;;
        cleanup)
            cleanup_old_logs_by_date
            cleanup_old_logs_by_count
            ;;
        stats)
            log_stats
            ;;
        *)
            echo "Usage: $0 {rotate|cleanup|stats}"
            exit 1
            ;;
    esac
}

# 실행
main "$@"
