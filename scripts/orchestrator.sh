#!/bin/bash

# ===================================
# AUTOMATED SECRETS SCANNER - MASTER ORCHESTRATOR
# ===================================

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Load environment variables
if [ -f "$PROJECT_ROOT/.env" ]; then
    export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)
fi

# Default values
LOG_DIR="${LOG_FILE_PATH:-$PROJECT_ROOT/logs}"
DATA_DIR="${DATA_STORAGE_PATH:-$PROJECT_ROOT/data}"
RAW_SECRETS_DIR="${RAW_SECRETS_PATH:-$DATA_DIR/scans/raw}"
DOMAINS_FILE="${1:-$PROJECT_ROOT/config/domains.txt}"
SCAN_TYPE="${2:-full}"  # full, incremental, or quick
DRY_RUN="${DRY_RUN:-false}"

# Logging setup
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/orchestrator_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ===================================
# LOGGING FUNCTIONS
# ===================================

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Log to console with colors
    case $level in
        ERROR)
            echo -e "${RED}[$timestamp] [$level] $message${NC}" >&2
            ;;
        WARN)
            echo -e "${YELLOW}[$timestamp] [$level] $message${NC}"
            ;;
        INFO)
            echo -e "${GREEN}[$timestamp] [$level] $message${NC}"
            ;;
        DEBUG)
            if [ "${VERBOSE_LOGGING:-false}" == "true" ]; then
                echo -e "${CYAN}[$timestamp] [$level] $message${NC}"
            fi
            ;;
        *)
            echo "[$timestamp] [$level] $message"
            ;;
    esac
}

log_error() { log ERROR "$@"; }
log_warn() { log WARN "$@"; }
log_info() { log INFO "$@"; }
log_debug() { log DEBUG "$@"; }

# ===================================
# ERROR HANDLING
# ===================================

error_handler() {
    local line_no=$1
    local bash_lineno=$2
    local last_command=$3
    local code=$4
    
    log_error "Error occurred in script at line $line_no"
    log_error "Command: $last_command"
    log_error "Exit code: $code"
    
    # Send Slack notification for critical errors
    if [ "${ENABLE_ERROR_TRACKING:-false}" == "true" ]; then
        send_error_notification "Orchestrator failed at line $line_no: $last_command"
    fi
    
    # Cleanup
    cleanup_on_error
    
    exit $code
}

trap 'error_handler ${LINENO} ${BASH_LINENO} "$BASH_COMMAND" $?' ERR

# ===================================
# UTILITY FUNCTIONS
# ===================================

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        missing_deps+=("node")
    fi
    
    # Check Go tools
    if [ "${ENABLE_GAU:-true}" == "true" ] && ! command -v gau &> /dev/null; then
        missing_deps+=("gau")
    fi
    
    if [ "${ENABLE_WAYBACKURLS:-true}" == "true" ] && ! command -v waybackurls &> /dev/null; then
        missing_deps+=("waybackurls")
    fi
    
    if [ "${ENABLE_TRUFFLEHOG:-true}" == "true" ] && ! command -v trufflehog &> /dev/null; then
        missing_deps+=("trufflehog")
    fi
    
    if [ "${ENABLE_GITLEAKS:-true}" == "true" ] && ! command -v gitleaks &> /dev/null; then
        missing_deps+=("gitleaks")
    fi
    
    # Check if any dependencies are missing
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please run: $SCRIPT_DIR/install_tools.sh"
        exit 1
    fi
    
    log_info "All dependencies are installed"
}

create_directories() {
    log_info "Creating necessary directories..."
    
    local dirs=(
        "$LOG_DIR"
        "$DATA_DIR"
        "$DATA_DIR/urls"
        "$DATA_DIR/content"
        "$DATA_DIR/scans"
        "$RAW_SECRETS_DIR"
        "$DATA_DIR/scans/validated"
        "$DATA_DIR/baselines"
        "$DATA_DIR/reports"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        log_debug "Created directory: $dir"
    done
}

validate_domains_file() {
    if [ ! -f "$DOMAINS_FILE" ]; then
        log_error "Domains file not found: $DOMAINS_FILE"
        exit 1
    fi
    
    # Count valid domains (excluding comments and empty lines)
    local domain_count=$(grep -v '^#' "$DOMAINS_FILE" | grep -v '^[[:space:]]*$' | grep -v '^!' | wc -l)
    
    if [ $domain_count -eq 0 ]; then
        log_error "No valid domains found in $DOMAINS_FILE"
        exit 1
    fi
    
    log_info "Found $domain_count domains to scan"
}

cleanup_old_data() {
    if [ "${ARCHIVE_OLD_SCANS:-true}" == "true" ]; then
        log_info "Archiving old scan data..."
        
        local archive_days="${ARCHIVE_AFTER_DAYS:-30}"
        local archive_dir="$DATA_DIR/archive/$(date +%Y%m)"
        mkdir -p "$archive_dir"
        
        # Find and move old files
        find "$DATA_DIR/scans" -type f -mtime +$archive_days -exec mv {} "$archive_dir/" \; 2>/dev/null || true
        find "$DATA_DIR/reports" -type f -mtime +$archive_days -exec mv {} "$archive_dir/" \; 2>/dev/null || true
        
        log_info "Archived files older than $archive_days days"
    fi
}

send_slack_notification() {
    local message=$1
    local severity=${2:-info}
    
    if [ "${SLACK_WEBHOOK_URL:-}" != "" ]; then
        python3 "$PROJECT_ROOT/modules/reporter/slack_notifier.py" \
            --message "$message" \
            --severity "$severity" \
            --scan-id "$SCAN_ID" 2>&1 | tee -a "$LOG_FILE"
    fi
}

send_error_notification() {
    local error_message=$1
    send_slack_notification "🚨 Scanner Error: $error_message" "error"
}

cleanup_on_error() {
    log_warn "Performing cleanup after error..."
    
    # Kill any running background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Remove incomplete files
    find "$DATA_DIR" -name "*.tmp" -delete 2>/dev/null || true
    find "$DATA_DIR" -name "*.partial" -delete 2>/dev/null || true
}

# ===================================
# MAIN SCANNING PHASES
# ===================================

phase1_url_discovery() {
    log_info "=== Phase 1: URL Discovery ==="
    
    local domains_to_scan=$(grep -v '^#' "$DOMAINS_FILE" | grep -v '^[[:space:]]*$' | grep -v '^!')
    local all_urls_file="$DATA_DIR/urls/all_urls_$(date +%Y%m%d_%H%M%S).txt"
    local unique_urls_file="$DATA_DIR/urls/unique_urls_$(date +%Y%m%d_%H%M%S).txt"
    
    > "$all_urls_file"  # Create empty file
    
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        
        log_info "Discovering URLs for: $domain"
        
        # GAU
        if [ "${ENABLE_GAU:-true}" == "true" ]; then
            log_debug "Running gau for $domain"
            if [ "$DRY_RUN" == "false" ]; then
                timeout "${URL_DISCOVERY_TIMEOUT:-600}" gau \
                    --subs \
                    --providers wayback,otx,commoncrawl \
                    --threads 5 \
                    "$domain" 2>>"$LOG_FILE" | head -n "${MAX_URLS_PER_DOMAIN:-10000}" >> "$all_urls_file" || {
                    log_warn "gau timed out or failed for $domain"
                }
            fi
        fi
        
        # Waybackurls
        if [ "${ENABLE_WAYBACKURLS:-true}" == "true" ]; then
            log_debug "Running waybackurls for $domain"
            if [ "$DRY_RUN" == "false" ]; then
                echo "$domain" | timeout "${URL_DISCOVERY_TIMEOUT:-600}" waybackurls 2>>"$LOG_FILE" | \
                    head -n "${MAX_URLS_PER_DOMAIN:-10000}" >> "$all_urls_file" || {
                    log_warn "waybackurls timed out or failed for $domain"
                }
            fi
        fi
        
        # Wayurls
        if [ "${ENABLE_WAYURLS:-true}" == "true" ] && command -v wayurls &> /dev/null; then
            log_debug "Running wayurls for $domain"
            if [ "$DRY_RUN" == "false" ]; then
                timeout "${URL_DISCOVERY_TIMEOUT:-600}" wayurls \
                    -no-subs \
                    "$domain" 2>>"$LOG_FILE" | head -n "${MAX_URLS_PER_DOMAIN:-10000}" >> "$all_urls_file" || {
                    log_warn "wayurls timed out or failed for $domain"
                }
            fi
        fi
        
    done <<< "$domains_to_scan"
    
    # Deduplicate and filter URLs
    if [ "$DRY_RUN" == "false" ] && [ -s "$all_urls_file" ]; then
        log_info "Deduplicating and filtering URLs..."
        
        # Apply exclusion patterns
        local exclude_extensions="${EXCLUDE_EXTENSIONS:-jpg,jpeg,png,gif,svg,ico,css,woff,woff2,ttf,eot}"
        local exclude_pattern=$(echo "$exclude_extensions" | sed 's/,/\\|/g')
        
        sort -u "$all_urls_file" | \
            grep -v -E "\.($exclude_pattern)(\?|$)" | \
            grep -E "^https?://" > "$unique_urls_file"
        
        local unique_count=$(wc -l < "$unique_urls_file")
        log_info "Found $unique_count unique URLs after filtering"
        
        echo "$unique_urls_file"
    else
        log_warn "No URLs discovered or dry run mode"
        echo ""
    fi
}

phase2_content_fetching() {
    local urls_file=$1
    
    log_info "=== Phase 2: Content Fetching ==="
    
    if [ -z "$urls_file" ] || [ ! -f "$urls_file" ]; then
        log_warn "No URLs file provided, skipping content fetching"
        return 1
    fi
    
    local content_dir="$DATA_DIR/content/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$content_dir"
    
    if [ "$DRY_RUN" == "false" ]; then
        log_info "Starting Crawlee crawler..."
        
        # Run the Node.js crawler
        cd "$PROJECT_ROOT"
        node modules/content_fetcher/crawler.js \
            --input "$urls_file" \
            --output "$content_dir" \
            --config "$PROJECT_ROOT/config/crawlee_config.js" \
            --max-requests "${CRAWLER_MAX_REQUESTS_PER_CRAWL:-1000}" \
            2>&1 | tee -a "$LOG_FILE" || {
            log_error "Crawler failed"
            return 1
        }
        
        log_info "Content fetching completed. Output directory: $content_dir"
        echo "$content_dir"
    else
        log_info "Dry run mode - skipping content fetching"
        echo ""
    fi
}

phase3_secret_scanning() {
    local content_dir=$1
    
    log_info "=== Phase 3: Secret Scanning ==="
    
    if [ -z "$content_dir" ] || [ ! -d "$content_dir" ]; then
        log_warn "No content directory provided, skipping secret scanning"
        return 1
    fi
    
    local scan_timestamp=$(date +%Y%m%d_%H%M%S)
    local raw_secrets_file="$RAW_SECRETS_DIR/raw_secrets_${scan_timestamp}.json"
    local combined_secrets_file="$RAW_SECRETS_DIR/combined_raw_secrets_${scan_timestamp}.json"
    
    mkdir -p "$RAW_SECRETS_DIR"
    
    if [ "$DRY_RUN" == "false" ]; then
        # Initialize combined results
        echo '{"scan_id": "'$SCAN_ID'", "timestamp": "'$(date -Iseconds)'", "findings": [' > "$combined_secrets_file"
        local first_finding=true
        
        # Run TruffleHog
        if [ "${ENABLE_TRUFFLEHOG:-true}" == "true" ]; then
            log_info "Running TruffleHog scanner..."
            
            local trufflehog_output="$RAW_SECRETS_DIR/trufflehog_raw_${scan_timestamp}.json"
            
            trufflehog filesystem "$content_dir" \
                --config "${TRUFFLEHOG_CONFIG_PATH:-$PROJECT_ROOT/config/trufflehog_config.yaml}" \
                --json \
                --no-update \
                2>>"$LOG_FILE" > "$trufflehog_output" || {
                log_error "TruffleHog scanning failed"
            }
            
            # Append to combined file
            if [ -s "$trufflehog_output" ]; then
                if [ "$first_finding" == "false" ]; then
                    echo "," >> "$combined_secrets_file"
                fi
                cat "$trufflehog_output" >> "$combined_secrets_file"
                first_finding=false
            fi
        fi
        
        # Run Gitleaks
        if [ "${ENABLE_GITLEAKS:-true}" == "true" ]; then
            log_info "Running Gitleaks scanner..."
            
            local gitleaks_output="$RAW_SECRETS_DIR/gitleaks_raw_${scan_timestamp}.json"
            
            gitleaks detect \
                --source "$content_dir" \
                --config "${GITLEAKS_CONFIG_PATH:-$PROJECT_ROOT/config/gitleaks.toml}" \
                --report-format json \
                --report-path "$gitleaks_output" \
                --no-git \
                --verbose \
                2>&1 | tee -a "$LOG_FILE" || {
                log_warn "Gitleaks scanning completed (may have found secrets)"
            }
            
            # Append to combined file
            if [ -s "$gitleaks_output" ]; then
                if [ "$first_finding" == "false" ]; then
                    echo "," >> "$combined_secrets_file"
                fi
                # Extract just the findings array from gitleaks output
                jq -r '.[] | @json' "$gitleaks_output" 2>/dev/null >> "$combined_secrets_file" || true
            fi
        fi
        
        # Close the JSON array
        echo ']}}' >> "$combined_secrets_file"
        
        # Validate JSON
        if jq . "$combined_secrets_file" > "$raw_secrets_file" 2>/dev/null; then
            log_info "Raw secrets saved to: $raw_secrets_file"
            rm -f "$combined_secrets_file"
            echo "$raw_secrets_file"
        else
            log_error "Failed to create valid JSON output"
            echo ""
        fi
    else
        log_info "Dry run mode - skipping secret scanning"
        echo ""
    fi
}

phase4_validation() {
    local raw_secrets_file=$1
    
    log_info "=== Phase 4: Validation ==="
    
    if [ -z "$raw_secrets_file" ] || [ ! -f "$raw_secrets_file" ]; then
        log_warn "No raw secrets file provided, skipping validation"
        return 1
    fi
    
    local validated_file="$DATA_DIR/scans/validated/validated_secrets_$(date +%Y%m%d_%H%M%S).json"
    mkdir -p "$(dirname "$validated_file")"
    
    if [ "$DRY_RUN" == "false" ]; then
        log_info "Running validation process..."
        
        python3 "$PROJECT_ROOT/modules/validator/auto_validator.py" \
            --input "$raw_secrets_file" \
            --output "$validated_file" \
            --config "$PROJECT_ROOT/config/validation_config.yaml" \
            2>&1 | tee -a "$LOG_FILE" || {
            log_error "Validation failed"
            return 1
        }
        
        log_info "Validated secrets saved to: $validated_file"
        echo "$validated_file"
    else
        log_info "Dry run mode - skipping validation"
        echo ""
    fi
}

phase5_reporting() {
    local validated_file=$1
    local is_first_run=$2
    
    log_info "=== Phase 5: Reporting & Alerting ==="
    
    if [ -z "$validated_file" ] || [ ! -f "$validated_file" ]; then
        log_warn "No validated secrets file provided, skipping reporting"
        return 1
    fi
    
    if [ "$DRY_RUN" == "false" ]; then
        if [ "$is_first_run" == "true" ]; then
            log_info "Generating HTML report for initial scan..."
            
            python3 "$PROJECT_ROOT/modules/reporter/html_generator.py" \
                --input "$validated_file" \
                --output "$DATA_DIR/reports" \
                --scan-id "$SCAN_ID" \
                2>&1 | tee -a "$LOG_FILE" || {
                log_error "HTML report generation failed"
            }
            
            # Send initial scan notification
            send_slack_notification "Initial scan completed. Check the HTML report for all findings." "info"
        else
            log_info "Checking for new secrets and sending alerts..."
            
            python3 "$PROJECT_ROOT/modules/reporter/slack_notifier.py" \
                --current "$validated_file" \
                --baseline "$DATA_DIR/baselines/baseline_secrets.json" \
                --scan-id "$SCAN_ID" \
                --send-alerts \
                2>&1 | tee -a "$LOG_FILE" || {
                log_error "Slack notification failed"
            }
        fi
        
        # Update baseline
        cp "$validated_file" "$DATA_DIR/baselines/baseline_secrets.json"
        log_info "Baseline updated"
    else
        log_info "Dry run mode - skipping reporting"
    fi
}

# ===================================
# MAIN EXECUTION
# ===================================

main() {
    local start_time=$(date +%s)
    
    # Generate unique scan ID
    export SCAN_ID="scan_$(date +%Y%m%d_%H%M%S)_$$"
    
    log_info "========================================="
    log_info "Starting Automated Secrets Scanner"
    log_info "Scan ID: $SCAN_ID"
    log_info "Scan Type: $SCAN_TYPE"
    log_info "Domains File: $DOMAINS_FILE"
    log_info "Dry Run: $DRY_RUN"
    log_info "========================================="
    
    # Pre-flight checks
    check_dependencies
    create_directories
    validate_domains_file
    cleanup_old_data
    
    # Send start notification
    send_slack_notification "Secret scan started for $(basename "$DOMAINS_FILE")" "info"
    
    # Determine if this is the first run
    local is_first_run="false"
    if [ ! -f "$DATA_DIR/baselines/baseline_secrets.json" ]; then
        is_first_run="true"
        log_info "This appears to be the first run (no baseline found)"
    fi
    
    # Execute scanning phases
    local urls_file=""
    local content_dir=""
    local raw_secrets_file=""
    local validated_file=""
    
    # Phase 1: URL Discovery
    if [ "$SCAN_TYPE" != "quick" ]; then
        urls_file=$(phase1_url_discovery)
        if [ -z "$urls_file" ]; then
            log_error "URL discovery failed"
            send_error_notification "URL discovery phase failed"
            exit 1
        fi
    else
        log_info "Quick scan mode - using provided URLs"
        urls_file="$DOMAINS_FILE"
    fi
    
    # Phase 2: Content Fetching
    content_dir=$(phase2_content_fetching "$urls_file")
    if [ -z "$content_dir" ]; then
        log_error "Content fetching failed"
        send_error_notification "Content fetching phase failed"
        exit 1
    fi
    
    # Phase 3: Secret Scanning
    raw_secrets_file=$(phase3_secret_scanning "$content_dir")
    if [ -z "$raw_secrets_file" ]; then
        log_error "Secret scanning failed"
        send_error_notification "Secret scanning phase failed"
        exit 1
    fi
    
    # Phase 4: Validation
    validated_file=$(phase4_validation "$raw_secrets_file")
    if [ -z "$validated_file" ]; then
        log_error "Validation failed"
        send_error_notification "Validation phase failed"
        exit 1
    fi
    
    # Phase 5: Reporting & Alerting
    phase5_reporting "$validated_file" "$is_first_run"
    
    # Calculate execution time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local duration_min=$((duration / 60))
    local duration_sec=$((duration % 60))
    
    log_info "========================================="
    log_info "Scan completed successfully!"
    log_info "Duration: ${duration_min}m ${duration_sec}s"
    log_info "Scan ID: $SCAN_ID"
    log_info "Raw secrets: $raw_secrets_file"
    log_info "Validated secrets: $validated_file"
    log_info "========================================="
    
    # Send completion notification
    send_slack_notification "Secret scan completed in ${duration_min}m ${duration_sec}s" "success"
    
    # Exit successfully
    exit 0
}

# Run main function
main "$@"