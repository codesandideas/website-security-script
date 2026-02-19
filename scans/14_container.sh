scan_section_14() {
    local REPORT_FILE="$1"
    # ══════════════════════════════════════════════════════════════════════════════
    # SECTION 14: CONTAINER SECURITY
    # ══════════════════════════════════════════════════════════════════════════════

    # Only run if Docker is detected
    HAS_DOCKER=false
    if command -v docker &>/dev/null || [[ -f "$SCAN_DIR/Dockerfile" ]] || [[ -f "$SCAN_DIR/docker-compose.yml" ]] || [[ -f "$SCAN_DIR/docker-compose.yaml" ]]; then
        HAS_DOCKER=true
    fi

    if [[ "$HAS_DOCKER" == true ]]; then
        log "Checking container security..."

        cat >> "$REPORT_FILE" <<'EOF'
---

## 14. Container Security

Checking Dockerfile best practices, Docker socket exposure, image tags, and secrets in compose files.

EOF

        # Find Dockerfiles and compose files
        DOCKERFILES=$(find "$SCAN_DIR" -maxdepth 3 -type f -name "Dockerfile*" 2>/dev/null | grep -v "node_modules\|vendor/\|\.git/" || true)
        COMPOSE_FILES=$(find "$SCAN_DIR" -maxdepth 3 -type f \( -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" \) 2>/dev/null | grep -v "node_modules\|vendor/\|\.git/" || true)

        # ── 14a. Running as Root ──────────────────────────────────────────────────
        if [[ -n "$DOCKERFILES" ]]; then
            ROOT_CONTAINERS=""
            while IFS= read -r df; do
                if ! grep -q '^USER ' "$df" 2>/dev/null; then
                    ROOT_CONTAINERS="$ROOT_CONTAINERS\n$df: No USER directive found (runs as root)"
                fi
            done <<< "$DOCKERFILES"

            if [[ -n "$ROOT_CONTAINERS" ]]; then
                finding "high" "Containers Running as Root" \
                    "Dockerfiles without a USER directive will run processes as root inside the container." \
                    "$(echo -e "$ROOT_CONTAINERS")" \
                    "Add a USER directive to Dockerfiles to run as a non-root user."
            else
                echo "✅ All Dockerfiles specify a non-root USER." >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
            fi
        fi

        # ── 14b. Exposed Docker Socket ────────────────────────────────────────────
        if [[ -e "/var/run/docker.sock" ]]; then
            SOCK_PERMS=$(stat -c '%a' /var/run/docker.sock 2>/dev/null || true)
            if [[ -n "$SOCK_PERMS" ]] && [[ "${SOCK_PERMS: -1}" != "0" ]]; then
                finding "critical" "Docker Socket World-Accessible" \
                    "The Docker socket (/var/run/docker.sock) is readable by others, allowing container escape and host compromise." \
                    "Permissions: $SOCK_PERMS" \
                    "Set Docker socket permissions to 660 and restrict access to the docker group only."
            else
                echo "✅ Docker socket permissions are properly restricted." >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
            fi
        fi

        # Also check compose files for socket mounts
        if [[ -n "$COMPOSE_FILES" ]]; then
            SOCK_MOUNT=$(grep -hEn 'docker\.sock' $COMPOSE_FILES 2>/dev/null || true)
            if [[ -n "$SOCK_MOUNT" ]]; then
                finding "high" "Docker Socket Mounted in Container" \
                    "Docker socket is mounted into a container, which can allow container escape." \
                    "$SOCK_MOUNT" \
                    "Avoid mounting the Docker socket into containers unless absolutely necessary."
            fi
        fi

        # ── 14c. Using :latest Tag ────────────────────────────────────────────────
        LATEST_TAGS=""
        if [[ -n "$DOCKERFILES" ]]; then
            while IFS= read -r df; do
                LATEST=$(grep -Ein '^FROM\s+\S+:latest|^FROM\s+[^:]+\s' "$df" 2>/dev/null | grep -v ':\S\+' || true)
                EXPLICIT_LATEST=$(grep -Ein '^FROM\s+\S+:latest' "$df" 2>/dev/null || true)
                if [[ -n "$EXPLICIT_LATEST" ]]; then
                    LATEST_TAGS="$LATEST_TAGS\n$df: $EXPLICIT_LATEST"
                elif [[ -n "$LATEST" ]]; then
                    LATEST_TAGS="$LATEST_TAGS\n$df: FROM without explicit tag (defaults to :latest)"
                fi
            done <<< "$DOCKERFILES"
        fi
        if [[ -n "$COMPOSE_FILES" ]]; then
            COMPOSE_LATEST=$(grep -hEn 'image:.*:latest|image:\s+[^:]+\s*$' $COMPOSE_FILES 2>/dev/null || true)
            if [[ -n "$COMPOSE_LATEST" ]]; then
                LATEST_TAGS="$LATEST_TAGS\n$COMPOSE_LATEST"
            fi
        fi

        if [[ -n "$LATEST_TAGS" ]]; then
            finding "medium" "Using :latest or Untagged Images" \
                "Docker images using :latest tag or no tag can lead to unpredictable builds and deployments." \
                "$(echo -e "$LATEST_TAGS")" \
                "Pin image versions to specific tags (e.g., node:20-alpine instead of node:latest)."
        else
            echo "✅ All Docker images use pinned version tags." >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi

        # ── 14d. Secrets in Docker Compose Environment ────────────────────────────
        if [[ -n "$COMPOSE_FILES" ]]; then
            COMPOSE_SECRETS=""
            while IFS= read -r cf; do
                SECRETS=$(grep -Ein '(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*[:=]' "$cf" 2>/dev/null | grep -v '^\s*#' | grep -v '\${' || true)
                if [[ -n "$SECRETS" ]]; then
                    COMPOSE_SECRETS="$COMPOSE_SECRETS\n$cf:\n$SECRETS"
                fi
            done <<< "$COMPOSE_FILES"

            if [[ -n "$COMPOSE_SECRETS" ]]; then
                finding "high" "Hardcoded Secrets in Docker Compose" \
                    "Docker Compose files contain hardcoded passwords, secrets, or API keys in environment variables." \
                    "$(echo -e "$COMPOSE_SECRETS")" \
                    "Use Docker secrets, .env files (excluded from version control), or a secrets manager instead of hardcoding credentials."
            else
                echo "✅ No hardcoded secrets found in Docker Compose files." >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
            fi
        fi
    fi


}
