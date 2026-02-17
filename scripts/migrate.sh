#!/bin/bash
# NetLogs Database Migration Script
# Usage: ./scripts/migrate.sh [command] [args]
#
# Commands:
#   status    - Show current migration version and pending migrations
#   upgrade   - Apply all pending migrations (default)
#   downgrade - Rollback last migration
#   generate  - Auto-generate a new migration from model changes
#   history   - Show migration history
#
# Examples:
#   ./scripts/migrate.sh status
#   ./scripts/migrate.sh upgrade
#   ./scripts/migrate.sh downgrade -1
#   ./scripts/migrate.sh generate "add user preferences table"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Activate venv if present
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

COMMAND="${1:-upgrade}"
shift 2>/dev/null || true

case "$COMMAND" in
    status)
        echo "=== PostgreSQL Migration Status ==="
        alembic current
        echo ""
        echo "=== Pending Migrations ==="
        alembic heads
        ;;
    upgrade)
        echo "=== Applying PostgreSQL Migrations ==="
        alembic upgrade "${1:-head}"
        echo "Done."
        ;;
    downgrade)
        echo "=== Rolling Back PostgreSQL Migration ==="
        alembic downgrade "${1:--1}"
        echo "Done."
        ;;
    generate)
        MSG="${1:-auto migration}"
        echo "=== Generating Migration: $MSG ==="
        alembic revision --autogenerate -m "$MSG"
        echo "Review the generated migration file before applying!"
        ;;
    history)
        echo "=== Migration History ==="
        alembic history --verbose
        ;;
    *)
        echo "Usage: $0 {status|upgrade|downgrade|generate|history} [args]"
        echo ""
        echo "Commands:"
        echo "  status              Show current version"
        echo "  upgrade [rev]       Apply migrations (default: head)"
        echo "  downgrade [rev]     Rollback migrations (default: -1)"
        echo "  generate \"message\"  Auto-generate from model changes"
        echo "  history             Show full migration history"
        exit 1
        ;;
esac
