#!/usr/bin/env bash
# =============================================================================
# GhidraMCP Development Check Script
# Run all linting, type checking, and tests
# Usage: ./scripts/check.sh [--fix] [--quick]
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

FIX_MODE=false
QUICK_MODE=false

for arg in "$@"; do
    case $arg in
        --fix)  FIX_MODE=true ;;
        --quick) QUICK_MODE=true ;;
        -h|--help)
            echo "Usage: $0 [--fix] [--quick]"
            echo "  --fix    Auto-fix linting issues where possible"
            echo "  --quick  Skip slow checks (type checking, integration tests)"
            exit 0
            ;;
    esac
done

PASS=0
FAIL=0
SKIP=0

run_check() {
    local name="$1"
    shift
    echo -e "\n${BLUE}━━━ $name ━━━${NC}"
    if "$@"; then
        echo -e "${GREEN}✓ $name passed${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗ $name failed${NC}"
        FAIL=$((FAIL + 1))
    fi
}

skip_check() {
    local name="$1"
    echo -e "\n${YELLOW}⊘ $name skipped${NC}"
    SKIP=$((SKIP + 1))
}

echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   GhidraMCP Development Checks       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"

# ---------------------------------------------------------------------------
# 1. Ruff Linter
# ---------------------------------------------------------------------------
if $FIX_MODE; then
    run_check "Ruff Lint (auto-fix)" ruff check . --fix
else
    run_check "Ruff Lint" ruff check .
fi

# ---------------------------------------------------------------------------
# 2. Ruff Formatter
# ---------------------------------------------------------------------------
if $FIX_MODE; then
    run_check "Ruff Format (auto-fix)" ruff format .
else
    run_check "Ruff Format Check" ruff format --check .
fi

# ---------------------------------------------------------------------------
# 3. Type Checking (mypy)
# ---------------------------------------------------------------------------
if $QUICK_MODE; then
    skip_check "Mypy Type Check"
else
    run_check "Mypy Type Check" mypy bridge_mcp_ghidra.py trajectory_recorder.py --ignore-missing-imports
fi

# ---------------------------------------------------------------------------
# 4. Unit Tests
# ---------------------------------------------------------------------------
run_check "Unit Tests" python -m pytest tests/ -v \
    -m "not integration and not slow" \
    --timeout=30 \
    --tb=short

# ---------------------------------------------------------------------------
# 5. Test Coverage
# ---------------------------------------------------------------------------
if $QUICK_MODE; then
    skip_check "Coverage Report"
else
    run_check "Test Coverage" python -m pytest tests/ \
        --cov=bridge_mcp_ghidra \
        --cov=trajectory_recorder \
        --cov-report=term-missing \
        -m "not integration and not slow" \
        --timeout=30 \
        -q
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $FAIL -gt 0 ]; then
    echo -e "\n${RED}Some checks failed. Fix issues before committing.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All checks passed!${NC}"
    exit 0
fi
