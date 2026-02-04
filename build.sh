#!/bin/bash
set -e

# GhidraMCP Build Script
# Rebuilds the Ghidra plugin and optionally restarts Docker containers

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       GhidraMCP Build Script           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo

# Parse arguments
REBUILD_DOCKER=false
QUIET=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--docker)
            REBUILD_DOCKER=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -d, --docker    Also rebuild and restart Docker container"
            echo "  -q, --quiet     Suppress Maven output"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Step 1: Build Ghidra Plugin
echo -e "${YELLOW}[1/3] Building Ghidra plugin...${NC}"
if [ "$QUIET" = true ]; then
    mvn clean package -q
else
    mvn clean package
fi

if [ $? -eq 0 ]; then
    PLUGIN_PATH="$SCRIPT_DIR/target/GhidraMCP-1.0-SNAPSHOT.zip"
    PLUGIN_SIZE=$(ls -lh "$PLUGIN_PATH" | awk '{print $5}')
    echo -e "${GREEN}✓ Plugin built successfully${NC}"
    echo -e "  ${BLUE}Path:${NC} $PLUGIN_PATH"
    echo -e "  ${BLUE}Size:${NC} $PLUGIN_SIZE"
else
    echo -e "${RED}✗ Plugin build failed${NC}"
    exit 1
fi
echo

# Step 2: Rebuild Docker (if requested)
if [ "$REBUILD_DOCKER" = true ]; then
    echo -e "${YELLOW}[2/3] Rebuilding Docker container...${NC}"
    cd "$SCRIPT_DIR/docker"
    docker-compose down 2>/dev/null || true
    docker-compose up -d --build
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Docker container rebuilt and started${NC}"
    else
        echo -e "${RED}✗ Docker rebuild failed${NC}"
        exit 1
    fi
    cd "$SCRIPT_DIR"
else
    echo -e "${YELLOW}[2/3] Skipping Docker rebuild (use -d to include)${NC}"
fi
echo

# Step 3: Verify services
echo -e "${YELLOW}[3/3] Checking services...${NC}"

# Check Ghidra
GHIDRA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/methods 2>/dev/null || echo "000")
if [ "$GHIDRA_STATUS" = "200" ]; then
    PROGRAM_NAME=$(curl -s http://127.0.0.1:8080/get_program_name 2>/dev/null | grep -v "404" | head -1 || echo "")
    if [ -n "$PROGRAM_NAME" ] && [ "$PROGRAM_NAME" != "No program loaded" ]; then
        echo -e "  ${GREEN}✓ Ghidra plugin:${NC} Running (program: $PROGRAM_NAME)"
    else
        echo -e "  ${GREEN}✓ Ghidra plugin:${NC} Running"
    fi
    echo -e "    ${RED}⚠ NOTE: Restart Ghidra to load the new plugin!${NC}"
else
    echo -e "  ${YELLOW}○ Ghidra plugin:${NC} Not running (start Ghidra and open a binary)"
fi

# Check Docker/GDB
GDB_STATUS=$(curl -s http://127.0.0.1:5000/health 2>/dev/null)
if [ -n "$GDB_STATUS" ]; then
    echo -e "  ${GREEN}✓ GDB container:${NC} Running"
else
    echo -e "  ${YELLOW}○ GDB container:${NC} Not running (cd docker && docker-compose up -d)"
fi

echo
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${GREEN}Build complete!${NC}"
echo
echo -e "Next steps:"
echo -e "  1. In Ghidra: File → Install Extensions"
echo -e "  2. Remove old GhidraMCP, add: ${BLUE}$PLUGIN_PATH${NC}"
echo -e "  3. Restart Ghidra"
echo -e "  4. Restart Claude Desktop to reload MCP tools"
echo
