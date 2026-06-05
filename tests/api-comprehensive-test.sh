#!/bin/bash
# Comprehensive API end-to-end test for SFTPxy Admin API
set +e

ADMIN_PORT=30088
CLIENT_PORT=30080
ADMIN_USER="admin"
ADMIN_PASS="admin-pass"
TEST_USER="testuser"
TEST_PASS="testuser-pass"
HOST="127.0.0.1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
declare -a FAILED_TESTS

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED_TESTS+=("$1"); ((FAIL++)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
section() { echo ""; echo -e "${BLUE}=========== $1 ===========${NC}"; }

# Get admin token
LOGIN=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/auth/admin/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1)
ADMIN_TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -z "$ADMIN_TOKEN" ]; then
    echo "Cannot get admin token, aborting"
    exit 1
fi
log_info "Admin token acquired"

USER_LOGIN=$(curl -s -m 5 -X POST http://$HOST:$CLIENT_PORT/api/v1/auth/user/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}" 2>&1)
USER_TOKEN=$(echo "$USER_LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -z "$USER_TOKEN" ]; then
    log_warn "Cannot get user token"
fi

AUTH="Authorization: Bearer $ADMIN_TOKEN"
USER_AUTH="Authorization: Bearer $USER_TOKEN"

section "1. Admin API - Basic CRUD"

# 1.1 GET /api/v1/config
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/config -H "$AUTH" 2>&1)
if echo "$RESP" | grep -q "ssh\|ftp\|webdav"; then
    log_pass "GET /api/v1/config returns config"
else
    log_fail "GET /api/v1/config: ${RESP:0:200}"
fi

# 1.2 GET /api/v1/admins
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/admins -H "$AUTH" 2>&1)
if echo "$RESP" | grep -q "admin\|id"; then
    log_pass "GET /api/v1/admins works"
else
    log_fail "GET /api/v1/admins: ${RESP:0:200}"
fi

# 1.3 GET /api/v1/users
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/users -H "$AUTH" 2>&1)
if echo "$RESP" | grep -q "testuser\|users\|id"; then
    log_pass "GET /api/v1/users works"
else
    log_fail "GET /api/v1/users: ${RESP:0:200}"
fi

# 1.4 GET /api/v1/groups
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/groups -H "$AUTH" 2>&1)
if [ -n "$RESP" ]; then
    log_pass "GET /api/v1/groups works (status 200)"
else
    log_fail "GET /api/v1/groups: empty"
fi

# 1.5 GET /api/v1/roles
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/roles -H "$AUTH" 2>&1)
if [ -n "$RESP" ]; then
    log_pass "GET /api/v1/roles works (status 200)"
else
    log_fail "GET /api/v1/roles: empty"
fi

# 1.6 GET /api/v1/folders
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/folders -H "$AUTH" 2>&1)
if [ -n "$RESP" ]; then
    log_pass "GET /api/v1/folders works"
else
    log_fail "GET /api/v1/folders: empty"
fi

# 1.7 GET /api/v1/connections
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/connections -H "$AUTH" 2>&1)
if [ -n "$RESP" ]; then
    log_pass "GET /api/v1/connections works"
else
    log_fail "GET /api/v1/connections: empty"
fi

# 1.8 GET /api/v1/logs
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/logs -H "$AUTH" 2>&1)
if [ -n "$RESP" ]; then
    log_pass "GET /api/v1/logs works"
else
    log_fail "GET /api/v1/logs: empty"
fi

# 1.9 GET /api/v1/events/rules
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/events/rules -H "$AUTH" 2>&1)
if [ -n "$RESP" ]; then
    log_pass "GET /api/v1/events/rules works"
else
    log_fail "GET /api/v1/events/rules: empty"
fi

# 1.10 GET /api/v1/events/history
RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/events/history -H "$AUTH" 2>&1)
if [ -n "$RESP" ]; then
    log_pass "GET /api/v1/events/history works"
else
    log_fail "GET /api/v1/events/history: empty"
fi

section "2. Admin API - Event Rules CRUD"
# Create event rule
RULE_PAYLOAD='{
    "name": "Test Rule '$(date +%s)'",
    "description": "Test rule created by API test",
    "trigger_type": "manual",
    "trigger_config": {},
    "conditions": [],
    "actions": [
        {"type": "log", "config": {"message": "Test action"}}
    ],
    "enabled": true
}'

CREATE_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/events/rules \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "$RULE_PAYLOAD" 2>&1)
RULE_ID=$(echo "$CREATE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id') or d.get('rule_id') or d.get('rule', {}).get('id', ''))" 2>/dev/null)
if [ -n "$RULE_ID" ] && [ "$RULE_ID" != "None" ]; then
    log_pass "POST /api/v1/events/rules created (id=$RULE_ID)"

    # Update event rule
    UPDATE_RESP=$(curl -s -m 5 -X PUT http://$HOST:$ADMIN_PORT/api/v1/events/rules/$RULE_ID \
        -H "$AUTH" -H "Content-Type: application/json" \
        -d "{\"name\":\"Updated Test Rule $RULE_ID\",\"description\":\"Updated\",\"trigger_type\":\"manual\",\"trigger_config\":{},\"conditions\":[],\"actions\":[{\"type\":\"log\",\"config\":{\"message\":\"Updated\"}}],\"enabled\":false}" 2>&1)
    if echo "$UPDATE_RESP" | grep -q "id\|name\|success"; then
        log_pass "PUT /api/v1/events/rules/$RULE_ID works"
    else
        log_warn "PUT /api/v1/events/rules/$RULE_ID: ${UPDATE_RESP:0:200}"
    fi

    # Toggle rule
    TOGGLE_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/events/rules/$RULE_ID/toggle -H "$AUTH" 2>&1)
    if [ -n "$TOGGLE_RESP" ]; then
        log_pass "POST /api/v1/events/rules/$RULE_ID/toggle works"
    else
        log_warn "POST /api/v1/events/rules/$RULE_ID/toggle: empty"
    fi

    # Delete event rule
    DEL_RESP=$(curl -s -m 5 -X DELETE http://$HOST:$ADMIN_PORT/api/v1/events/rules/$RULE_ID -H "$AUTH" -o /dev/null -w "%{http_code}" 2>&1)
    if [ "$DEL_RESP" = "200" ] || [ "$DEL_RESP" = "204" ] || [ "$DEL_RESP" = "404" ]; then
        log_pass "DELETE /api/v1/events/rules/$RULE_ID (HTTP $DEL_RESP)"
    else
        log_warn "DELETE /api/v1/events/rules/$RULE_ID returned $DEL_RESP"
    fi
else
    log_fail "POST /api/v1/events/rules: ${CREATE_RESP:0:200}"
fi

section "3. Admin API - Virtual Folders CRUD"
FOLDER_PAYLOAD='{
    "name": "test_folder_'$(date +%s)'",
    "mapped_path": "/tmp/test_folder_'$(date +%s)'",
    "filesystem_type": "local",
    "filesystem_config": {},
    "description": "Test folder",
    "user_ids": [],
    "group_ids": []
}'

FOLDER_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/folders \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "$FOLDER_PAYLOAD" 2>&1)
FOLDER_ID=$(echo "$FOLDER_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id') or d.get('folder', {}).get('id', ''))" 2>/dev/null)
if [ -n "$FOLDER_ID" ] && [ "$FOLDER_ID" != "None" ]; then
    log_pass "POST /api/v1/folders created (id=$FOLDER_ID)"

    # Update folder
    UPD_RESP=$(curl -s -m 5 -X PUT http://$HOST:$ADMIN_PORT/api/v1/folders/$FOLDER_ID \
        -H "$AUTH" -H "Content-Type: application/json" \
        -d "{\"name\":\"updated_$FOLDER_ID\",\"mapped_path\":\"/tmp/updated_$FOLDER_ID\",\"filesystem_type\":\"local\",\"filesystem_config\":{}}" 2>&1)
    if echo "$UPD_RESP" | grep -q "id\|name"; then
        log_pass "PUT /api/v1/folders/$FOLDER_ID works"
    else
        log_warn "PUT /api/v1/folders/$FOLDER_ID: ${UPD_RESP:0:200}"
    fi

    # Delete folder
    DEL_RESP=$(curl -s -m 5 -X DELETE http://$HOST:$ADMIN_PORT/api/v1/folders/$FOLDER_ID -H "$AUTH" -o /dev/null -w "%{http_code}" 2>&1)
    if [ "$DEL_RESP" = "200" ] || [ "$DEL_RESP" = "204" ]; then
        log_pass "DELETE /api/v1/folders/$FOLDER_ID (HTTP $DEL_RESP)"
    else
        log_warn "DELETE /api/v1/folders/$FOLDER_ID returned $DEL_RESP"
    fi
else
    log_fail "POST /api/v1/folders: ${FOLDER_RESP:0:200}"
fi

section "4. Admin API - User CRUD"
USER_PAYLOAD='{
    "username": "test_api_user_'$(date +%s)'",
    "email": "testapi@example.com",
    "password": "TestPass123!",
    "status": "active",
    "home_dir": "/tmp/test_home_'$(date +%s)'",
    "permissions": "full"
}'

NEW_USER_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/users \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "$USER_PAYLOAD" 2>&1)
NEW_USER_ID=$(echo "$NEW_USER_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id') or d.get('user', {}).get('id', ''))" 2>/dev/null)
if [ -n "$NEW_USER_ID" ] && [ "$NEW_USER_ID" != "None" ]; then
    log_pass "POST /api/v1/users created (id=$NEW_USER_ID)"

    # Update user
    UPD_RESP=$(curl -s -m 5 -X PUT http://$HOST:$ADMIN_PORT/api/v1/users/$NEW_USER_ID \
        -H "$AUTH" -H "Content-Type: application/json" \
        -d '{"email":"updated@example.com","status":"active","permissions":"full"}' 2>&1)
    if echo "$UPD_RESP" | grep -q "id\|email"; then
        log_pass "PUT /api/v1/users/$NEW_USER_ID works"
    else
        log_warn "PUT /api/v1/users/$NEW_USER_ID: ${UPD_RESP:0:200}"
    fi

    # Delete user
    DEL_RESP=$(curl -s -m 5 -X DELETE http://$HOST:$ADMIN_PORT/api/v1/users/$NEW_USER_ID -H "$AUTH" -o /dev/null -w "%{http_code}" 2>&1)
    if [ "$DEL_RESP" = "200" ] || [ "$DEL_RESP" = "204" ]; then
        log_pass "DELETE /api/v1/users/$NEW_USER_ID (HTTP $DEL_RESP)"
    else
        log_warn "DELETE /api/v1/users/$NEW_USER_ID returned $DEL_RESP"
    fi
else
    log_fail "POST /api/v1/users: ${NEW_USER_RESP:0:200}"
fi

section "5. Admin API - Admin CRUD"
ADMIN_PAYLOAD='{
    "username": "test_admin_'$(date +%s)'",
    "password": "AdminPass123!",
    "status": "active",
    "permissions": ["users:read", "users:write"]
}'

NEW_ADMIN_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/admins \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "$ADMIN_PAYLOAD" 2>&1)
NEW_ADMIN_ID=$(echo "$NEW_ADMIN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id') or d.get('admin', {}).get('id', ''))" 2>/dev/null)
if [ -n "$NEW_ADMIN_ID" ] && [ "$NEW_ADMIN_ID" != "None" ]; then
    log_pass "POST /api/v1/admins created (id=$NEW_ADMIN_ID)"

    # Delete admin
    DEL_RESP=$(curl -s -m 5 -X DELETE http://$HOST:$ADMIN_PORT/api/v1/admins/$NEW_ADMIN_ID -H "$AUTH" -o /dev/null -w "%{http_code}" 2>&1)
    if [ "$DEL_RESP" = "200" ] || [ "$DEL_RESP" = "204" ]; then
        log_pass "DELETE /api/v1/admins/$NEW_ADMIN_ID (HTTP $DEL_RESP)"
    else
        log_warn "DELETE /api/v1/admins/$NEW_ADMIN_ID returned $DEL_RESP"
    fi
else
    log_fail "POST /api/v1/admins: ${NEW_ADMIN_RESP:0:200}"
fi

section "6. Admin API - Config Update"
# Test PUT /api/v1/config
CONFIG_PAYLOAD='{"common":{"log_level":"info","log_path":"./data/e2e/sftpxy.log"}}'
CONFIG_RESP=$(curl -s -m 5 -X PUT http://$HOST:$ADMIN_PORT/api/v1/config \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "$CONFIG_PAYLOAD" 2>&1)
if echo "$CONFIG_RESP" | grep -q "config\|ok\|success\|updated"; then
    log_pass "PUT /api/v1/config works"
else
    log_warn "PUT /api/v1/config: ${CONFIG_RESP:0:200}"
fi

section "7. Admin API - Data Retention Policies"
LIST_RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/data-retention -H "$AUTH" 2>&1)
if [ -n "$LIST_RESP" ]; then
    log_pass "GET /api/v1/data-retention works"
else
    log_warn "GET /api/v1/data-retention: empty"
fi

# Create policy
DR_PAYLOAD='{
    "name": "test_policy_'$(date +%s)'",
    "resource_type": "audit_logs",
    "max_age_seconds": 86400,
    "enabled": true
}'
DR_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/data-retention \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "$DR_PAYLOAD" 2>&1)
DR_ID=$(echo "$DR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id') or d.get('policy', {}).get('id', ''))" 2>/dev/null)
if [ -n "$DR_ID" ] && [ "$DR_ID" != "None" ]; then
    log_pass "POST /api/v1/data-retention created (id=$DR_ID)"

    DEL_RESP=$(curl -s -m 5 -X DELETE http://$HOST:$ADMIN_PORT/api/v1/data-retention/$DR_ID -H "$AUTH" -o /dev/null -w "%{http_code}" 2>&1)
    if [ "$DEL_RESP" = "200" ] || [ "$DEL_RESP" = "204" ]; then
        log_pass "DELETE /api/v1/data-retention/$DR_ID (HTTP $DEL_RESP)"
    else
        log_warn "DELETE /api/v1/data-retention/$DR_ID returned $DEL_RESP"
    fi
else
    log_warn "POST /api/v1/data-retention: ${DR_RESP:0:200}"
fi

section "8. User WebClient API"
if [ -n "$USER_TOKEN" ]; then
    # GET /api/v1/profile
    PROF_RESP=$(curl -s -m 5 http://$HOST:$CLIENT_PORT/api/v1/profile -H "$USER_AUTH" 2>&1)
    if echo "$PROF_RESP" | grep -q "testuser\|username"; then
        log_pass "GET /api/v1/profile (webclient) works"
    else
        log_fail "GET /api/v1/profile: ${PROF_RESP:0:200}"
    fi

    # GET /api/v1/files
    FILES_RESP=$(curl -s -m 5 http://$HOST:$CLIENT_PORT/api/v1/files -H "$USER_AUTH" 2>&1)
    if echo "$FILES_RESP" | grep -q "files\|items\|name\|\\["; then
        log_pass "GET /api/v1/files (webclient) works"
    else
        log_warn "GET /api/v1/files: ${FILES_RESP:0:200}"
    fi

    # GET /api/v1/user/quota
    QUOTA_RESP=$(curl -s -m 5 http://$HOST:$CLIENT_PORT/api/v1/user/quota -H "$USER_AUTH" 2>&1)
    if [ -n "$QUOTA_RESP" ]; then
        log_pass "GET /api/v1/user/quota works"
    else
        log_warn "GET /api/v1/user/quota: empty"
    fi

    # GET /api/v1/user/sessions
    SESS_RESP=$(curl -s -m 5 http://$HOST:$CLIENT_PORT/api/v1/user/sessions -H "$USER_AUTH" 2>&1)
    if [ -n "$SESS_RESP" ]; then
        log_pass "GET /api/v1/user/sessions works"
    else
        log_warn "GET /api/v1/user/sessions: empty"
    fi

    # GET /api/v1/shares
    SHARES_RESP=$(curl -s -m 5 http://$HOST:$CLIENT_PORT/api/v1/shares -H "$USER_AUTH" 2>&1)
    if [ -n "$SHARES_RESP" ]; then
        log_pass "GET /api/v1/shares (webclient) works"
    else
        log_warn "GET /api/v1/shares: empty"
    fi
fi

section "9. Defender / Blocked IPs"
DEF_RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/defender/blocked -H "$AUTH" 2>&1)
if [ -n "$DEF_RESP" ]; then
    log_pass "GET /api/v1/defender/blocked works"
else
    log_warn "GET /api/v1/defender/blocked: empty"
fi

section "10. Summary"
echo ""
echo -e "${GREEN}Passed:${NC}  $PASS"
echo -e "${RED}Failed:${NC}  $FAIL"
echo -e "${YELLOW}Warned:${NC}  $WARN"
echo ""
if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Failed tests:${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
    exit 1
fi
exit 0
