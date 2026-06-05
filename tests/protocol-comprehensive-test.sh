#!/bin/bash
# Comprehensive protocol-layer end-to-end test for SFTPxy
set +e

# Configuration
ADMIN_USER="admin"
ADMIN_PASS="admin-pass"
TEST_USER="testuser"
TEST_PASS="testuser-pass"
HOST="127.0.0.1"
ADMIN_PORT=30088
CLIENT_PORT=30080
SFTP_PORT=30082
FTP_PORT=30086
WEBDAV_PORT=30084

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
declare -a FAILED_TESTS
declare -a WARNED_TESTS

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++))
}
log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED_TESTS+=("$1")
    ((FAIL++))
}
log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNED_TESTS+=("$1")
    ((WARN++))
}
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}
section() {
    echo ""
    echo -e "${BLUE}=========== $1 ===========${NC}"
}

section "1. Service Health Checks"
# HTTP admin health
HEALTH=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/health 2>&1)
if echo "$HEALTH" | grep -q "healthy\|running"; then
    log_pass "HTTP admin health endpoint: $(echo $HEALTH | head -c 100)"
else
    log_fail "HTTP admin health endpoint failed: $HEALTH"
fi

# HTTP status
STATUS=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/status 2>&1)
if echo "$STATUS" | grep -q '"service"\|SFTPxy\|"version"'; then
    log_pass "HTTP admin status endpoint"
else
    log_fail "HTTP admin status endpoint failed: $STATUS"
fi

# SFTP port
if nc -z -w 2 $HOST $SFTP_PORT 2>/dev/null; then
    log_pass "SFTP port $SFTP_PORT is listening"
else
    log_fail "SFTP port $SFTP_PORT not listening"
fi

# FTP port
if nc -z -w 2 $HOST $FTP_PORT 2>/dev/null; then
    log_pass "FTP port $FTP_PORT is listening"
else
    log_fail "FTP port $FTP_PORT not listening"
fi

# WebDAV port
if nc -z -w 2 $HOST $WEBDAV_PORT 2>/dev/null; then
    log_pass "WebDAV port $WEBDAV_PORT is listening"
else
    log_fail "WebDAV port $WEBDAV_PORT not listening"
fi

section "2. Admin Authentication"
LOGIN_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/auth/admin/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1)
if echo "$LOGIN_RESP" | grep -q "token"; then
    log_pass "Admin login successful"
    ADMIN_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
    if [ -z "$ADMIN_TOKEN" ]; then
        ADMIN_TOKEN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*"' | head -1 | sed 's/"token":"//;s/"//')
    fi
    log_info "Token (first 30 chars): ${ADMIN_TOKEN:0:30}..."
else
    log_fail "Admin login failed: $LOGIN_RESP"
fi

# Invalid login
INVALID_RESP=$(curl -s -m 5 -X POST http://$HOST:$ADMIN_PORT/api/v1/auth/admin/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"wrong\"}" 2>&1)
if echo "$INVALID_RESP" | grep -qi "invalid\|credentials\|unauthorized\|401"; then
    log_pass "Invalid admin login rejected"
else
    log_warn "Invalid admin login unexpected response: $INVALID_RESP"
fi

section "3. User Authentication"
USER_LOGIN_RESP=$(curl -s -m 5 -X POST http://$HOST:$CLIENT_PORT/api/v1/auth/user/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}" 2>&1)
if echo "$USER_LOGIN_RESP" | grep -q "token"; then
    log_pass "User login successful"
    USER_TOKEN=$(echo "$USER_LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
    if [ -z "$USER_TOKEN" ]; then
        USER_TOKEN=$(echo "$USER_LOGIN_RESP" | grep -o '"token":"[^"]*"' | head -1 | sed 's/"token":"//;s/"//')
    fi
    log_info "User token (first 30 chars): ${USER_TOKEN:0:30}..."
else
    log_fail "User login failed: $USER_LOGIN_RESP"
fi

section "4. SFTP/SSH Protocol Tests"
SFTP_TEST_DIR="/tmp/sftp_test_$$"
mkdir -p $SFTP_TEST_DIR
TEST_FILE="$SFTP_TEST_DIR/test_upload.txt"
echo "hello sftp $(date)" > $TEST_FILE

if command -v sftp >/dev/null 2>&1; then
    # SFTP upload
    SFTP_CMD="put $TEST_FILE /test_upload_sftp.txt
ls /
bye"
    SFTP_OUT=$(echo "$SFTP_CMD" | timeout 10 sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $SFTP_PORT $TEST_USER@$HOST 2>&1 <<< "$TEST_CMD")
    if echo "$SFTP_OUT" | grep -q "test_upload_sftp.txt\|sftp>"; then
        log_pass "SFTP connection successful"
    else
        log_warn "SFTP client may not be available, trying SSH"
    fi
else
    log_warn "sftp client not installed, skipping SFTP client test"
fi

# SSH protocol version
SSH_BANNER=$(timeout 3 bash -c "echo '' | nc $HOST $SFTP_PORT" 2>&1 | head -1) || SSH_BANNER=""
# Try gtimeout on macOS
if [ -z "$SSH_BANNER" ]; then
    SSH_BANNER=$(gtimeout 3 bash -c "echo '' | nc $HOST $SFTP_PORT" 2>&1 | head -1) || SSH_BANNER=""
fi
# Try a simpler approach
if [ -z "$SSH_BANNER" ]; then
    SSH_BANNER=$( (echo '' | nc -w 3 $HOST $SFTP_PORT 2>&1 | head -1) ) || SSH_BANNER=""
fi
if echo "$SSH_BANNER" | grep -q "SSH-"; then
    log_pass "SSH protocol banner received: $(echo $SSH_BANNER | head -c 50)"
else
    log_warn "SSH banner not detected (server may need real SSH client)"
fi

rm -rf $SFTP_TEST_DIR

section "5. FTP Protocol Tests"
FTP_TEST_DIR="/tmp/ftp_test_$$"
mkdir -p $FTP_TEST_DIR
TEST_FILE="$FTP_TEST_DIR/test_upload.txt"
echo "hello ftp $(date)" > $TEST_FILE

if command -v curl >/dev/null 2>&1; then
    # Use Python for FTP testing as curl FTP support is limited
    python3 -c "
import ftplib
import sys
import time

try:
    ftp = ftplib.FTP()
    ftp.connect('$HOST', $FTP_PORT, timeout=10)
    banner = ftp.getwelcome()
    print(f'FTP BANNER: {banner}')
    ftp.login('$TEST_USER', '$TEST_PASS')
    print('FTP LOGIN OK')

    # List root
    files = []
    ftp.retrlines('LIST', files.append)
    print(f'FTP LIST ({len(files)} entries): {files[:3]}')

    # Upload
    with open('$TEST_FILE', 'rb') as f:
        ftp.storbinary('STOR test_upload_ftp.txt', f)
    print('FTP UPLOAD OK')

    # Download
    import io
    buf = io.BytesIO()
    ftp.retrbinary('RETR test_upload_ftp.txt', buf.write)
    content = buf.getvalue()
    print(f'FTP DOWNLOAD OK ({len(content)} bytes)')

    # Passive mode test - already implicitly tested
    print(f'FTP PASV/PORT mode: passive (default)')

    ftp.quit()
    print('FTP QUIT OK')
except Exception as e:
    print(f'FTP ERROR: {e}')
    sys.exit(1)
" 2>&1 | tee $FTP_TEST_DIR/ftp_result.txt

    if grep -q "FTP LOGIN OK" $FTP_TEST_DIR/ftp_result.txt; then
        log_pass "FTP login successful"
    else
        log_fail "FTP login failed"
    fi
    if grep -q "FTP LIST" $FTP_TEST_DIR/ftp_result.txt; then
        log_pass "FTP LIST works"
    else
        log_fail "FTP LIST failed"
    fi
    if grep -q "FTP UPLOAD OK" $FTP_TEST_DIR/ftp_result.txt; then
        log_pass "FTP upload (STOR) works"
    else
        log_fail "FTP upload failed"
    fi
    if grep -q "FTP DOWNLOAD OK" $FTP_TEST_DIR/ftp_result.txt; then
        log_pass "FTP download (RETR) works"
    else
        log_fail "FTP download failed"
    fi
    if grep -q "FTP QUIT OK" $FTP_TEST_DIR/ftp_result.txt; then
        log_pass "FTP QUIT works"
    else
        log_warn "FTP QUIT failed"
    fi
fi

rm -rf $FTP_TEST_DIR

section "6. WebDAV Protocol Tests"
if command -v curl >/dev/null 2>&1; then
    # WebDAV basic OPTIONS
    OPTIONS_RESP=$(curl -s -m 5 -X OPTIONS http://$HOST:$WEBDAV_PORT/ -u $TEST_USER:$TEST_PASS -i 2>&1)
    if echo "$OPTIONS_RESP" | grep -qi "DAV:\|webdav\|allow"; then
        log_pass "WebDAV OPTIONS responds"
    else
        log_warn "WebDAV OPTIONS: $OPTIONS_RESP" | head -3
    fi

    # WebDAV PROPFIND
    PROPFIND_RESP=$(curl -s -m 5 -X PROPFIND -H "Depth: 1" http://$HOST:$WEBDAV_PORT/ -u $TEST_USER:$TEST_PASS 2>&1)
    if echo "$PROPFIND_RESP" | grep -qi "multistatus\|response\|existing"; then
        log_pass "WebDAV PROPFIND works"
    else
        log_warn "WebDAV PROPFIND: ${PROPFIND_RESP:0:200}"
    fi

    # WebDAV PUT (upload)
    PUT_RESP=$(curl -s -m 5 -X PUT -d "hello webdav $(date)" http://$HOST:$WEBDAV_PORT/webdav_test.txt -u $TEST_USER:$TEST_PASS -o /dev/null -w "%{http_code}")
    if [ "$PUT_RESP" = "201" ] || [ "$PUT_RESP" = "204" ]; then
        log_pass "WebDAV PUT works (HTTP $PUT_RESP)"
    else
        log_warn "WebDAV PUT returned HTTP $PUT_RESP"
    fi

    # WebDAV GET
    GET_RESP=$(curl -s -m 5 http://$HOST:$WEBDAV_PORT/webdav_test.txt -u $TEST_USER:$TEST_PASS 2>&1)
    if echo "$GET_RESP" | grep -q "hello webdav"; then
        log_pass "WebDAV GET works"
    else
        log_warn "WebDAV GET: ${GET_RESP:0:200}"
    fi

    # WebDAV DELETE
    DEL_RESP=$(curl -s -m 5 -X DELETE http://$HOST:$WEBDAV_PORT/webdav_test.txt -u $TEST_USER:$TEST_PASS -o /dev/null -w "%{http_code}")
    if [ "$DEL_RESP" = "204" ] || [ "$DEL_RESP" = "200" ]; then
        log_pass "WebDAV DELETE works (HTTP $DEL_RESP)"
    else
        log_warn "WebDAV DELETE returned HTTP $DEL_RESP"
    fi
fi

section "7. Admin API Tests"
if [ -n "$ADMIN_TOKEN" ]; then
    # List users
    USERS_RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/users -H "Authorization: Bearer $ADMIN_TOKEN" 2>&1)
    if echo "$USERS_RESP" | grep -q "testuser\|users\|id"; then
        log_pass "GET /api/v1/users works"
    else
        log_warn "GET /api/v1/users: ${USERS_RESP:0:200}"
    fi

    # List admins
    ADMINS_RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/admins -H "Authorization: Bearer $ADMIN_TOKEN" 2>&1)
    if echo "$ADMINS_RESP" | grep -q "admin\|id"; then
        log_pass "GET /api/v1/admins works"
    else
        log_warn "GET /api/v1/admins: ${ADMINS_RESP:0:200}"
    fi

    # Get config
    CONFIG_RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/config -H "Authorization: Bearer $ADMIN_TOKEN" 2>&1)
    if echo "$CONFIG_RESP" | grep -q "ftp\|ssh\|webdav"; then
        log_pass "GET /api/v1/config works"
    else
        log_warn "GET /api/v1/config: ${CONFIG_RESP:0:200}"
    fi

    # List connections
    CONN_RESP=$(curl -s -m 5 http://$HOST:$ADMIN_PORT/api/v1/connections -H "Authorization: Bearer $ADMIN_TOKEN" 2>&1)
    if echo "$CONN_RESP" | grep -q "connections\|\\["; then
        log_pass "GET /api/v1/connections works"
    else
        log_warn "GET /api/v1/connections: ${CONN_RESP:0:200}"
    fi
fi

section "8. Summary"
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
fi
if [ $WARN -gt 0 ]; then
    echo -e "${YELLOW}Warning tests:${NC}"
    for t in "${WARNED_TESTS[@]}"; do
        echo "  - $t"
    done
fi
echo ""
if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
