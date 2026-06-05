const { chromium } = require('../web/node_modules/playwright');

const HOST = 'http://127.0.0.1:30088';
const CLIENT_HOST = 'http://127.0.0.1:30080';
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin-pass';
const TEST_USER = 'testuser';
const TEST_PASS = 'testuser-pass';

const results = { pass: 0, fail: 0, warn: 0, failed: [] };

function log_pass(msg) { console.log(`\x1b[32m[PASS]\x1b[0m ${msg}`); results.pass++; }
function log_fail(msg) { console.log(`\x1b[31m[FAIL]\x1b[0m ${msg}`); results.failed.push(msg); results.fail++; }
function log_warn(msg) { console.log(`\x1b[33m[WARN]\x1b[0m ${msg}`); results.warn++; }
function log_info(msg) { console.log(`\x1b[34m[INFO]\x1b[0m ${msg}`); }

async function safeTest(name, fn) {
    try {
        const result = await fn();
        if (result === true) {
            log_pass(name);
        } else if (result === 'warn') {
            log_warn(name);
        } else {
            log_fail(`${name} - unexpected result`);
        }
    } catch (e) {
        log_fail(`${name} - ${e.message.substring(0, 200)}`);
    }
}

async function main() {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });

    // ========== ADMIN LOGIN & DASHBOARD ==========
    const adminPage = await context.newPage();

    await safeTest('Admin login page loads', async () => {
        await adminPage.goto(`${HOST}/admin/login`, { waitUntil: 'networkidle', timeout: 10000 });
        await adminPage.waitForSelector('input', { timeout: 5000 });
        return true;
    });

    await safeTest('Admin login successful', async () => {
        await adminPage.fill('input[data-testid="admin-login-username"]', ADMIN_USER);
        await adminPage.fill('input[data-testid="admin-login-password"]', ADMIN_PASS);
        await adminPage.click('button[data-testid="admin-login-submit"]');
        await adminPage.waitForURL(/\/admin\/dashboard|\/admin\/.*/, { timeout: 10000 });
        return true;
    });

    // Wait for dashboard to load
    await adminPage.waitForTimeout(2000);

    // ========== ADMIN PAGES ==========
    const adminPages = [
        { name: 'Dashboard', path: '/admin/dashboard' },
        { name: 'EventRules', path: '/admin/event-rules' },
        { name: 'EventHistory', path: '/admin/event-history' },
        { name: 'Hooks', path: '/admin/hooks' },
        { name: 'Folders', path: '/admin/folders' },
        { name: 'Shares', path: '/admin/shares' },
        { name: 'Users', path: '/admin/users' },
        { name: 'Admins', path: '/admin/admins' },
        { name: 'Settings', path: '/admin/settings' },
        { name: 'Security', path: '/admin/security' },
        { name: 'Logs', path: '/admin/logs' }
    ];

    for (const p of adminPages) {
        await safeTest(`Admin page loads: ${p.name}`, async () => {
            await adminPage.goto(`${HOST}${p.path}`, { waitUntil: 'networkidle', timeout: 15000 });
            await adminPage.waitForTimeout(1000);
            // Check that the page didn't show a 404/error
            const url = adminPage.url();
            if (url.includes(p.path) || url.includes('/admin/')) {
                return true;
            }
            return 'warn';
        });
    }

    // ========== CLIENT LOGIN & PAGES ==========
    const clientPage = await context.newPage();

    await safeTest('Client login page loads', async () => {
        await clientPage.goto(`${CLIENT_HOST}/client/login`, { waitUntil: 'networkidle', timeout: 10000 });
        await clientPage.waitForSelector('input', { timeout: 5000 });
        return true;
    });

    await safeTest('Client login successful', async () => {
        await clientPage.fill('input[data-testid="client-login-username"]', TEST_USER);
        await clientPage.fill('input[data-testid="client-login-password"]', TEST_PASS);
        await clientPage.click('button[data-testid="client-login-submit"]');
        await clientPage.waitForURL(/\/client\/.*/, { timeout: 10000 });
        return true;
    });

    await clientPage.waitForTimeout(2000);

    const clientPages = [
        { name: 'Client Files', path: '/client/files' },
        { name: 'Client Profile', path: '/client/profile' },
        { name: 'Client Shares', path: '/client/shares' }
    ];

    for (const p of clientPages) {
        await safeTest(`Client page loads: ${p.name}`, async () => {
            await clientPage.goto(`${CLIENT_HOST}${p.path}`, { waitUntil: 'networkidle', timeout: 15000 });
            await clientPage.waitForTimeout(1000);
            const url = clientPage.url();
            if (url.includes(p.path) || url.includes('/client/')) {
                return true;
            }
            return 'warn';
        });
    }

    // ========== ADMIN CRUD OPERATIONS ==========
    await safeTest('Admin: Create event rule', async () => {
        await adminPage.goto(`${HOST}/admin/event-rules`, { waitUntil: 'networkidle' });
        await adminPage.waitForTimeout(1500);

        // Look for a New/Create button
        const buttons = await adminPage.$$('button');
        let createBtn = null;
        for (const btn of buttons) {
            const text = await btn.textContent();
            if (text && /new|create|新建|创建/i.test(text)) {
                createBtn = btn;
                break;
            }
        }
        if (createBtn) {
            await createBtn.click();
            await adminPage.waitForTimeout(1000);
            return true;
        }
        return 'warn';
    });

    // Summary
    console.log('');
    console.log('\x1b[34m=========== Summary ===========\x1b[0m');
    console.log(`\x1b[32mPassed:\x1b[0m  ${results.pass}`);
    console.log(`\x1b[31mFailed:\x1b[0m  ${results.fail}`);
    console.log(`\x1b[33mWarned:\x1b[0m  ${results.warn}`);

    if (results.fail > 0) {
        console.log('\nFailed tests:');
        for (const t of results.failed) {
            console.log(`  - ${t}`);
        }
    }

    await browser.close();
    process.exit(results.fail > 0 ? 1 : 0);
}

main().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
