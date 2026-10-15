/**
 * Latency Benchmark Browser Runner.
 * Controls headless Chrome instances via Puppeteer:
 * 1. Page 1: Web App Analyst Dashboard (http://127.0.0.1:8001/dashboard)
 * 2. Page 2: Kibana SOC Triage Board (http://127.0.0.1:5601/app/dashboards#/view/temp-soc-triage-board-dashboard?_g=(refreshInterval:(pause:!f,value:2000),time:(from:now-7d,to:now%2B1d)))
 * 
 * Drops test log file into incoming directory and tracks the 5 milestones with timestamps:
 * (a) Events indexed
 * (b) Alert created
 * (c) Alert visible in /api/dashboard-data
 * (d) Alert visible on /dashboard with the toast
 * (e) Kibana SOC Triage Board panels updated
 */

const puppeteer = require('D:\\PROJECTS\\SIEM-CORRELATION-ENGINE\\stack\\kibana-8.13.0\\node_modules\\puppeteer-core');
const fs = require('fs');
const path = require('path');
const http = require('http');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const APP_PORT = 8001;
const KIBANA_PORT = 5601;
const ES_PORT = 9200;

const APP_DASHBOARD_URL = `http://127.0.0.1:${APP_PORT}/dashboard`;
const APP_API_DATA_URL = `http://127.0.0.1:${APP_PORT}/api/dashboard-data`;
const KIBANA_DASHBOARD_URL = `http://127.0.0.1:${KIBANA_PORT}/app/dashboards#/view/temp-soc-triage-board-dashboard?_g=(refreshInterval:(pause:!f,value:2000),time:(from:now-7d,to:now%2B1d))`;

const INCOMING_DIR = path.resolve('temp_latency_incoming');

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function httpGetJson(url) {
    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    resolve(null);
                }
            });
        }).on('error', () => resolve(null));
    });
}

function httpPost(url, body) {
    return new Promise((resolve) => {
        const u = new URL(url);
        const req = http.request({
            hostname: u.hostname,
            port: u.port,
            path: u.pathname + u.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
            }
        }, (res) => {
            res.on('data', () => {});
            res.on('end', () => resolve(res.statusCode));
        });
        req.on('error', () => resolve(500));
        req.write(body);
        req.end();
    });
}

async function resetTemporaryIndices() {
    // Delete documents in temporary indices
    await httpPost(`http://127.0.0.1:${ES_PORT}/temp-latency-events/_delete_by_query?refresh=true`, JSON.stringify({ query: { match_all: {} } }));
    await httpPost(`http://127.0.0.1:${ES_PORT}/temp-latency-alerts/_delete_by_query?refresh=true`, JSON.stringify({ query: { match_all: {} } }));
}

async function runBenchmark() {
    console.log('[*] Launching headless browser for benchmark...');
    const browser = await puppeteer.launch({
        executablePath: CHROME_PATH,
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--window-size=1920,1080',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding'
        ]
    });

    try {
        const pageApp = await browser.newPage();
        await pageApp.setViewport({ width: 1440, height: 900 });

        // Ensure pageApp document.hidden is always false so background tab throttling never engages
        await pageApp.evaluateOnNewDocument(() => {
            Object.defineProperty(document, 'hidden', { value: false, writable: false });
            Object.defineProperty(document, 'visibilityState', { value: 'visible', writable: false });
        });

        console.log(`[*] Opening App /dashboard at ${APP_DASHBOARD_URL}...`);
        await pageApp.goto(APP_DASHBOARD_URL, { waitUntil: 'domcontentloaded', timeout: 30000 });

        const pageKibana = await browser.newPage();
        await pageKibana.setViewport({ width: 1440, height: 900 });
        await pageKibana.evaluateOnNewDocument(() => {
            Object.defineProperty(document, 'hidden', { value: false, writable: false });
            Object.defineProperty(document, 'visibilityState', { value: 'visible', writable: false });
        });

        console.log(`[*] Opening Kibana SOC Triage Board at ${KIBANA_DASHBOARD_URL}...`);
        await pageKibana.goto(KIBANA_DASHBOARD_URL, { waitUntil: 'networkidle2', timeout: 60000 });

        // Allow Kibana initial render
        console.log('[*] Waiting for Kibana dashboard initial render...');
        await sleep(6000);

        const results = [];

        for (let run = 1; run <= 3; run++) {
            console.log(`\n============================================================`);
            console.log(`  RUN ${run} / 3`);
            console.log(`============================================================`);

            const testIp = `198.51.100.8${run}`;

            // Clear temporary indices
            await resetTemporaryIndices();
            
            // Clear any lingering toasts on pageApp
            await pageApp.evaluate(() => {
                const container = document.getElementById('toast-container');
                if (container) container.innerHTML = '';
            });

            // Wait for App and Kibana to reflect reset state
            console.log('[*] Waiting for App and Kibana to reflect clean state...');
            for (let i = 0; i < 30; i++) {
                const api = await httpGetJson(APP_API_DATA_URL);
                const appCounts = api && api.counts ? api.counts.total : 0;
                const kibanaClean = await pageKibana.evaluate((ip) => {
                    const body = document.body.innerText || '';
                    return !body.includes(ip);
                }, testIp);
                if (appCounts === 0 && kibanaClean) break;
                await sleep(500);
            }

            // Clean incoming folder
            if (fs.existsSync(INCOMING_DIR)) {
                for (const f of fs.readdirSync(INCOMING_DIR)) {
                    const fp = path.join(INCOMING_DIR, f);
                    if (fs.statSync(fp).isFile()) fs.unlinkSync(fp);
                }
            } else {
                fs.mkdirSync(INCOMING_DIR, { recursive: true });
            }

            // Prepare 6 failed logins for IP 198.51.100.8{run}
            const logLines = [
                `Oct 15 14:00:01 srv01 sshd[101]: Failed password for invalid user admin from ${testIp} port 2201 ssh2\n`,
                `Oct 15 14:00:02 srv01 sshd[102]: Failed password for invalid user admin from ${testIp} port 2202 ssh2\n`,
                `Oct 15 14:00:03 srv01 sshd[103]: Failed password for invalid user admin from ${testIp} port 2203 ssh2\n`,
                `Oct 15 14:00:04 srv01 sshd[104]: Failed password for invalid user admin from ${testIp} port 2204 ssh2\n`,
                `Oct 15 14:00:05 srv01 sshd[105]: Failed password for invalid user admin from ${testIp} port 2205 ssh2\n`,
                `Oct 15 14:00:06 srv01 sshd[106]: Failed password for invalid user admin from ${testIp} port 2206 ssh2\n`
            ].join('');

            const targetFilePath = path.join(INCOMING_DIR, `auth_test_run_${run}.log`);

            console.log(`[*] Dropping file ${path.basename(targetFilePath)} into ./temp_latency_incoming...`);
            const t0 = Date.now();
            fs.writeFileSync(targetFilePath, logLines, 'utf8');
            const isoT0 = new Date(t0).toISOString();
            console.log(`    [T0] File dropped at: ${isoT0}`);

            let tA = null;
            let tB = null;
            let tC = null;
            let tD = null;
            let tE = null;

            const maxWaitMs = 45000;
            const startTime = Date.now();

            while (Date.now() - startTime < maxWaitMs) {
                const now = Date.now();

                // (a) Check events indexed
                if (!tA) {
                    const evRes = await httpGetJson(`http://127.0.0.1:${ES_PORT}/temp-latency-events/_count`);
                    if (evRes && evRes.count >= 6) {
                        tA = now;
                        console.log(`    (a) Events indexed:          +${((tA - t0) / 1000).toFixed(2)}s (${new Date(tA).toISOString()})`);
                    }
                }

                // (b) Check alert created
                if (!tB) {
                    const alRes = await httpGetJson(`http://127.0.0.1:${ES_PORT}/temp-latency-alerts/_count`);
                    if (alRes && alRes.count >= 1) {
                        tB = now;
                        console.log(`    (b) Alert created:           +${((tB - t0) / 1000).toFixed(2)}s (${new Date(tB).toISOString()})`);
                    }
                }

                // (c) Check alert visible in /api/dashboard-data
                if (!tC) {
                    const apiData = await httpGetJson(APP_API_DATA_URL);
                    if (apiData && apiData.counts && (apiData.counts.total >= 1 || apiData.counts.high >= 1)) {
                        tC = now;
                        console.log(`    (c) Visible in API:          +${((tC - t0) / 1000).toFixed(2)}s (${new Date(tC).toISOString()})`);
                    }
                }

                // (d) Check alert visible on /dashboard with toast
                if (!tD) {
                    const toastCount = await pageApp.evaluate(() => {
                        return document.querySelectorAll('.toast').length;
                    });
                    if (toastCount > 0) {
                        tD = now;
                        console.log(`    (d) Toast on /dashboard:     +${((tD - t0) / 1000).toFixed(2)}s (${new Date(tD).toISOString()})`);
                    }
                }

                // (e) Check Kibana SOC Triage Board panels updated
                if (!tE) {
                    const kibanaUpdated = await pageKibana.evaluate((ip) => {
                        const body = document.body.innerText || '';
                        const hasAlertText = body.includes('Brute Force') && body.includes(ip);
                        const metricValues = Array.from(document.querySelectorAll('.lnsXYMetricView__primaryValue, .euiStat__title'));
                        const metricAboveZero = metricValues.some(el => {
                            const val = parseInt(el.innerText.trim(), 10);
                            return !isNaN(val) && val > 0;
                        });
                        return hasAlertText || (metricAboveZero && body.includes(ip));
                    }, testIp);

                    if (kibanaUpdated) {
                        tE = now;
                        console.log(`    (e) Kibana panels updated:   +${((tE - t0) / 1000).toFixed(2)}s (${new Date(tE).toISOString()})`);
                    }
                }

                if (tA && tB && tC && tD && tE) {
                    break;
                }

                await sleep(100);
            }

            const runResult = {
                run,
                t0_iso: isoT0,
                step_a_sec: tA ? (tA - t0) / 1000 : null,
                step_b_sec: tB ? (tB - t0) / 1000 : null,
                step_c_sec: tC ? (tC - t0) / 1000 : null,
                step_d_sec: tD ? (tD - t0) / 1000 : null,
                step_e_sec: tE ? (tE - t0) / 1000 : null,
                tA_iso: tA ? new Date(tA).toISOString() : null,
                tB_iso: tB ? new Date(tB).toISOString() : null,
                tC_iso: tC ? new Date(tC).toISOString() : null,
                tD_iso: tD ? new Date(tD).toISOString() : null,
                tE_iso: tE ? new Date(tE).toISOString() : null,
            };

            results.push(runResult);
        }

        console.log('\n[*] Benchmark complete. Emitting results JSON...');
        fs.writeFileSync('latency_results.json', JSON.stringify(results, null, 2), 'utf8');
        return results;
    } finally {
        await browser.close();
    }
}

runBenchmark().catch(err => {
    console.error('[!] Benchmark error:', err);
    process.exit(1);
});
