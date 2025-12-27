/**
 * AppAudix Security Scan GitHub Action
 *
 * Scans mobile applications (APK, AAB, IPA) for security vulnerabilities
 * and compliance issues against PCI-DSS, OWASP MASVS, HIPAA, GDPR, and more.
 *
 * Copyright (c) 2025 AppAudix, LLC
 */

const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch');

// Severity levels in order of priority
const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'none'];

/**
 * Main action entry point
 */
async function run() {
    try {
        // Get inputs
        const apiKey = core.getInput('api-key', { required: true });
        const filePath = core.getInput('file', { required: true });
        const frameworks = core.getInput('frameworks') || 'pci_dss';
        const failOn = core.getInput('fail-on') || 'critical';
        const uploadSarif = core.getInput('upload-sarif') === 'true';
        const waitForCompletion = core.getInput('wait-for-completion') !== 'false';
        const timeoutMinutes = parseInt(core.getInput('timeout-minutes') || '30', 10);
        const apiUrl = core.getInput('api-url') || 'https://api.appaudix.com';

        // Validate file exists
        if (!fs.existsSync(filePath)) {
            throw new Error(`File not found: ${filePath}`);
        }

        const fileStats = fs.statSync(filePath);
        const fileName = path.basename(filePath);
        const fileSizeMB = (fileStats.size / (1024 * 1024)).toFixed(2);

        core.info(`📱 AppAudix Security Scan`);
        core.info(`   File: ${fileName} (${fileSizeMB} MB)`);
        core.info(`   Frameworks: ${frameworks}`);
        core.info(`   Fail on: ${failOn}`);

        // Submit scan
        core.startGroup('Uploading app for scanning...');
        const scanResult = await submitScan(apiUrl, apiKey, filePath, fileName, frameworks);
        core.endGroup();

        const scanId = scanResult.scan_id;
        core.info(`✅ Scan submitted: ${scanId}`);
        core.setOutput('scan-id', scanId);

        if (!waitForCompletion) {
            core.info(`⏭️ Not waiting for completion (wait-for-completion=false)`);
            core.setOutput('status', 'queued');
            return;
        }

        // Poll for completion
        core.startGroup('Waiting for scan to complete...');
        const finalStatus = await pollForCompletion(apiUrl, apiKey, scanId, timeoutMinutes);
        core.endGroup();

        if (finalStatus.status !== 'completed') {
            throw new Error(`Scan did not complete successfully. Status: ${finalStatus.status}`);
        }

        // Extract results
        const results = finalStatus.results || {};
        const complianceScore = results.compliance_score || 0;
        const riskLevel = results.risk_level || 'UNKNOWN';
        const criticalCount = results.critical_issues || 0;
        const highCount = results.high_issues || 0;
        const mediumCount = results.medium_issues || 0;
        const lowCount = results.low_issues || 0;

        // Set outputs
        core.setOutput('status', 'completed');
        core.setOutput('compliance-score', complianceScore.toString());
        core.setOutput('risk-level', riskLevel);
        core.setOutput('critical-count', criticalCount.toString());
        core.setOutput('high-count', highCount.toString());
        core.setOutput('medium-count', mediumCount.toString());
        core.setOutput('low-count', lowCount.toString());
        core.setOutput('report-url', `https://pciappscan.com/dashboard/scans/${scanId}`);

        // Display summary
        core.info('');
        core.info('📊 Scan Results');
        core.info(`   Compliance Score: ${complianceScore}%`);
        core.info(`   Risk Level: ${riskLevel}`);
        core.info(`   Critical: ${criticalCount} | High: ${highCount} | Medium: ${mediumCount} | Low: ${lowCount}`);

        // Upload SARIF if requested
        if (uploadSarif) {
            core.startGroup('Uploading SARIF to GitHub Code Scanning...');
            try {
                const sarifPath = await downloadSarif(apiUrl, apiKey, scanId);
                core.setOutput('sarif-file', sarifPath);
                await uploadSarifToGitHub(sarifPath);
                core.info('✅ SARIF uploaded to GitHub Code Scanning');
            } catch (sarifError) {
                core.warning(`Failed to upload SARIF: ${sarifError.message}`);
            }
            core.endGroup();
        }

        // Check fail conditions
        const shouldFail = checkFailCondition(failOn, criticalCount, highCount, mediumCount, lowCount);

        if (shouldFail) {
            const failMessage = `Security scan failed: Found issues at or above '${failOn}' severity`;
            core.setFailed(failMessage);
        } else {
            core.info('');
            core.info('✅ Security scan passed');
        }

    } catch (error) {
        core.setFailed(`Action failed: ${error.message}`);
    }
}

/**
 * Submit a scan to the AppAudix API
 */
async function submitScan(apiUrl, apiKey, filePath, fileName, frameworks) {
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath), fileName);

    // Add each framework separately (API expects array)
    const frameworkList = frameworks.split(',').map(f => f.trim());
    for (const framework of frameworkList) {
        form.append('frameworks', framework);
    }

    const response = await fetch(`${apiUrl}/v2/scans`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            ...form.getHeaders()
        },
        body: form
    });

    if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`Failed to submit scan: ${response.status} ${response.statusText} - ${errorBody}`);
    }

    const result = await response.json();

    if (!result.success) {
        throw new Error(`API error: ${result.error?.message || 'Unknown error'}`);
    }

    return result.data;
}

/**
 * Poll the API until scan completes or times out
 */
async function pollForCompletion(apiUrl, apiKey, scanId, timeoutMinutes) {
    const startTime = Date.now();
    const timeoutMs = timeoutMinutes * 60 * 1000;
    const pollIntervalMs = 15000; // 15 seconds

    let lastProgress = -1;

    while (Date.now() - startTime < timeoutMs) {
        const status = await getScanStatus(apiUrl, apiKey, scanId);

        // Log progress updates
        const progress = status.progress || 0;
        if (progress !== lastProgress) {
            const message = status.message || status.status;
            core.info(`   [${progress}%] ${message}`);
            lastProgress = progress;
        }

        // Check if done
        if (status.status === 'completed' || status.status === 'error' || status.status === 'cancelled') {
            return status;
        }

        // Wait before next poll
        await sleep(pollIntervalMs);
    }

    throw new Error(`Scan timed out after ${timeoutMinutes} minutes`);
}

/**
 * Get current scan status
 */
async function getScanStatus(apiUrl, apiKey, scanId) {
    const response = await fetch(`${apiUrl}/v2/scans/${scanId}`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        }
    });

    if (!response.ok) {
        throw new Error(`Failed to get scan status: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();

    if (!result.success) {
        throw new Error(`API error: ${result.error?.message || 'Unknown error'}`);
    }

    return result.data;
}

/**
 * Download SARIF report
 */
async function downloadSarif(apiUrl, apiKey, scanId) {
    const response = await fetch(`${apiUrl}/v2/scans/${scanId}/report?format=sarif`, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${apiKey}`
        }
    });

    if (!response.ok) {
        throw new Error(`Failed to download SARIF: ${response.status} ${response.statusText}`);
    }

    const sarifContent = await response.text();
    const sarifPath = path.join(process.env.RUNNER_TEMP || '/tmp', `appaudix-${scanId}.sarif`);

    fs.writeFileSync(sarifPath, sarifContent);
    core.info(`   Downloaded SARIF to ${sarifPath}`);

    return sarifPath;
}

/**
 * Upload SARIF file to GitHub Code Scanning
 */
async function uploadSarifToGitHub(sarifPath) {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
        throw new Error('GITHUB_TOKEN not available. Ensure the job has `permissions: security-events: write`');
    }

    const octokit = github.getOctokit(token);
    const context = github.context;

    // Read and compress SARIF
    const sarifContent = fs.readFileSync(sarifPath, 'utf8');
    const zlib = require('zlib');
    const sarifGzip = zlib.gzipSync(sarifContent);
    const sarifBase64 = sarifGzip.toString('base64');

    // Get the commit SHA
    const commitSha = context.sha;
    const ref = context.ref;

    core.info(`   Uploading to ${context.repo.owner}/${context.repo.repo}`);
    core.info(`   Commit: ${commitSha.substring(0, 7)}`);
    core.info(`   Ref: ${ref}`);

    await octokit.rest.codeScanning.uploadSarif({
        owner: context.repo.owner,
        repo: context.repo.repo,
        commit_sha: commitSha,
        ref: ref,
        sarif: sarifBase64,
        tool_name: 'AppAudix'
    });
}

/**
 * Check if the build should fail based on severity threshold
 */
function checkFailCondition(failOn, critical, high, medium, low) {
    const failIndex = SEVERITY_LEVELS.indexOf(failOn.toLowerCase());

    if (failIndex === -1 || failOn.toLowerCase() === 'none') {
        return false; // Never fail
    }

    // Check each severity level up to the threshold
    if (failIndex <= 0 && critical > 0) return true;  // critical
    if (failIndex <= 1 && high > 0) return true;      // high
    if (failIndex <= 2 && medium > 0) return true;    // medium
    if (failIndex <= 3 && low > 0) return true;       // low

    return false;
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Run the action
run();
