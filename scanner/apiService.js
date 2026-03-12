#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// Debug mode - controlled by DEBUG_MODE environment variable (default: false)
const DEBUG_MODE = process.env.DEBUG_MODE === 'true';

/**
 * Mask sensitive values for logging
 * @param {string} value - The value to mask
 * @returns {string} - Masked value
 */
function maskValue(value) {
  if (!value || value.length <= 8) return '****';
  return value.substring(0, 4) + '****' + value.substring(value.length - 4);
}

/**
 * Log message only in debug mode
 * @param {...any} args - Arguments to log
 */
function debugLog(...args) {
  if (DEBUG_MODE) {
    console.log(...args);
  }
}

// Print environment variables on startup (only in debug mode)
if (DEBUG_MODE) {
  console.log('\n========== Environment Variables ==========');
  console.log(`NT_API_KEY:', ${process.env.NT_API_KEY}`);
  console.log(`NT_SECRET_KEY: ${process.env.NT_SECRET_KEY}`);
  console.log(`PROJECT_ID: ${process.env.PROJECT_ID || 'NOT SET'}`);
  console.log(`ORGANIZATION_ID: ${process.env.ORGANIZATION_ID || 'NOT SET'}`);
  console.log(`BUILD_ID: ${process.env.BUILD_ID || 'NOT SET'}`);
  console.log(`JOB_NAME: ${process.env.JOB_NAME || 'NOT SET'}`);
  console.log(`GIT_URL: ${process.env.GIT_URL || 'NOT SET'}`);
  console.log(`GIT_BRANCH: ${process.env.GIT_BRANCH || 'NOT SET'}`);
  console.log(`WORKSPACE: ${process.env.WORKSPACE || 'NOT SET'}`);
  console.log(`DEBUG_MODE: ${DEBUG_MODE}`);
  console.log('==========================================\n');
} else {
  console.log(`Starting API Service (Debug Mode: OFF)`);
}

/**
 * Parse all report files from the output directory
 * @param {string} outputDir - Directory containing scan reports
 * @returns {object} - Object containing all parsed reports
 */
function parseReportFiles(outputDir) {
  debugLog(`\nParsing report files from: ${outputDir}`);

  const reports = {
    sbom: null,
    trivyConfig: null,
    trivyVuln: null,
    gitleaks: null
  };

  // Define report file paths
  const reportFiles = {
    sbom: path.join(outputDir, 'cyclonedx.json'),
    trivyConfig: path.join(outputDir, 'trivy-config-report.json'),
    trivyVuln: path.join(outputDir, 'trivy-vuln-report.json'),
    gitleaks: path.join(outputDir, 'gitleaks-report.json')
  };

  // Parse each report file
  for (const [key, filePath] of Object.entries(reportFiles)) {
    try {
      if (fs.existsSync(filePath)) {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        reports[key] = JSON.parse(fileContent);
        debugLog(`✓ Parsed ${key} report: ${filePath}`);
      } else {
        debugLog(`⚠ Report file not found: ${filePath}`);
      }
    } catch (error) {
      console.error(`✗ Error parsing ${key} report (${filePath}):`, error.message);
    }
  }

  return reports;
}

/**
 * Transform Trivy config report to configScanResponseDto format
 * @param {object} trivyConfig - Trivy config scan report
 * @returns {object} - Transformed config scan response
 */
function transformConfigScanResponse(trivyConfig) {
  if (!trivyConfig) return null;

  const results = [];
  let totalMisconfigurations = 0;

  if (trivyConfig.Results && Array.isArray(trivyConfig.Results)) {
    trivyConfig.Results.forEach(result => {
      if (result.Misconfigurations && result.Misconfigurations.length > 0) {
        totalMisconfigurations += result.Misconfigurations.length;

        results.push({
          Target: result.Target,
          Class: result.Class || 'config',
          Type: result.Type || 'kubernetes',
          Misconfigurations: result.Misconfigurations.map(misc => ({
            ID: misc.ID,
            Title: misc.Title,
            Description: misc.Description || '',
            Message: misc.Message || '',
            Severity: misc.Severity || 'UNKNOWN',
            PrimaryURL: misc.PrimaryURL || '',
            Query: misc.Query || '',
            Resolution: misc.Resolution || ''
          }))
        });
      }
    });
  }

  return {
    ArtifactName: trivyConfig.ArtifactName || process.env.WORKSPACE || process.cwd(),
    ArtifactType: trivyConfig.ArtifactType || 'filesystem',
    Results: results,
    TotalMisconfigurations: totalMisconfigurations
  };
}

/**
 * Transform Gitleaks report to scannerSecretResponse format
 * @param {object} gitleaksReport - Gitleaks scan report
 * @returns {array} - Array of secret findings (duplicates removed)
 */
function transformSecretScanResponse(gitleaksReport) {
  if (!gitleaksReport || !Array.isArray(gitleaksReport)) return [];

  const transformed = gitleaksReport.map(finding => ({
    RuleID: finding.RuleID || finding.Rule || '',
    Description: finding.Description || `Detect ${finding.RuleID || 'secret'}`,
    File: finding.File || '',
    Match: finding.Match || '',
    Secret: finding.Secret || finding.Match || '',
    StartLine: finding.StartLine ? String(finding.StartLine) : '0',
    EndLine: finding.EndLine ? String(finding.EndLine) : '0',
    StartColumn: finding.StartColumn ? String(finding.StartColumn) : '0',
    EndColumn: finding.EndColumn ? String(finding.EndColumn) : '0'
  }));

  // Remove duplicates based on File, Secret, and location (line/column)
  const seen = new Map();
  const deduplicated = [];

  for (const item of transformed) {
    // Create a unique key based on all relevant fields
    const key = `${item.File}|${item.Secret}|${item.StartLine}|${item.EndLine}|${item.StartColumn}|${item.EndColumn}`;

    if (!seen.has(key)) {
      seen.set(key, true);
      deduplicated.push(item);
    }
  }

  debugLog(`\n🔍 Secret deduplication: ${transformed.length} entries → ${deduplicated.length} unique entries`);

  return deduplicated;
}

/**
 * Create multipart form data boundary and payload
 * @param {object} combinedScanRequest - Combined scan request object
 * @param {string} sbomFilePath - Path to SBOM file
 * @param {string} boundary - Multipart boundary string
 * @param {object} options - Additional options (repoName, branchName, etc.)
 * @returns {Buffer} - Multipart form data buffer
 */
function createMultipartFormData(combinedScanRequest, sbomFilePath, boundary, options = {}) {
  const parts = [];
  const CRLF = '\r\n';

  // Add combinedScanRequest field
  parts.push(
    `--${boundary}${CRLF}`,
    `Content-Disposition: form-data; name="combinedScanRequest"${CRLF}`,
    `Content-Type: application/json${CRLF}${CRLF}`,
    JSON.stringify(combinedScanRequest),
    CRLF
  );

  // Add sbomFile field
  if (fs.existsSync(sbomFilePath)) {
    const sbomContent = fs.readFileSync(sbomFilePath);
    const fileName = path.basename(sbomFilePath);

    parts.push(
      `--${boundary}${CRLF}`,
      `Content-Disposition: form-data; name="sbomFile"; filename="${fileName}"${CRLF}`,
      `Content-Type: application/json${CRLF}${CRLF}`
    );
    parts.push(sbomContent);
    parts.push(CRLF);
  }

  // Add displayName field (required)
  parts.push(
    `--${boundary}${CRLF}`,
    `Content-Disposition: form-data; name="displayName"${CRLF}${CRLF}`,
    'sbom',
    CRLF
  );

  // Add source field (required) - indicates CI/CD source
  parts.push(
    `--${boundary}${CRLF}`,
    `Content-Disposition: form-data; name="source"${CRLF}${CRLF}`,
    'jenkins',
    CRLF
  );

  // Add organizationId field (optional) - if provided via environment
  const organizationId = process.env.ORGANIZATION_ID;
  if (organizationId) {
    parts.push(
      `--${boundary}${CRLF}`,
      `Content-Disposition: form-data; name="organizationId"${CRLF}${CRLF}`,
      organizationId,
      CRLF
    );
  }

  // Add jobId field (optional) - from Jenkins environment (BUILD_ID or BUILD_NUMBER)
  const jobId = process.env.BUILD_ID || process.env.BUILD_NUMBER;
  if (jobId) {
    parts.push(
      `--${boundary}${CRLF}`,
      `Content-Disposition: form-data; name="jobId"${CRLF}${CRLF}`,
      jobId,
      CRLF
    );
  }

  // Add repoName field (optional) - repository name from Jenkins environment
  // This is passed as a parameter from the calling function
  if (options.repoName) {
    parts.push(
      `--${boundary}${CRLF}`,
      `Content-Disposition: form-data; name="repoName"${CRLF}${CRLF}`,
      options.repoName,
      CRLF
    );
  }

  // Add branchName field (optional) - branch name from Jenkins environment
  // This is passed as a parameter from the calling function
  if (options.branchName) {
    parts.push(
      `--${boundary}${CRLF}`,
      `Content-Disposition: form-data; name="branchName"${CRLF}${CRLF}`,
      options.branchName,
      CRLF
    );
  }

  // Add closing boundary
  parts.push(`--${boundary}--${CRLF}`);

  // Convert parts to buffer
  const buffers = parts.map(part => {
    if (Buffer.isBuffer(part)) {
      return part;
    }
    return Buffer.from(part, 'utf8');
  });

  return Buffer.concat(buffers);
}

/**
 * Extract repository name and branch from Git URL
 * @param {string} gitUrl - Git repository URL
 * @returns {object} - Object containing repoName and provider
 */
function extractRepoInfoFromGitUrl(gitUrl) {
  if (!gitUrl) return { repoName: null, provider: null };

  try {
    // Detect provider and extract repo name
    if (gitUrl.includes('github.com')) {
      // GitHub URL patterns:
      // https://github.com/owner/repo.git
      // git@github.com:owner/repo.git
      const match = gitUrl.match(/github\.com[/:]([\w-]+\/[\w-]+?)(\.git)?$/);
      return {
        repoName: match ? match[1] : null,
        provider: 'github'
      };
    } else if (gitUrl.includes('gitlab.com') || gitUrl.includes('gitlab')) {
      // GitLab URL patterns:
      // https://gitlab.com/owner/repo.git
      // git@gitlab.com:owner/repo.git
      const match = gitUrl.match(/gitlab[^/:]*[/:]([\w-]+\/[\w-]+?)(\.git)?$/);
      return {
        repoName: match ? match[1] : null,
        provider: 'gitlab'
      };
    }

    // Generic Git URL - try to extract repo name
    const genericMatch = gitUrl.match(/[/:]([\w-]+\/[\w-]+?)(\.git)?$/);
    return {
      repoName: genericMatch ? genericMatch[1] : null,
      provider: 'unknown'
    };
  } catch (error) {
    debugLog(`Error parsing Git URL: ${error.message}`);
    return { repoName: null, provider: null };
  }
}

/**
 * Clean branch name (remove origin/ prefix if present)
 * @param {string} branchName - Raw branch name
 * @returns {string} - Cleaned branch name
 */
function cleanBranchName(branchName) {
  if (!branchName) return null;

  // Remove "origin/" or "refs/heads/" prefix
  return branchName
    .replace(/^origin\//, '')
    .replace(/^refs\/heads\//, '')
    .trim();
}

/**
 * Get repository and branch information from Jenkins environment
 * Supports both GitHub and GitLab projects
 * @returns {object} - Object containing repoName, branchName, and provider
 */
function getRepoAndBranchInfo() {
  // Get Git URL from Jenkins environment
  const gitUrl = process.env.GIT_URL || process.env.GIT_URL_1;

  // Extract repo name and provider from Git URL
  const { repoName: extractedRepoName, provider } = extractRepoInfoFromGitUrl(gitUrl);

  // Get repo name (priority: extracted from Git URL > JOB_NAME > REPO_NAME)
  const repoName = extractedRepoName || process.env.JOB_NAME || process.env.REPO_NAME;

  // Get branch name from Jenkins environment and clean it
  const rawBranchName = process.env.GIT_BRANCH || process.env.BRANCH_NAME;
  const branchName = cleanBranchName(rawBranchName);
  const username = process.env.BUILD_USER || process.env.BUILD_USER_ID || null;

  debugLog(`\n🔍 Repository Detection:`);
  debugLog(`  Git URL: ${gitUrl || 'NOT SET'}`);
  debugLog(`  Detected Provider: ${provider || 'unknown'}`);
  debugLog(`  Repo Name: ${repoName || 'NOT SET'}`);
  debugLog(`  Raw Branch: ${rawBranchName || 'NOT SET'}`);
  debugLog(`  Cleaned Branch: ${branchName || 'NOT SET'}`);
  debugLog(`  username: ${username || 'NOT SET'}`);

  return { repoName, branchName, provider, username };
}

/**
 * Send parsed reports to an API endpoint
 * @param {object} reports - Parsed report data
 * @param {string} apiUrl - API endpoint URL (optional, will use default if not provided)
 * @param {object} options - Additional options (headers, method, etc.)
 * @returns {Promise} - Promise resolving to API response
 */
function sendToAPI(reports, apiUrl, options = {}) {
  return new Promise((resolve, reject) => {
    // Get PROJECT_ID from environment (optional)
    const projectId = process.env.PROJECT_ID;

    // Construct the API URL with projectId if provided
    const fullApiUrl = projectId
      ? `${apiUrl}/open-pulse/project/upload-all/${projectId}`
      : `${apiUrl}/open-pulse/project/upload-all`;

    console.log(`\nSending reports to API: ${fullApiUrl}`);

    // Parse the URL
    const url = new URL(fullApiUrl);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    // Transform reports to combinedScanRequest format
    const configScanResponseDto = transformConfigScanResponse(reports.trivyConfig);
    const scannerSecretResponse = transformSecretScanResponse(reports.gitleaks);

    // Get repo and branch information from Jenkins environment (with GitHub/GitLab detection)
    const { repoName, branchName, provider, username } = getRepoAndBranchInfo();

    console.log(`\n📦 Repository Info: ${repoName || 'Unknown'} (${provider || 'unknown'})`);
    console.log(`🌿 Branch: ${branchName || 'Unknown'}`);
    console.log(`👤 Username: ${username || 'Unknown'}`);

    const combinedScanRequest = {
      configScanResponseDto,
      scannerSecretResponse,
      repoName: repoName || null,
      branchName: branchName || null,
      username: username || null
    };

    // Always show summary counts
    const misconfigCount = configScanResponseDto ? configScanResponseDto.TotalMisconfigurations : 0;
    const secretCount = scannerSecretResponse.length;
    console.log(`\n📊 Scan Summary: ${misconfigCount} misconfiguration(s), ${secretCount} secret(s)`);

    debugLog('\n📋 CombinedScanRequest Structure:');
    if (configScanResponseDto) {
      debugLog(`  - configScanResponseDto:`);
      debugLog(`      ArtifactName: ${configScanResponseDto.ArtifactName}`);
      debugLog(`      ArtifactType: ${configScanResponseDto.ArtifactType}`);
      debugLog(`      Results count: ${configScanResponseDto.Results.length}`);
      debugLog(`      Total Misconfigurations: ${configScanResponseDto.TotalMisconfigurations}`);
      configScanResponseDto.Results.forEach((result, idx) => {
        debugLog(`      Result ${idx + 1}: ${result.Target} (${result.Misconfigurations.length} issues)`);
        result.Misconfigurations.forEach((misc, miscIdx) => {
          debugLog(`        ${miscIdx + 1}. ID: ${misc.ID}`);
          debugLog(`           Title: ${misc.Title}`);
          debugLog(`           Severity: ${misc.Severity}`);
          if (misc.Description) debugLog(`           Description: ${misc.Description}`);
          if (misc.Message) debugLog(`           Message: ${misc.Message}`);
          if (misc.Query) debugLog(`           Query: ${misc.Query}`);
          if (misc.Resolution) debugLog(`           Resolution: ${misc.Resolution}`);
        });
      });
    }
    debugLog(`  - scannerSecretResponse count: ${scannerSecretResponse.length}`);
    if (scannerSecretResponse.length > 0) {
      debugLog(`      Secrets found:`);
      scannerSecretResponse.forEach((secret, idx) => {
        debugLog(`        ${idx + 1}. RuleID: ${secret.RuleID}`);
        debugLog(`           Description: ${secret.Description}`);
        debugLog(`           File: ${secret.File}`);
        debugLog(`           Secret: ${maskValue(secret.Secret)}`);
        debugLog(`           Location: Line ${secret.StartLine}:${secret.StartColumn} - ${secret.EndLine}:${secret.EndColumn}`);
      });
    }
    debugLog(`  - repoName: ${repoName || 'NOT SET'}`);
    debugLog(`  - branchName: ${branchName || 'NOT SET'}`);

    // Print full CombinedScanRequest JSON for debugging
    debugLog('\n📋 Full CombinedScanRequest JSON:');
    debugLog(JSON.stringify(combinedScanRequest, null, 2));

    // Create multipart form data
    const boundary = `----WebKitFormBoundary${Math.random().toString(16).substring(2)}`;
    const outputDirPath = options.outputDir || './scan-report';
    const sbomFilePath = path.join(outputDirPath, 'cyclonedx.json');
    const formData = createMultipartFormData(combinedScanRequest, sbomFilePath, boundary, {
      repoName,
      branchName
    });

    debugLog('\n📋 Multipart Form Data Details:');
    debugLog(`  - Boundary: ${boundary}`);
    debugLog(`  - SBOM File: ${sbomFilePath}`);
    debugLog(`  - Form Data Size: ${formData.length} bytes`);
    debugLog(`  - displayName: sbom`);
    debugLog(`  - source: jenkins`);
    debugLog(`  - organizationId: ${process.env.ORGANIZATION_ID || 'NOT SET'}`);
    debugLog(`  - jobId: ${process.env.BUILD_ID || process.env.BUILD_NUMBER || 'NOT SET'}`);
    debugLog(`  - repoName: ${repoName || 'NOT SET'} (provider: ${provider || 'unknown'})`);
    debugLog(`  - branchName: ${branchName || 'NOT SET'}`);

    // Prepare request options
    const requestOptions = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: options.method || 'POST',
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': formData.length,
        'User-Agent': 'Jenkins-SBOM-Scanner/1.0',
        'x-api-key': process.env.NT_API_KEY || '',
        'x-secret-key': process.env.NT_SECRET_KEY || '',
        ...options.headers
      }
    };

    debugLog('\n📋 Request Details:');
    debugLog(`URL: ${fullApiUrl}`);
    debugLog(`Project ID: ${projectId || 'NOT SET'}`);
    debugLog('Headers: {');
    Object.entries(requestOptions.headers).forEach(([key, value]) => {
      if (key.toLowerCase().includes('key')) {
        debugLog(`  "${key}": "***"`);
      } else {
        debugLog(`  "${key}": "${value}"`);
      }
    });
    debugLog('}');

    // Make the request
    const req = client.request(requestOptions, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        debugLog(`✓ API Response Status: ${res.statusCode}`);
        debugLog(`Response Data: ${data}`);

        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const response = data ? JSON.parse(data) : {};
            console.log('✓ Reports sent successfully');
            resolve({ statusCode: res.statusCode, data: response });
          } catch (error) {
            console.log('✓ Reports sent successfully (non-JSON response)');
            resolve({ statusCode: res.statusCode, data: data });
          }
        } else {
          console.error(`✗ API request failed with status ${res.statusCode}`);
          debugLog(`Error response: ${data}`);
          reject(new Error(`API request failed with status ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', (error) => {
      console.error('✗ API request failed:', error.message);
      reject(error);
    });

    // Set timeout
    req.setTimeout(options.timeout || 60000, () => {
      req.destroy();
      reject(new Error('API request timeout'));
    });

    // Send the payload
    req.write(formData);
    req.end();
  });
}

/**
 * Create a formatted table from data with column width limits
 */
function createFormattedTable(headers, rows, maxColWidths = null) {
  if (rows.length === 0) return '';

  // Default max column widths if not provided
  const defaultMaxWidths = {
    0: 50,  // First column (File/Package)
    1: 40,  // Second column (Issue/Vulnerability)
    2: 15,  // Third column (Severity)
    3: 20   // Fourth column (Line/Fixed Version)
  };

  const maxWidths = maxColWidths || defaultMaxWidths;

  // Calculate column widths with limits
  const colWidths = headers.map((header, idx) => {
    const headerWidth = header.length;
    const maxRowWidth = Math.max(...rows.map(row => (row[idx] || '').toString().length));
    const calculatedWidth = Math.max(headerWidth, maxRowWidth) + 2; // +2 for padding
    const maxAllowed = maxWidths[idx] || 50;
    return Math.min(calculatedWidth, maxAllowed);
  });

  // Truncate text to fit within column width
  const truncateText = (text, maxWidth) => {
    const str = (text || '').toString();
    const availableWidth = maxWidth - 2; // Account for padding
    if (str.length <= availableWidth) return str;
    return str.substring(0, availableWidth - 3) + '...';
  };

  // Create border lines
  const topBorder = '┌' + colWidths.map(w => '─'.repeat(w)).join('┬') + '┐';
  const middleBorder = '├' + colWidths.map(w => '─'.repeat(w)).join('┼') + '┤';
  const bottomBorder = '└' + colWidths.map(w => '─'.repeat(w)).join('┴') + '┘';

  // Build table
  const lines = [];
  lines.push(topBorder);

  // Header row
  const headerRow = '│' + headers.map((h, idx) => ' ' + truncateText(h, colWidths[idx]).padEnd(colWidths[idx] - 1)).join('│') + '│';
  lines.push(headerRow);
  lines.push(middleBorder);

  // Data rows
  rows.forEach(row => {
    const rowLine = '│' + row.map((cell, idx) => ' ' + truncateText(cell, colWidths[idx]).padEnd(colWidths[idx] - 1)).join('│') + '│';
    lines.push(rowLine);
  });

  lines.push(bottomBorder);

  return lines.join('\n');
}

/**
 * Display vulnerability table
 */
function displayVulnerabilityTable(trivyVuln) {
  if (!trivyVuln || !trivyVuln.Results || trivyVuln.Results.length === 0) {
    return;
  }

  const vulnerabilities = [];
  trivyVuln.Results.forEach(result => {
    if (result.Vulnerabilities && result.Vulnerabilities.length > 0) {
      result.Vulnerabilities.forEach(vuln => {
        vulnerabilities.push(vuln);
      });
    }
  });

  if (vulnerabilities.length === 0) return;

  console.log('\n📋 Vulnerability Details:\n');

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const severityEmojis = { 'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢' };

  // Prepare table data
  const headers = ['Package', 'Vulnerability', 'Severity', 'Fixed Version'];
  const rows = [];

  severities.forEach(severity => {
    const vulnsOfSeverity = vulnerabilities.filter(v => (v.Severity || '').toUpperCase() === severity);

    vulnsOfSeverity.forEach(vuln => {
      const emoji = severityEmojis[severity] || '';
      const pkg = vuln.PkgName || 'Unknown';
      const vulnId = vuln.VulnerabilityID || 'N/A';
      const sev = `${emoji} ${severity}`;
      const fixed = vuln.FixedVersion || 'N/A';

      rows.push([pkg, vulnId, sev, fixed]);
    });
  });

  // Display formatted table
  console.log(createFormattedTable(headers, rows));
  console.log('');
}

/**
 * Display configuration table
 */
function displayConfigTable(trivyConfig) {
  if (!trivyConfig || !trivyConfig.Results || trivyConfig.Results.length === 0) {
    return;
  }

  const misconfigurations = [];
  trivyConfig.Results.forEach(result => {
    if (result.Misconfigurations && result.Misconfigurations.length > 0) {
      result.Misconfigurations.forEach(misc => {
        misconfigurations.push({
          File: result.Target || 'Unknown',
          Issue: misc.Title || misc.ID || 'N/A',
          Severity: misc.Severity || 'UNKNOWN',
          Line: 'N/A'
        });
      });
    }
  });

  if (misconfigurations.length === 0) return;

  console.log('\n📋 Misconfiguration Details:\n');

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const severityEmojis = { 'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢' };

  // Prepare table data
  const headers = ['File', 'Issue', 'Severity', 'Line'];
  const rows = [];

  severities.forEach(severity => {
    const configsOfSeverity = misconfigurations.filter(c => (c.Severity || '').toUpperCase() === severity);

    configsOfSeverity.forEach(config => {
      const emoji = severityEmojis[severity] || '';
      const file = config.File || 'Unknown';
      const issue = config.Issue || 'N/A';
      const sev = `${emoji} ${severity}`;
      const line = config.Line.toString();

      rows.push([file, issue, sev, line]);
    });
  });

  // Display formatted table
  console.log(createFormattedTable(headers, rows));
  console.log('');
}

/**
 * Display secret table
 * @returns {number} - Number of unique secrets after deduplication
 */
function displaySecretTable(gitleaks) {
  if (!gitleaks || !Array.isArray(gitleaks) || gitleaks.length === 0) {
    return 0;
  }

  console.log('\n📋 Secret Details:\n');

  // Deduplicate secrets based on File, Secret/Match, and location
  const seen = new Map();
  const deduplicated = [];

  gitleaks.forEach(secret => {
    const file = secret.File || '';
    const match = secret.Match || secret.Secret || '';
    const startLine = secret.StartLine || '0';
    const endLine = secret.EndLine || '0';
    const startCol = secret.StartColumn || '0';
    const endCol = secret.EndColumn || '0';

    // Create unique key
    const key = `${file}|${match}|${startLine}|${endLine}|${startCol}|${endCol}`;

    if (!seen.has(key)) {
      seen.set(key, true);
      deduplicated.push(secret);
    }
  });

  // Prepare table data
  const headers = ['File', 'Line', 'Matched Secret'];
  const rows = [];

  deduplicated.forEach(secret => {
    const cleanFile = (secret.File || 'Unknown').replace(/^\/+/, '');
    const line = (secret.StartLine || 'N/A').toString();
    const matched = secret.Match || 'N/A';

    rows.push([cleanFile, line, matched]);
  });

  // Custom column widths for secrets table (wider columns)
  const customWidths = {
    0: 70,  // File path - wider for long paths
    1: 8,   // Line number - narrow
    2: 30   // Matched secret - wider to show more context
  };

  // Display formatted table
  console.log(createFormattedTable(headers, rows, customWidths));
  console.log('');

  return deduplicated.length;
}

/**
 * Display all scan results in tables
 */
function displayScanResults(reports) {
  console.log('\n' + '='.repeat(50));
  console.log('CONSOLIDATED SCAN REPORT');
  console.log('='.repeat(50));

  // Display vulnerability table
  if (reports.trivyVuln) {
    const vulnCount = reports.trivyVuln.Results?.reduce((sum, r) =>
      sum + (r.Vulnerabilities?.length || 0), 0) || 0;
    console.log(`\n🔍 VULNERABILITY SCAN RESULTS`);
    console.log(`   Total Vulnerabilities: ${vulnCount}`);
    displayVulnerabilityTable(reports.trivyVuln);
  }

  console.log('\n' + '='.repeat(50));

  // Display config table
  if (reports.trivyConfig) {
    const misconfigCount = reports.trivyConfig.Results?.reduce((sum, r) =>
      sum + (r.Misconfigurations?.length || 0), 0) || 0;
    console.log(`\n📋 CONFIG SCANNER RESULTS`);
    console.log(`   Total Misconfigurations: ${misconfigCount}`);
    displayConfigTable(reports.trivyConfig);
  }

  console.log('\n' + '='.repeat(50));

  // Display secret table
  if (reports.gitleaks && Array.isArray(reports.gitleaks)) {
    // Calculate deduplicated count first
    const seen = new Map();
    let uniqueCount = 0;
    reports.gitleaks.forEach(secret => {
      const file = secret.File || '';
      const match = secret.Match || secret.Secret || '';
      const startLine = secret.StartLine || '0';
      const endLine = secret.EndLine || '0';
      const startCol = secret.StartColumn || '0';
      const endCol = secret.EndColumn || '0';
      const key = `${file}|${match}|${startLine}|${endLine}|${startCol}|${endCol}`;
      if (!seen.has(key)) {
        seen.set(key, true);
        uniqueCount++;
      }
    });

    console.log(`\n🔐 SECRET SCANNER RESULTS`);
    console.log(`   Total Secrets Detected: ${uniqueCount}`);
    displaySecretTable(reports.gitleaks);
  }

  console.log('\n' + '='.repeat(50));
}

/**
 * Main function to parse reports and send to API
 * @param {string} outputDir - Directory containing scan reports
 * @param {string} apiUrl - API endpoint URL
 * @param {object} options - Additional options
 */
async function processAndSendReports(outputDir, apiUrl, options = {}) {
  try {
    // Parse all report files
    const reports = parseReportFiles(outputDir);

    // Check if any reports were parsed
    const hasReports = Object.values(reports).some(report => report !== null);
    if (!hasReports) {
      throw new Error('No valid reports found to send');
    }

    // Display scan results in tables
    displayScanResults(reports);

    // Send to API
    const response = await sendToAPI(reports, apiUrl, options);
    console.log('\n✓ Successfully processed and sent all reports');
    return response;
  } catch (error) {
    console.error('\n✗ Failed to process and send reports:', error.message);
    throw error;
  }
}

// If run directly (not imported)
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.length < 1) {
    console.error('Usage: node apiService.js <output-dir> [base-url] [auth-token]');
    console.error('Example: node apiService.js ./scan-report');
    console.error('         node apiService.js ./scan-report https://dev.neoTrak.io');
    console.error('\nEnvironment Variables:');
    console.error('  Required:');
    console.error('    - NT_API_KEY: API authentication key');
    console.error('    - NT_SECRET_KEY: Secret key for authentication');
    console.error('  Optional:');
    console.error('    - PROJECT_ID: UUID of the project (appended to endpoint path if set)');
    console.error('    - ORGANIZATION_ID: UUID of the organization');
    console.error('    - BUILD_ID or BUILD_NUMBER: Jenkins build ID');
    console.error('    - JOB_NAME or REPO_NAME: Repository/job name');
    console.error('    - GIT_BRANCH or BRANCH_NAME: Branch name');
    console.error('    - WORKSPACE: Jenkins workspace directory');
    console.error('\nAPI Endpoint:');
    console.error('  - With PROJECT_ID: {base-url}/open-pulse/project/upload-all/{PROJECT_ID}');
    console.error('  - Without PROJECT_ID: {base-url}/open-pulse/project/upload-all');
    process.exit(1);
  }

  const [outputDir, apiUrl, authToken] = args;

  const options = {};
  if (authToken) {
    options.headers = {
      'Authorization': `Bearer ${authToken}`
    };
  }

  processAndSendReports(outputDir, apiUrl, options)
    .then(() => {
      console.log('\n✓ Operation completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n✗ Operation failed:', error.message);
      process.exit(1);
    });
}

module.exports = { parseReportFiles, sendToAPI, processAndSendReports };
