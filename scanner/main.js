#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { runTrivyScan } = require('./trivy-config-scan');
const { runTrivyVulnScan } = require('./trivy-vuln-scan');
const { runGitleaksScan } = require('./gitleaks-scan');
const { processAndSendReports } = require('./apiService');

// Configuration variables from environment (with defaults)
const debug = process.env.DEBUG_MODE === 'true' || false;
const fail_on_misconfiguration = process.env.FAIL_ON_MISCONFIGURATION !== 'false'; // default true
const fail_on_vulnerability = process.env.FAIL_ON_VULNERABILITY !== 'false'; // default true
const fail_on_secret = process.env.FAIL_ON_SECRET !== 'false'; // default true

console.log('Starting SBOM scan of test-project source code');
if (debug) {
  console.log('\n🔧 Debug mode enabled');
  console.log(`Configuration:
  - debug: ${debug}
  - fail_on_misconfiguration: ${fail_on_misconfiguration}
  - fail_on_vulnerability: ${fail_on_vulnerability}
  - fail_on_secret: ${fail_on_secret}`);
}

// Get project directory from environment variable (Jenkins uses WORKSPACE)
const projectDir = process.env.WORKSPACE || process.cwd();
console.log(`Project directory: ${projectDir}`);

// List files in current directory
console.log('\nDirectory contents:');
execSync('ls -la', { stdio: 'inherit' });

// Create output directory
const outputDir = path.join(projectDir, 'scan-report');
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
  console.log(`\nCreated output directory: ${outputDir}`);
}

// Run cdxgen to generate SBOM
const cdxgenOutputFile = path.join(outputDir, 'cyclonedx.json');
console.log(`\nGenerating SBOM with cdxgen...`);
console.log(`Output file: ${cdxgenOutputFile}`);

try {
  execSync(`cdxgen -r ${projectDir} -o ${cdxgenOutputFile} --no-banner`, {
    stdio: 'inherit',
    cwd: projectDir
  });
  console.log('\nSBOM scan completed successfully!');
} catch (error) {
  console.error('Error during SBOM scan:', error.message);
  process.exit(1);
}

// Run Trivy config scan on the generated SBOM
const trivyOutputFile = path.join(outputDir, 'trivy-config-report.json');

try {
  const hasConfigIssues = runTrivyScan(trivyOutputFile, projectDir, { debug, fail_on_misconfiguration });
  if (hasConfigIssues && fail_on_misconfiguration) {
    console.error('❌ Trivy config scan found misconfigurations and fail_on_misconfiguration is enabled');
    process.exit(1);
  }
} catch (error) {
  console.error('Trivy config scan failed', error.message);
  if (fail_on_misconfiguration) {
    process.exit(1);
  }
}

// Run Trivy vulnerability scan on the project source code
const trivyVulnOutputFile = path.join(outputDir, 'trivy-vuln-report.json');

try {
  const hasVulnerabilities = runTrivyVulnScan(cdxgenOutputFile, trivyVulnOutputFile, projectDir, { debug, fail_on_vulnerability });
  if (hasVulnerabilities && fail_on_vulnerability) {
    console.error('❌ Trivy vulnerability scan found vulnerabilities and fail_on_vulnerability is enabled');
    process.exit(1);
  }
} catch (error) {
  console.error('Trivy vulnerability scan failed', error.message);
  if (fail_on_vulnerability) {
    process.exit(1);
  }
}

// Run Gitleaks secret scan on the project source code
const gitleaksReportFile = path.join(outputDir, 'gitleaks-report.json');

try {
  const hasSecrets = runGitleaksScan(projectDir, gitleaksReportFile, null, { debug, fail_on_secret });
  if (hasSecrets && fail_on_secret) {
    console.error('❌ Gitleaks scan found secrets and fail_on_secret is enabled');
    process.exit(1);
  }
} catch (error) {
  console.error('Gitleaks scan failed', error.message);
  if (fail_on_secret) {
    process.exit(1);
  }
}

// Send reports to API (this will print environment variables)
(async () => {
  try {
    // Get API URL from environment variable with fallback to default
    const apiUrl = process.env.NT_API_ENDPOINT || 'https://beta.neoTrak.io';

    console.log(`API URL: ${apiUrl}`);

    // Prepare API options with headers
    const options = {
      headers: {},
      outputDir: outputDir
    };

    console.log('\n📤 Sending reports to API...');
    await processAndSendReports(outputDir, apiUrl, options);
    console.log('✓ All scans and API submission completed successfully!');
  } catch (error) {
    console.error('\n✗ Failed to send reports to API:', error.message);
    process.exit(1);
  }
})();
