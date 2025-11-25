#!/usr/bin/env node

const { execSync } = require('child_process');
const path = require('path');

/**
 * Run Gitleaks secret scanning
 * @param {string} scanDir - Directory to scan for secrets
 * @param {string} reportPath - Path to save the Gitleaks report
 * @param {string} rulesPath - Path to the Gitleaks config/rules file (optional)
 * @param {object} options - Configuration options
 * @param {boolean} options.debug - Enable debug logging
 * @param {boolean} options.fail_on_secret - Fail if secrets are found
 */
function runGitleaksScan(scanDir, reportPath, rulesPath = null, options = {}) {
  const { debug = false, fail_on_secret = true } = options;

  console.log(`\nRunning Gitleaks secret scan...`);
  console.log(`Scan directory: ${scanDir}`);
  console.log(`Report path: ${reportPath}`);

  if (debug) {
    console.log(`🔧 Debug: fail_on_secret = ${fail_on_secret}`);
  }

  // Use custom rules file if no rulesPath provided
  if (!rulesPath) {
    rulesPath = path.join(__dirname, 'gitleaks-custom-rules.toml');
    console.log(`Using custom rules file: ${rulesPath}`);
  } else {
    console.log(`Config/Rules path: ${rulesPath}`);
  }

  // Build the gitleaks command
  let command = `gitleaks dir ${scanDir} --report-path=${reportPath} --no-banner --config=${rulesPath}`;

  if (debug) {
    console.log(`🔧 Executing: ${command}`);
  } else {
    console.log(`Executing: ${command}`);
  }

  try {
    execSync(command, {
      stdio: 'inherit',
      cwd: scanDir
    });
    console.log('\nGitleaks secret scan completed successfully!');
    return false; // No secrets found
  } catch (error) {
    // Gitleaks exits with code 1 if secrets are found
    if (error.status === 1) {
      console.warn('\n⚠️  Warning: Gitleaks found potential secrets!');
      if (debug) {
        console.log(`🔧 Debug: Secrets found, returning true. fail_on_secret is ${fail_on_secret}`);
      }
      return true; // Secrets found - let caller decide whether to fail
    }
    console.error('Error during Gitleaks scan:', error.message);
    throw error;
  }
}

// If run directly (not imported)
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.length < 2) {
    console.error('Usage: node gitleaks-scan.js <scan-dir> <report-path> [rules-path]');
    process.exit(1);
  }

  const [scanDir, reportPath, rulesPath] = args;

  try {
    runGitleaksScan(scanDir, reportPath, rulesPath || null);
  } catch (error) {
    process.exit(1);
  }
}

module.exports = { runGitleaksScan };
