#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');

/**
 * Run Trivy vulnerability scan on a directory
 * @param {string} scanSbomfile - SBOM file to scan for vulnerabilities
 * @param {string} outputFile - Path to save the Trivy vulnerability report
 * @param {string} projectDir - Project directory for working directory
 * @param {object} options - Configuration options
 * @param {boolean} options.debug - Enable debug logging
 * @param {boolean} options.fail_on_vulnerability - Fail if vulnerabilities are found
 */
function runTrivyVulnScan(scanSbomfile, outputFile, projectDir = process.cwd(), options = {}) {
  const { debug = false, fail_on_vulnerability = true } = options;

  console.log(`\nRunning Trivy vulnerability scan...`);
  console.log(`SBOM file: ${scanSbomfile}`);
  console.log(`Trivy output file: ${outputFile}`);

  if (debug) {
    console.log(`🔧 Debug: fail_on_vulnerability = ${fail_on_vulnerability}`);
  }

  const command = `trivy sbom --format json --output ${outputFile} ${scanSbomfile}`;

  if (debug) {
    console.log(`🔧 Executing: ${command}`);
  } else {
    console.log(`Executing: Vulnerability scan...`);
  }

  try {
    execSync(command, {
      stdio: 'inherit',
      cwd: projectDir
    });
    console.log('\nTrivy vulnerability scan completed successfully!');

    // Check if vulnerabilities were found by reading the report
    if (fs.existsSync(outputFile)) {
      const reportData = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
      const hasVulnerabilities = reportData.Results && reportData.Results.some(result =>
        result.Vulnerabilities && result.Vulnerabilities.length > 0
      );

      if (hasVulnerabilities) {
        console.warn('⚠️  Warning: Trivy found vulnerabilities!');
        if (debug) {
          console.log(`🔧 Debug: Vulnerabilities found, returning true. fail_on_vulnerability is ${fail_on_vulnerability}`);
        }
        return true; // Vulnerabilities found
      }
    }

    return false; // No vulnerabilities found
  } catch (error) {
    console.error('Error during Trivy vulnerability scan:', error.message);
    throw error;
  }
}


module.exports = { runTrivyVulnScan };
