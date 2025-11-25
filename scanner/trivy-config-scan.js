#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');

/**
 * Run Trivy config scan on a file
 * @param {string} outputFile - Path to save the Trivy report
 * @param {string} projectDir - Project directory for working directory
 * @param {object} options - Configuration options
 * @param {boolean} options.debug - Enable debug logging
 * @param {boolean} options.fail_on_misconfiguration - Fail if misconfigurations are found
 */
function runTrivyScan(outputFile, projectDir = process.cwd(), options = {}) {
  const { debug = false, fail_on_misconfiguration = true } = options;

  console.log(`\nRunning Trivy config scan...`);
  console.log(`Scan target: ${projectDir}`);
  console.log(`Trivy output file: ${outputFile}`);

  if (debug) {
    console.log(`🔧 Debug: fail_on_misconfiguration = ${fail_on_misconfiguration}`);
  }

  const command = `trivy config --format json --output ${outputFile} ${projectDir}`;

  if (debug) {
    console.log(`🔧 Executing: ${command}`);
  } else {
    console.log(`Executing: Config scan...`);
  }

  try {
    execSync(command, {
      stdio: 'inherit',
      cwd: projectDir
    });
    console.log('\nTrivy config scan completed successfully!');

    // Check if misconfigurations were found by reading the report
    if (fs.existsSync(outputFile)) {
      const reportData = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
      const hasIssues = reportData.Results && reportData.Results.some(result =>
        result.Misconfigurations && result.Misconfigurations.length > 0
      );

      if (hasIssues) {
        console.warn('⚠️  Warning: Trivy found misconfigurations!');
        if (debug) {
          console.log(`🔧 Debug: Misconfigurations found, returning true. fail_on_misconfiguration is ${fail_on_misconfiguration}`);
        }
        return true; // Misconfigurations found
      }
    }

    return false; // No misconfigurations found
  } catch (error) {
    console.error('Error during Trivy config scan:', error.message);
    throw error;
  }
}

// If run directly (not imported)
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.length < 2) {
    console.error('Usage: node trivy-scan.js <input-file> <output-file> [project-dir]');
    process.exit(1);
  }

  const [inputFile, outputFile, projectDir] = args;

  try {
    runTrivyScan(inputFile, outputFile, projectDir);
  } catch (error) {
    process.exit(1);
  }
}

module.exports = { runTrivyScan };
