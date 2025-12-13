# NeoTrack Security Scanner Jenkins CI/CD

A comprehensive security scanning Jenkins CI/CD integration that performs vulnerability scanning, configuration analysis, secret detection, and SBOM (Software Bill of Materials) generation for your projects.

## Features

- **Vulnerability Scanning**: Detect security vulnerabilities in dependencies and packages
- **Configuration Analysis**: Identify misconfigurations in your infrastructure and application files
- **Secret Detection**: Scan for exposed secrets, API keys, and credentials
- **SBOM Generation**: Generate Software Bill of Materials for dependency tracking
- **Automated Reporting**: Upload scan results to NeoTrack platform for centralized security management
- **Jenkins Integration**: Seamless integration with Jenkins pipelines and artifact archiving

## Prerequisites

Before using this integration, you need to:

1. **Sign up for NeoTrack**: Create an account at [NeoTrack Platform](https://beta.neoTrak.io)
2. **Obtain API Credentials**: Get your `NT_API_KEY` and `NT_SECRET_KEY` from the NeoTrack dashboard
3. **Jenkins Server**: Jenkins server with Docker support
4. **Docker Image**: `neotrak/sbom-base:1.0.5` (contains cdxgen, Trivy, and Gitleaks pre-installed)

## Quick Start

### Step 1: Configure Jenkins Credentials

Add the following credentials in Jenkins (Manage Jenkins > Credentials):

1. Go to **Manage Jenkins** → **Manage Credentials**
2. Select your credential store and domain
3. Click **Add Credentials**
4. Add the following credentials:

| Credential ID | Type | Description | Required |
|---------------|------|-------------|----------|
| `NT_API_KEY` | Secret text | Your NeoTrack API key | Yes |
| `NT_SECRET_KEY` | Secret text | Your NeoTrack secret key | Yes |

### Configuration Parameters

| Parameter | Description | Default | Example Value |
|-----------|-------------|---------|---------------|
| `FAIL_ON_VULNERABILITY` | Fail the pipeline if vulnerabilities are found | `false` | `true` or `false` |
| `FAIL_ON_MISCONFIGURATION` | Fail the pipeline if misconfigurations are found | `false` | `true` or `false` |
| `FAIL_ON_SECRET` | Fail the pipeline if secrets are detected | `false` | `true` or `false` |

**Note:** All failure flags are **optional** and default to `false` (non-blocking). You can:
- **Omit them entirely** - scanner will use default `false` behavior (non-blocking)
- **Explicitly set to `false`** - same as omitting them (non-blocking)
- **Set to `true`** - pipeline will fail when issues are found (blocking)

### Step 2: Add NeoTrack Scan to Your Jenkins Pipeline

**Option 1: Basic Jenkinsfile (non-blocking by default):**

```groovy
pipeline {
    agent any

    environment {
        NT_API_KEY = credentials('NT_API_KEY')
        NT_SECRET_KEY = credentials('NT_SECRET_KEY')
    }

    stages {
        stage('neotrak_scan') {
            agent {
                docker {
                    image 'neotrak/sbom-base:1.0.5'
                }
            }
            steps {
                sh 'rm -rf external-scanner && git clone https://github.com/contract-Developer123/jenkins-action.git -b main external-scanner'
                sh 'node external-scanner/scanner/main.js'
                archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true
            }
        }
    }
}
```

**Option 2: Blocking configuration (fail pipeline on issues):**

```groovy
pipeline {
    agent any

    environment {
        NT_API_KEY = credentials('NT_API_KEY')
        NT_SECRET_KEY = credentials('NT_SECRET_KEY')
        FAIL_ON_MISCONFIGURATION = 'true'   // Set to true to fail the build
        FAIL_ON_VULNERABILITY = 'true'      // Set to true to fail the build
        FAIL_ON_SECRET = 'true'             // Set to true to fail the build
    }

    stages {
        stage('neotrak_scan') {
            agent {
                docker {
                    image 'neotrak/sbom-base:1.0.5'
                }
            }
            steps {
                sh 'rm -rf external-scanner && git clone https://github.com/contract-Developer123/jenkins-action.git -b main external-scanner'
                sh 'node external-scanner/scanner/main.js'
                archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true
            }
        }
    }
}
```

### Step 3: Adding to Existing Pipeline (Optional)

If you already have a `Jenkinsfile` in your project, you can add the NeoTrack Security Scan as an additional stage:

**Option 1: Add as a parallel stage (non-blocking by default)**

```groovy
pipeline {
    agent any

    environment {
        NT_API_KEY = credentials('NT_API_KEY')
        NT_SECRET_KEY = credentials('NT_SECRET_KEY')
    }

    stages {
        stage('Build and Test') {
            parallel {
                stage('Build') {
                    steps {
                        sh 'npm run build'
                    }
                }

                stage('Test') {
                    steps {
                        sh 'npm test'
                    }
                }

                stage('Security Scan') {
                    agent {
                        docker {
                            image 'neotrak/sbom-base:1.0.5'
                        }
                    }
                    steps {
                        sh 'rm -rf external-scanner && git clone https://github.com/contract-Developer123/jenkins-action.git -b main external-scanner'
                        sh 'node external-scanner/scanner/main.js'
                        archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                sh 'npm run deploy'
            }
        }
    }
}
```

**Option 2: Run scan before deployment (blocking mode)**

```groovy
pipeline {
    agent any

    environment {
        NT_API_KEY = credentials('NT_API_KEY')
        NT_SECRET_KEY = credentials('NT_SECRET_KEY')
        // Fail deployment if security issues found
        FAIL_ON_MISCONFIGURATION = 'true'
        FAIL_ON_VULNERABILITY = 'true'
        FAIL_ON_SECRET = 'true'
    }

    stages {
        stage('Build') {
            steps {
                sh 'npm run build'
            }
        }

        stage('Test') {
            steps {
                sh 'npm test'
            }
        }

        stage('Security Scan') {
            agent {
                docker {
                    image 'neotrak/sbom-base:1.0.5'
                }
            }
            steps {
                sh 'rm -rf external-scanner && git clone https://github.com/contract-Developer123/jenkins-action.git -b main external-scanner'
                sh 'node external-scanner/scanner/main.js'
                archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true
            }
        }

        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'npm run deploy'
            }
        }
    }
}
```

**Option 3: Scan only on specific branches (non-blocking by default)**

```groovy
pipeline {
    agent any

    environment {
        NT_API_KEY = credentials('NT_API_KEY')
        NT_SECRET_KEY = credentials('NT_SECRET_KEY')
    }

    stages {
        stage('Build') {
            steps {
                sh 'npm run build'
            }
        }

        stage('Test') {
            steps {
                sh 'npm test'
            }
        }

        stage('Security Scan') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    changeRequest()  // Run on pull requests
                }
            }
            agent {
                docker {
                    image 'neotrak/sbom-base:1.0.5'
                }
            }
            steps {
                sh 'rm -rf external-scanner && git clone https://github.com/contract-Developer123/jenkins-action.git -b main external-scanner'
                sh 'node external-scanner/scanner/main.js'
                archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true
            }
        }
    }
}
```

**Best Practices:**

1. **Separate Stage** - Run security scans in a dedicated stage for better organization
2. **Before Deployment** - Always scan before deploying to production with `FAIL_ON_*='true'`
3. **Fail on Production** - Set `FAIL_ON_VULNERABILITY='true'` for main/production branches
4. **Non-blocking for Development** - Omit `FAIL_ON_*` variables (or set to `'false'`) for development branches to avoid blocking developers
5. **Archive Artifacts** - Always archive scan reports for later review and compliance

## Configuration Options

### Environment Variables

The following environment variables are configured through Jenkins credentials:

#### Required Variables (Jenkins Credentials)

- **`NT_API_KEY`**: Your NeoTrack API authentication key
  - **Credential Type**: Secret text
  - **Credential ID**: `NT_API_KEY`
  - **Why needed**: Authenticates your requests to the NeoTrack API
  - **How to get**: Generated in your NeoTrack account settings

- **`NT_SECRET_KEY`**: Your NeoTrack secret key
  - **Credential Type**: Secret text
  - **Credential ID**: `NT_SECRET_KEY`
  - **Why needed**: Provides additional security layer for API authentication
  - **How to get**: Generated alongside your API key in NeoTrack account settings

#### Optional Variables (Environment in Jenkinsfile)

- **`FAIL_ON_VULNERABILITY`**: Fail pipeline on vulnerabilities (default: `false`)
  - **Optional** - can be omitted or explicitly set
  - Set to `'true'` to enable blocking: `FAIL_ON_VULNERABILITY = 'true'`
  - Set to `'false'` or omit for non-blocking: `FAIL_ON_VULNERABILITY = 'false'` (or don't declare it)

- **`FAIL_ON_MISCONFIGURATION`**: Fail pipeline on misconfigurations (default: `false`)
  - **Optional** - can be omitted or explicitly set
  - Set to `'true'` to enable blocking: `FAIL_ON_MISCONFIGURATION = 'true'`
  - Set to `'false'` or omit for non-blocking: `FAIL_ON_MISCONFIGURATION = 'false'` (or don't declare it)

- **`FAIL_ON_SECRET`**: Fail pipeline on secret detection (default: `false`)
  - **Optional** - can be omitted or explicitly set
  - Set to `'true'` to enable blocking: `FAIL_ON_SECRET = 'true'`
  - Set to `'false'` or omit for non-blocking: `FAIL_ON_SECRET = 'false'` (or don't declare it)

**Note:** By default, all scans are **non-blocking** (report only). You can choose to omit these variables entirely, explicitly set them to `'false'`, or set them to `'true'` to fail the pipeline when issues are found.

### Jenkins Environment Variables (Automatically Available)

- `WORKSPACE`: Jenkins workspace directory
- `BUILD_ID` / `BUILD_NUMBER`: Jenkins build identifier
- `JOB_NAME`: Jenkins job name (used as repo name)
- `GIT_BRANCH`: Git branch being built
- `GIT_URL`: Repository URL

## Advanced Usage Examples

### Example 1: Complete Production Pipeline

A comprehensive setup for production environments:

```groovy
pipeline {
    agent any

    environment {
        NT_API_KEY = credentials('NT_API_KEY')
        NT_SECRET_KEY = credentials('NT_SECRET_KEY')
        DOCKER_REGISTRY = 'docker.io'
        // Fail on production issues
        FAIL_ON_MISCONFIGURATION = 'true'
        FAIL_ON_VULNERABILITY = 'true'
        FAIL_ON_SECRET = 'true'
    }

    stages {
        stage('Build') {
            agent {
                docker {
                    image 'node:18'
                }
            }
            steps {
                sh 'npm install'
                sh 'npm run build'
            }
        }

        stage('Test') {
            agent {
                docker {
                    image 'node:18'
                }
            }
            steps {
                sh 'npm install'
                sh 'npm test'
            }
        }

        stage('Security Scan') {
            agent {
                docker {
                    image 'neotrak/sbom-base:1.0.5'
                }
            }
            steps {
                sh 'rm -rf external-scanner && git clone https://github.com/contract-Developer123/jenkins-action.git -b main external-scanner'
                sh 'node external-scanner/scanner/main.js'
                archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true
            }
        }

        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'npm run deploy'
            }
        }
    }

    post {
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed! Check security scan results.'
        }
    }
}
```

### Example 2: Scheduled Security Scans (Non-blocking)

Run security scans on a schedule:

```groovy
pipeline {
    agent any

    triggers {
        cron('H 2 * * *')  // Run daily at 2 AM
    }

    environment {
        NT_API_KEY = credentials('NT_API_KEY')
        NT_SECRET_KEY = credentials('NT_SECRET_KEY')
    }

    stages {
        stage('Security Scan') {
            agent {
                docker {
                    image 'neotrak/sbom-base:1.0.5'
                }
            }
            steps {
                sh 'rm -rf external-scanner && git clone https://github.com/contract-Developer123/jenkins-action.git -b main external-scanner'
                sh 'node external-scanner/scanner/main.js'
                archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true, fingerprint: true
            }
        }
    }
}
```

## Understanding the Scan Results

The scanner generates comprehensive security reports including:

### Vulnerability Report
- Lists all detected vulnerabilities with severity levels
- Shows affected packages and available fixes
- Provides CVE identifiers for tracking

### Misconfiguration Report
- Identifies security misconfigurations in:
  - Docker files
  - Kubernetes manifests
  - Terraform files
  - Cloud configuration files
  - Application configuration

### Secret Detection Report
- Detects exposed secrets including:
  - API keys
  - Access tokens
  - Private keys
  - Database credentials
  - Cloud provider credentials

### SBOM (Software Bill of Materials)
- Complete inventory of software components
- Dependency relationships
- License information
- Version tracking

## Viewing Results

Scan results are available in multiple locations:

1. **Jenkins Console Output**: View detailed results in the build console logs
2. **Jenkins Artifacts**: Download detailed reports from build artifacts (`scan-report/` directory)
3. **NeoTrack Dashboard**: Centralized view of all scans at [https://beta.neoTrak.io](https://beta.neoTrak.io)
4. **Build Trends**: Track security trends across builds in Jenkins

### Scan Reports Generated

The scanner generates the following reports in the `scan-report/` directory:

- `cyclonedx.json`: SBOM in CycloneDX format
- `trivy-config-report.json`: Configuration scan results
- `trivy-vuln-report.json`: Vulnerability scan results
- `gitleaks-report.json`: Secret detection results

All reports are automatically uploaded to the NeoTrack API and archived as Jenkins artifacts.

## Troubleshooting

| Issue | Error Message | Solution |
|-------|---------------|----------|
| **Authentication Failures** | `Upload failed: 401 Unauthorized` | • Verify Jenkins credentials `NT_API_KEY` and `NT_SECRET_KEY` are set correctly<br>• Ensure credentials are properly bound in environment section<br>• Check credentials are not expired in NeoTrack dashboard |
| **Timeout Issues** | `ETIMEDOUT` or `ECONNABORTED` | • Scanner auto-retries up to 3 times<br>• Check Jenkins agent network connectivity<br>• Verify NeoTrack API is accessible from Jenkins<br>• Check firewall/proxy settings |
| **SBOM Not Found** | `SBOM file not found — skipping upload` | • Ensure project has dependencies<br>• Verify package files exist (package.json, requirements.txt, go.mod, etc.)<br>• Check workspace is correctly mounted |
| **Missing Credentials** | Credentials not found or undefined | • Verify credential IDs match in Jenkinsfile<br>• Check credentials exist in Jenkins credential store<br>• Ensure credentials are accessible to the job |
| **Docker Image Pull Failures** | Docker image pull failures | • Confirm Jenkins agent has Docker installed<br>• Check agent can access Docker Hub<br>• Verify sufficient resources (CPU, memory, disk)<br>• Try manual pull: `docker pull neotrak/sbom-base:1.0.5` |
| **Git Clone Failures** | `git clone` failed | • Check Jenkins agent has git installed<br>• Verify network access to GitHub<br>• Check for firewall/proxy issues |
| **Docker Permissions** | Permission denied accessing Docker | • Add Jenkins user to docker group: `sudo usermod -aG docker jenkins`<br>• Restart Jenkins: `sudo systemctl restart jenkins`<br>• Verify with: `sudo -u jenkins docker ps` |

### Verify Docker Image

Ensure the Docker image is accessible:

```bash
docker pull neotrak/sbom-base:1.0.5
docker run --rm neotrak/sbom-base:1.0.5 sh -c "cdxgen --version && trivy --version && gitleaks version"
```

## Security Best Practices

| Category | Best Practice |
|----------|---------------|
| **Secrets Management** | Never commit secrets - always use Jenkins Credentials for sensitive data |
| **Branch Protection** | Require security scans to pass before merging to main/production branches |
| **Regular Scanning** | Set up scheduled pipelines (daily/weekly) to catch new vulnerabilities |
| **Prompt Response** | Address critical and high severity findings immediately |
| **Dependency Updates** | Keep dependencies updated to patch known vulnerabilities |
| **Credential Scope** | Use folder-level or job-level credentials for better isolation |
| **Production Safety** | Set `FAIL_ON_VULNERABILITY='true'` for production deployments |
| **Audit Trail** | Archive scan reports as artifacts for compliance and auditing |

## Why Use NeoTrack Scanner?

| Feature | Benefit |
|---------|---------|
| **Centralized Dashboard** | Track security trends, compare projects, view all scans in one place at [beta.neoTrak.io](https://beta.neoTrak.io) |
| **Comprehensive Scanning** | Multi-engine approach covers vulnerabilities, misconfigurations, secrets, and generates SBOM |
| **Flexible Configuration** | Control failure conditions, severity thresholds, and scan scope per pipeline |
| **Jenkins Integration** | Seamless CI/CD integration, automatic artifact archiving, build trend tracking |
| **Easy Setup** | Simple configuration with Jenkins credentials - no complex installation required |
| **Docker-Based** | All tools pre-installed in Docker image - consistent environment across agents |

## Gitleaks Custom Rules

The scanner includes a custom Gitleaks configuration file (`gitleaks-custom-rules.toml`) that defines rules for secret detection. You can modify this file to add or remove detection rules.

## Support

- **Documentation**: [NeoTrack Documentation](https://beta.neoTrak.io/docs)
- **Issues**: [GitHub Issues](https://github.com/neotrak/jenkins-action/issues)
- **Email**: support@neotrak.io

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

---

**Made with care by the NeoTrack Security Team**
