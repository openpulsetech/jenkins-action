# NeoTrak Jenkins SBOM Scanner

This Jenkins action performs comprehensive security scanning including:
- SBOM (Software Bill of Materials) generation using CycloneDX
- Configuration scanning with Trivy
- Vulnerability scanning with Trivy
- Secret detection with Gitleaks

## Prerequisites

1. Jenkins server with Docker support
2. Docker image: `neotrak/sbom-base:1.0.5` (contains cdxgen, Trivy, and Gitleaks pre-installed)
3. No additional tool installation required - everything runs inside the Docker container

## Setup

### 1. Configure Jenkins Credentials

Add the following credentials in Jenkins (Manage Jenkins > Credentials):

- `nt-api-endpoint`: NeoTrak API endpoint URL (e.g., https://beta.neoTrak.io)
- `nt-api-key`: Your NeoTrak API key
- `nt-secret-key`: Your NeoTrak secret key
- `nt-project-id`: Your project UUID
- `nt-organization-id`: Your organization UUID

### 2. Add Jenkinsfile to Your Repository

Copy the `Jenkinsfile` from this repository to the root of your project repository.

### 3. Configure Jenkins Pipeline Job

1. Create a new Pipeline job in Jenkins
2. Under "Pipeline" section:
   - Definition: Pipeline script from SCM
   - SCM: Git
   - Repository URL: Your repository URL
   - Script Path: Jenkinsfile

## Environment Variables

### Required Variables (via Jenkins Credentials)
- `NT_API_KEY`: API authentication key
- `NT_SECRET_KEY`: Secret key for authentication
- `NT_API_ENDPOINT`: API endpoint URL

### Optional Variables
- `PROJECT_ID`: UUID of the project (appended to endpoint path if set)
- `ORGANIZATION_ID`: UUID of the organization
- `FAIL_ON_MISCONFIGURATION`: Fail pipeline if misconfigurations found (default: true)
- `FAIL_ON_VULNERABILITY`: Fail pipeline if vulnerabilities found (default: true)
- `FAIL_ON_SECRET`: Fail pipeline if secrets found (default: true)
- `DEBUG_MODE`: Enable debug logging (default: false)

### Jenkins Environment Variables (Automatically Available)
- `WORKSPACE`: Jenkins workspace directory
- `BUILD_ID` / `BUILD_NUMBER`: Jenkins build identifier
- `JOB_NAME`: Jenkins job name (used as repo name)
- `GIT_BRANCH`: Git branch being built
- `GIT_URL`: Repository URL

## Usage

### Basic Usage

Simply add the Jenkinsfile to your repository and create a Jenkins Pipeline job pointing to your repository. The scanner will run automatically on each build.

### Manual Execution with Docker

You can also run the scanner manually using Docker:

```bash
# Set required environment variables
export NT_API_KEY="your-api-key"
export NT_SECRET_KEY="your-secret-key"
export NT_API_ENDPOINT="https://beta.neoTrak.io"
export PROJECT_ID="your-project-id"
export ORGANIZATION_ID="your-org-id"

# Run the scanner in Docker container
docker run --rm \
  -v $(pwd):$(pwd) \
  -w $(pwd) \
  -e NT_API_KEY="${NT_API_KEY}" \
  -e NT_SECRET_KEY="${NT_SECRET_KEY}" \
  -e NT_API_ENDPOINT="${NT_API_ENDPOINT}" \
  -e PROJECT_ID="${PROJECT_ID}" \
  -e ORGANIZATION_ID="${ORGANIZATION_ID}" \
  -e WORKSPACE=$(pwd) \
  neotrak/sbom-base:1.0.5 \
  node jenkins-action/scanner/main.js
```

### Manual Execution without Docker

If you prefer to run without Docker:

```bash
# Install required tools: cdxgen, trivy, gitleaks
# Set required environment variables
export NT_API_KEY="your-api-key"
export NT_SECRET_KEY="your-secret-key"
export NT_API_ENDPOINT="https://beta.neoTrak.io"
export PROJECT_ID="your-project-id"
export ORGANIZATION_ID="your-org-id"
export WORKSPACE=$(pwd)

# Run the scanner
node scanner/main.js
```

## Scan Results

The scanner generates the following reports in the `scan-report/` directory:

- `cyclonedx.json`: SBOM in CycloneDX format
- `trivy-config-report.json`: Configuration scan results
- `trivy-vuln-report.json`: Vulnerability scan results
- `gitleaks-report.json`: Secret detection results

All reports are automatically uploaded to the NeoTrak API and archived as Jenkins artifacts.

## Customizing Scan Behavior

You can customize the scan behavior by modifying environment variables in the Jenkinsfile:

```groovy
environment {
    // Disable failing on specific findings
    FAIL_ON_MISCONFIGURATION = 'false'
    FAIL_ON_VULNERABILITY = 'false'
    FAIL_ON_SECRET = 'false'

    // Enable debug mode for troubleshooting
    DEBUG_MODE = 'true'
}
```

## Gitleaks Custom Rules

The scanner includes a custom Gitleaks configuration file (`gitleaks-custom-rules.toml`) that defines rules for secret detection. You can modify this file to add or remove detection rules.

## Troubleshooting

### Enable Debug Mode

Set `DEBUG_MODE=true` in the Jenkinsfile to see detailed logging including:
- Environment variables
- API request details
- Scan results

### Check Jenkins Logs

If the scan fails, check the Jenkins console output for detailed error messages.

### Verify Docker Image

Ensure the Docker image is accessible:

```bash
docker pull neotrak/sbom-base:1.0.5
docker run --rm neotrak/sbom-base:1.0.5 sh -c "cdxgen --version && trivy --version && gitleaks version"
```

### Docker Permissions

Make sure the Jenkins user has permissions to run Docker commands. You may need to add the Jenkins user to the docker group:

```bash
sudo usermod -aG docker jenkins
sudo systemctl restart jenkins
```

## File Structure

```
jenkins-action/
├── Jenkinsfile                       # Jenkins pipeline configuration
├── README.md                         # This file
└── scanner/
    ├── main.js                       # Main scanner orchestrator
    ├── apiService.js                 # API communication service
    ├── trivy-config-scan.js          # Trivy config scanner
    ├── trivy-vuln-scan.js            # Trivy vulnerability scanner
    ├── gitleaks-scan.js              # Gitleaks secret scanner
    └── gitleaks-custom-rules.toml    # Gitleaks detection rules
```

## Support

For issues or questions, please contact NeoTrak support or check the documentation at https://neoTrak.io
