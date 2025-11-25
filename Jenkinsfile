pipeline {
    agent any

    environment {
        // NeoTrak API Configuration
        NT_API_ENDPOINT = credentials('nt-api-endpoint') // Store in Jenkins credentials
        NT_API_KEY = credentials('nt-api-key')
        NT_SECRET_KEY = credentials('nt-secret-key')
        PROJECT_ID = credentials('nt-project-id')
        ORGANIZATION_ID = credentials('nt-organization-id')

        // Scan Configuration (Optional - defaults to true)
        FAIL_ON_MISCONFIGURATION = 'true'
        FAIL_ON_VULNERABILITY = 'true'
        FAIL_ON_SECRET = 'true'
        DEBUG_MODE = 'false'

        // Node.js version
        NODEJS_HOME = tool name: 'NodeJS', type: 'NodeJSInstallation'
        PATH = "${NODEJS_HOME}/bin:${env.PATH}"
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out source code...'
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                echo 'Installing cdxgen, trivy, and gitleaks...'
                sh '''
                    # Install cdxgen globally
                    npm install -g @cyclonedx/cdxgen

                    # Install Trivy (if not already installed)
                    if ! command -v trivy &> /dev/null; then
                        echo "Installing Trivy..."
                        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
                        sudo apt-get update
                        sudo apt-get install trivy -y
                    fi

                    # Install Gitleaks (if not already installed)
                    if ! command -v gitleaks &> /dev/null; then
                        echo "Installing Gitleaks..."
                        wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
                        tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
                        sudo mv gitleaks /usr/local/bin/
                        rm gitleaks_8.18.0_linux_x64.tar.gz
                    fi

                    # Verify installations
                    cdxgen --version
                    trivy --version
                    gitleaks version
                '''
            }
        }

        stage('Run Security Scans') {
            steps {
                echo 'Running SBOM and security scans...'
                dir("${WORKSPACE}") {
                    sh '''
                        # Copy scanner scripts to workspace
                        cp -r jenkins-action/scanner .

                        # Run the main scanner script
                        node scanner/main.js
                    '''
                }
            }
        }

        stage('Archive Results') {
            steps {
                echo 'Archiving scan results...'
                archiveArtifacts artifacts: 'scan-report/*.json', allowEmptyArchive: true
            }
        }
    }

    post {
        always {
            echo 'Cleaning up...'
            cleanWs()
        }
        success {
            echo 'Security scan completed successfully!'
        }
        failure {
            echo 'Security scan failed. Check the logs for details.'
        }
    }
}
