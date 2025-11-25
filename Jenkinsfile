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
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out source code...'
                checkout scm
            }
        }

        stage('Run Security Scans in Docker') {
            steps {
                script {
                    echo 'Running SBOM and security scans inside Docker container...'

                    docker.image('neotrak/sbom-base:1.0.5').inside("-v ${WORKSPACE}:${WORKSPACE} -w ${WORKSPACE}") {
                        sh '''
                            echo "Running inside neotrak/sbom-base:1.0.5 container"

                            # Verify tools are available
                            echo "Verifying installations..."
                            trivy --version
                            cdxgen --version
                            gitleaks version

                            # Copy scanner scripts to workspace if not already present
                            if [ ! -d "scanner" ]; then
                                cp -r jenkins-action/scanner .
                            fi

                            # Set environment variables for the scanner
                            export WORKSPACE=${WORKSPACE}
                            export BUILD_ID=${BUILD_ID}
                            export BUILD_NUMBER=${BUILD_NUMBER}
                            export JOB_NAME=${JOB_NAME}
                            export GIT_BRANCH=${GIT_BRANCH}
                            export GIT_URL=${GIT_URL}

                            # Run the main scanner script
                            node scanner/main.js
                        '''
                    }
                    // Container is automatically cleaned up after 'inside' block
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
