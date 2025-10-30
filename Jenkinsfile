pipeline {
    agent any

    // Ajuste os nomes conforme "Manage Jenkins » Tools"
    tools {
        jdk 'jdk-21'            // ex.: JDK 21 instalado no Jenkins
        maven 'maven-3.9'       // ex.: Maven 3.x instalado no Jenkins
    }

    options {
        timestamps()                                // Adiciona timestamps nos logs
        buildDiscarder(logRotator(numToKeepStr: '20'))  // Mantém as últimas 20 builds
    }

    //parameters se for necessario

    environment {
        DC_CACHE       = 'C:\\DC_CACHE'  // Diretório de cache para o Dependency-Check
        NVD_DELAY_MS   = '30000'         // Delay entre requisições
        NVD_RETRIES    = '15'            // Tentativas em caso de erro
        NVD_CF_RETRIES = '15'            // Tentativas adicionais com Cloudflare
    }

    stages {


        stage('Build') {
            steps {
                bat '''
                    mvn -B -DskipTests clean package
                ''' // Compila o projeto sem rodar os testes
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/*.jar', allowEmptyArchive: true
                    fingerprint 'target/*.jar'
                }
            }
        }

        stage('Test') {
            steps {
                bat '''
                    mvn -B test
                ''' // Executa os testes automatizados
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: '**/surefire-reports/*.xml'
                }
            }
        }

        stage('Dependency check') {
            steps {
                //dependencyCheck additionalArguments: '', nvdCredentialsId: 'nvd-api-key', odcInstallation: 'OWASP-DC', stopBuild: true
                //dependencyCheckPublisher pattern: '', stopBuild: true
                bat 'mvn org.owasp:dependency-check-maven:check'
            }

        }//dependency
        
    }

    post {
        always {

            // O relatório HTML agora estará em 'target/'
            archiveArtifacts artifacts: 'target/dependency-check-report.html', allowEmptyArchive: true

            // O publisher vai procurar o XML gerado pelo Maven na pasta 'target/'
            dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'

            echo "Pipeline finalizado"  // Executado ao final da pipeline, com sucesso ou erro
        }
    }
}
