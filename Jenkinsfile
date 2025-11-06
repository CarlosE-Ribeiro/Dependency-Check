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

    parameters {
        // 1. NOVO PARÂMETRO "BOTÃO"
        // Este é o botão de "liga/desliga" para o scan
        booleanParam(name: 'EXECUTAR_VERIFICACAO_SEGURANCA', 
                     defaultValue: true, 
                     description: 'Marque esta caixa para executar a verificação de vulnerabilidades (OWASP Dependency-Check)')

        // 2. PARÂMETRO ANTIGO
        // Continua aqui, mas só será usado se o botão acima for marcado.
        string(name: 'LIMITE_CVSS_FALHA', 
               defaultValue: '7.0', 
               description: 'Falhar o build se uma CVE tiver score CVSS igual ou superior a este valor (0.0 a 10.0)')
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
            when {
                expression { return params.EXECUTAR_VERIFICACAO_SEGURANCA }
            }

            steps {
                script {
                    // Força o download das últimas definições de CVEs
                    bat "mvn org.owasp:dependency-check-maven:update-only"
                    try {
                        // O comando agora usa o parâmetro de limite
                        bat "mvn org.owasp:dependency-check-maven:check -Dowasp.fail.threshold=${params.LIMITE_CVSS_FALHA}"
                    } catch (e) {
                        currentBuild.result = 'FAILURE'
                        error("Pipeline falhou devido a vulnerabilidades acima do score: ${params.LIMITE_CVSS_FALHA}")
                    }
                }
            }

            stage('Gerar Relatório com IA') {
            when {
                expression { return params.EXECUTAR_VERIFICACAO_SEGURANCA }
            }
            
            // ADICIONE ESTE BLOCO 'environment'
            environment {
                // Puxa a credencial 'gemini-api-key' que você criou no Jenkins
                // e a coloca na variável de ambiente 'API_KEY_GEMINI'
                API_KEY_GEMINI = credentials('gemini-api-key')
            }
            
            steps {
                echo "Executando script Python para gerar relatório HTML com IA..."
                // Agora, quando o 'gerar_relatorio.py' rodar, 
                // ele terá acesso à variável 'API_KEY_GEMINI'
                bat 'python gerar_relatorio.py'

            post {
                always {
                    echo "Arquivando relatórios de segurança..."
                    // Arquiva os 3 formatos principais
                    archiveArtifacts artifacts: 'target/dependency-check-report.html, target/dependency-check-report.json, target/dependency-check-report.xml', 
                                     allowEmptyArchive: true
                    
                    // O Publisher usa o XML para os gráficos do Jenkins
                    dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'

                    archiveArtifacts artifacts: 'relatorio_vulnerabilidades.html', allowEmptyArchive: true
                }
            }
        }
    } // <- fecha stages
} // <- fecha pipeline
