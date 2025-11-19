// Início do pipeline declarativo do Jenkins
pipeline {
    // O agente "any" indica que este pipeline pode rodar em qualquer nó disponível
    agent any

    // Define as ferramentas que o Jenkins vai usar (configuradas em "Manage Jenkins » Tools")
    tools {
        jdk 'jdk-21'      // Usa o JDK 21 configurado no Jenkins
        maven 'maven-3.9' // Usa o Maven 3.9 configurado no Jenkins
    }

    // Opções gerais do pipeline
    options {
        timestamps() // Adiciona timestamps aos logs do console (útil para debug e auditoria)
        buildDiscarder(logRotator(numToKeepStr: '20')) // Mantém apenas as 20 últimas execuções no histórico
    }

    // Declaração de parâmetros que o usuário pode ajustar antes de rodar o pipeline
    parameters {
        // Parâmetro booleano (checkbox) para ativar ou não a verificação de vulnerabilidades
        booleanParam(
            name: 'EXECUTAR_VERIFICACAO_SEGURANCA',
            defaultValue: true,
            description: 'Marque esta caixa para executar a verificação de vulnerabilidades (OWASP Dependency-Check)'
        )

        // Parâmetro numérico (em formato string) que define o limite de CVSS que causa falha no build
        string(
            name: 'LIMITE_CVSS_FALHA',
            defaultValue: '7.0',
            description: 'Falhar o build se uma CVE tiver score CVSS igual ou superior a este valor (0.0 a 10.0)'
        )
    }

    // ============================
    //  DEFINIÇÃO DAS ETAPAS
    // ============================
    stages {

        // ------------------------------
        // Etapa 1: Compilação do projeto
        // ------------------------------
        stage('Build') {
            steps {
                // Executa comando Maven no Windows (bat)
                // -B: modo batch (sem prompts interativos)
                // -DskipTests: pula a execução dos testes
                bat '''
                    mvn -B -DskipTests clean package
                '''
            }
            post {
                // Sempre executa, mesmo que a compilação falhe
                always {
                    // Arquiva o .jar gerado no Jenkins (para download)
                    archiveArtifacts artifacts: 'target/*.jar', allowEmptyArchive: true
                    // Gera um "fingerprint" do artefato para rastreamento entre builds
                    fingerprint 'target/*.jar'
                }
            }
        }

        // ------------------------------
        // Etapa 2: Execução dos testes
        // ------------------------------
        stage('Test') {
            steps {
                // Roda os testes com Maven
                bat '''
                    mvn -B test
                '''
            }
            post {
                always {
                    // Publica os resultados de testes no Jenkins (Junit plugin)
                    junit allowEmptyResults: true, testResults: '**/surefire-reports/*.xml'
                }
            }
        }

        // ------------------------------------------
        // Etapa 3: Verificação de vulnerabilidades
        // ------------------------------------------
        stage('Dependency check') {
            when {
                expression { return params.EXECUTAR_VERIFICACAO_SEGURANCA }
            }

            steps {
                script {
                    // Atualiza banco local de CVEs
                    bat "mvn org.owasp:dependency-check-maven:update-only"

                    // Lê o valor digitado no parâmetro (String -> BigDecimal)
                    def userLimit = params.LIMITE_CVSS_FALHA as BigDecimal

                    // Se for 10, manda 11 pro plugin (nada falha)
                    // Senão, manda userLimit + 0.01 para simular "maior que"
                    BigDecimal effectiveThreshold
                    if (userLimit >= 10) {
                        effectiveThreshold = 11.0
                    } else {
                        effectiveThreshold = userLimit + 0.01
                    }

                    echo "Limite informado pelo usuário: ${userLimit}"
                    echo "Threshold efetivo enviado ao Dependency-Check: ${effectiveThreshold}"

                    try {
                        // Aqui usamos a user property do plugin: failBuildOnCVSS
                        bat "mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=${effectiveThreshold}"
                    } catch (e) {
                        currentBuild.result = 'FAILURE'
                        error("Pipeline falhou devido a vulnerabilidades com score acima de ${userLimit}")
                    }
                }
            }
        }


        // ------------------------------------------
        // Etapa 4: Baixando JSON
        // ------------------------------------------
        stage('Copiar JSON para máquina local') {
            when {
                expression { return params.EXECUTAR_VERIFICACAO_SEGURANCA }
            }
            steps {
                bat """
                    echo Copiando JSON gerado para sua pasta local...
                    copy /Y "%WORKSPACE%\\target\\dependency-check-report.json" "C:\\Users\\Carlos Eduardo\\Desktop\\Programacao\\Dependency-Check\\report\\dependency-check-report.json"
                """
            }
        }


    } // <-- Fim das etapas (stages)

    // ============================
    //  AÇÕES PÓS-BUILD
    // ============================
    post {
        always {
            echo "Arquivando relatórios de segurança..."

            // Arquiva os relatórios do OWASP Dependency-Check em vários formatos
            archiveArtifacts artifacts: 'target/dependency-check-report.html, target/dependency-check-report.json, target/dependency-check-report.xml',
                             allowEmptyArchive: true

            // Publica o XML para o plugin "OWASP Dependency Check" gerar gráficos no Jenkins
            dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'

            // Arquiva o relatório final gerado com IA
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.', // Pasta onde o relatório está (raiz do workspace)
                        reportFiles: 'relatorio_vulnerabilidades.html', // O nome do seu arquivo
                        reportName: 'Relatório de Vulnerabilidades (IA)' // O nome que vai aparecer no link
                    ])
        }
    }
}
