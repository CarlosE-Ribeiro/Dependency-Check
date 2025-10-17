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

        stage('Libraries') {
            steps {
                bat '''
                if not exist "target\\dc-libs" mkdir "target\\dc-libs"

                rem === Hibernate Validator ===
                mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get ^
                    -Dartifact=org.hibernate.validator:hibernate-validator:8.0.1.Final
                mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy ^
                    -Dartifact=org.hibernate.validator:hibernate-validator:8.0.1.Final ^
                    -DoutputDirectory=target/dc-libs

                rem === Netty ===
                mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get ^
                    -Dartifact=io.netty:netty-handler:4.1.109.Final
                mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy ^
                    -Dartifact=io.netty:netty-handler:4.1.109.Final ^
                    -DoutputDirectory=target/dc-libs

                rem === Bouncy Castle ===
                mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get ^
                    -Dartifact=org.bouncycastle:bcprov-jdk18on:1.78.1
                mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy ^
                    -Dartifact=org.bouncycastle:bcprov-jdk18on:1.78.1 ^
                    -DoutputDirectory=target/dc-libs
                '''
            }
        }

        stage('Dependency check') {
            steps {
                dependencyCheck additionalArguments: '', nvdCredentialsId: 'nvd-api-key', odcInstallation: 'OWASP-DC', stopBuild: true
                dependencyCheckPublisher pattern: '', stopBuild: true
            }

        }//dependency
        
    }

    post {
        always {
            echo "Pipeline finalizado"  // Executado ao final da pipeline, com sucesso ou erro
        }
    }
}
