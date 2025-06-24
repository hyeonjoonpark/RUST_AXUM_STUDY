pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "yourdockerid/axum_study:latest"
        // 필요시 DOCKERHUB_CREDENTIALS 등 등록
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Build') {
            steps {
                sh 'cargo build --release'
            }
        }
        stage('Test') {
            steps {
                sh 'cargo test'
            }
        }
        stage('Docker Build') {
            steps {
                sh 'docker build -t $DOCKER_IMAGE .'
            }
        }
        stage('Docker Push') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh 'echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin'
                    sh 'docker push $DOCKER_IMAGE'
                }
            }
        }
        // (옵션) 배포 단계 추가
        // stage('Deploy') { ... }
    }
    post {
        always {
            cleanWs()
        }
    }
}