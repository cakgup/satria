FROM jenkins/jenkins:lts-jdk21

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl python3 python3-venv jq git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY casc/jenkins.yaml /usr/share/jenkins/ref/casc_configs/jenkins.yaml

ENV CASC_JENKINS_CONFIG=/var/jenkins_home/casc_configs/jenkins.yaml
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"

USER jenkins
