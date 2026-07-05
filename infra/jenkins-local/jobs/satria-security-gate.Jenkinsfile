pipeline {
  agent any
  options {
    timestamps()
    disableConcurrentBuilds()
  }
  parameters {
    string(name: 'IMAGE_REF', defaultValue: 'nginx:latest', description: 'Image yang akan diuji oleh SATRIA. Untuk uji awal gunakan image publik yang bisa dipull worker SATRIA.')
    string(name: 'ASSET_CODE', defaultValue: 'JENKINS-DEMO', description: 'Kode aset yang dipakai saat intake release.')
    string(name: 'ASSET_NAME', defaultValue: 'Jenkins Demo Service', description: 'Nama aset yang tampil di SATRIA.')
    choice(name: 'SCAN_PROFILE', choices: ['quick_container', 'full_container', 'sbom_scan'], description: 'Profile scan SATRIA.')
    choice(name: 'ENVIRONMENT_TARGET', choices: ['staging', 'production'], description: 'Environment target release.')
    choice(name: 'GATE_OVERRIDE_DECISION', choices: ['', 'allowed', 'need_approval', 'blocked'], description: 'Khusus demo/override formal. Kosongkan untuk memakai keputusan asli SATRIA.')
    booleanParam(name: 'PUBLISH_TO_IRIS', defaultValue: false, description: 'Jika aktif, publish temuan critical/high ke IRIS setelah scan selesai.')
  }
  environment {
    SATRIA_URL = '__SATRIA_URL__'
    SATRIA_TOKEN = '__SATRIA_TOKEN__'
  }
  stages {
    stage('Prepare release intake') {
      steps {
        script {
          currentBuild.displayName = "#${env.BUILD_NUMBER} ${params.ASSET_NAME}"
        }
        sh '''
set -eu
GATE_JSON=null
if [ -n "${GATE_OVERRIDE_DECISION:-}" ]; then
  GATE_JSON="\\"$GATE_OVERRIDE_DECISION\\""
fi
cat > release-intake.json <<EOF
{
  "asset_code": "$ASSET_CODE",
  "asset_name": "$ASSET_NAME",
  "release_version": "jenkins-$BUILD_NUMBER-$JOB_NAME",
  "image_ref": "$IMAGE_REF",
  "git_commit": "${GIT_COMMIT:-manual-run}",
  "build_number": "$BUILD_NUMBER",
  "environment_target": "$ENVIRONMENT_TARGET",
  "gate_override_decision": $GATE_JSON
}
EOF
cat release-intake.json
'''
      }
    }
    stage('Intake release to SATRIA') {
      steps {
        sh '''
set -eu
curl -sS -X POST "$SATRIA_URL/api/v1/releases/intake" \
  -H "Authorization: Bearer $SATRIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d @release-intake.json > release-response.json
python3 - <<'PY'
import json
data = json.load(open('release-response.json'))
print(json.dumps(data, indent=2))
PY
'''
      }
    }
    stage('Create scan job') {
      steps {
        sh '''
set -eu
ASSET_ID=$(python3 -c 'import json; print(json.load(open("release-response.json"))["asset_id"])')
RELEASE_ID=$(python3 -c 'import json; print(json.load(open("release-response.json"))["release_id"])')
cat > scan-request.json <<EOF
{
  "asset_id": $ASSET_ID,
  "release_id": $RELEASE_ID,
  "image_ref": "$IMAGE_REF",
  "scan_profile": "$SCAN_PROFILE",
  "requested_by": "jenkins-local",
  "build_number": "$BUILD_NUMBER"
}
EOF
curl -sS -X POST "$SATRIA_URL/api/v1/scans" \
  -H "Authorization: Bearer $SATRIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d @scan-request.json > scan-response.json
python3 - <<'PY'
import json
data = json.load(open('scan-response.json'))
print(json.dumps(data, indent=2))
PY
'''
      }
    }
    stage('Poll SATRIA status') {
      steps {
        sh '''
set -eu
SCAN_ID=$(python3 -c 'import json; print(json.load(open("scan-response.json"))["scan_id"])')
for i in $(seq 1 60); do
  curl -sS -H "Authorization: Bearer $SATRIA_TOKEN" \
    "$SATRIA_URL/api/v1/scans/$SCAN_ID" > scan-status.json
  STATUS=$(python3 -c 'import json; print(json.load(open("scan-status.json"))["status"])')
  echo "poll-$i status=$STATUS"
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ] || [ "$STATUS" = "cancelled" ]; then
    exit 0
  fi
  sleep 10
done
echo "Timeout menunggu scan SATRIA"
exit 1
'''
      }
    }
    stage('Fetch result') {
      steps {
        sh '''
set -eu
SCAN_ID=$(python3 -c 'import json; print(json.load(open("scan-response.json"))["scan_id"])')
curl -sS -H "Authorization: Bearer $SATRIA_TOKEN" \
  "$SATRIA_URL/api/v1/scans/$SCAN_ID/result" > scan-result.json
python3 - <<'PY'
import json
data = json.load(open('scan-result.json'))
print(json.dumps(data, indent=2))
PY
'''
      }
    }
    stage('Evaluate gate') {
      steps {
        script {
          def result = readJSON file: 'scan-result.json'
          currentBuild.description = 'decision=' + result.decision + ' findings=' + result.total_findings
          if (result.status != 'completed') {
            error('Scan SATRIA tidak selesai normal: status=' + result.status)
          }
          if (result.decision == 'blocked') {
            error('Release diblokir SATRIA. policy=' + result.policy_name + ' findings=' + result.total_findings)
          }
          if (result.decision == 'need_approval') {
            unstable('SATRIA meminta approval manual sebelum release lanjut.')
          }
        }
      }
    }
    stage('Publish to IRIS (optional)') {
      when {
        expression { return params.PUBLISH_TO_IRIS }
      }
      steps {
        sh '''
set -eu
SCAN_ID=$(python3 -c 'import json; print(json.load(open("scan-response.json"))["scan_id"])')
curl -sS -X POST "$SATRIA_URL/api/v1/scans/$SCAN_ID/publish-ticket" \
  -H "Authorization: Bearer $SATRIA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_system":"IRIS","severity_filter":["critical","high"]}' > publish-response.json
python3 - <<'PY'
import json
data = json.load(open('publish-response.json'))
print(json.dumps(data, indent=2))
PY
        '''
      }
    }
    stage('Archive artifacts') {
      steps {
        archiveArtifacts artifacts: '*.json', allowEmptyArchive: true
      }
    }
  }
}
