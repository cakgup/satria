import jenkins.model.Jenkins
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jenkins = Jenkins.instance
def pipelinePath = '/var/jenkins_home/seed-jobs/satria-security-gate.Jenkinsfile'
def pipelineFile = new File(pipelinePath)
def satriaUrl = System.getenv('SATRIA_URL') ?: 'http://host.docker.internal:8090'
def satriaToken = System.getenv('SATRIA_API_TOKEN') ?: 'change-me-pipeline-token'

if (!pipelineFile.exists()) {
    println("Pipeline seed file not found: ${pipelinePath}")
    return
}

def pipelineScript = pipelineFile
    .getText('UTF-8')
    .replace('__SATRIA_URL__', satriaUrl.replace('\\', '\\\\'))
    .replace('__SATRIA_TOKEN__', satriaToken.replace('\\', '\\\\'))

def createOrUpdateJob = { String jobName, String jobDescription, Map<String, String> replacements = [:] ->
    def rendered = pipelineScript
    replacements.each { needle, replacement ->
        rendered = rendered.replace(needle, replacement)
    }

    def job = jenkins.getItem(jobName)
    if (job == null) {
        println("Creating Jenkins pipeline job: ${jobName}")
        job = jenkins.createProject(WorkflowJob, jobName)
    } else {
        println("Updating Jenkins pipeline job: ${jobName}")
    }

    job.setDescription(jobDescription)
    job.setDefinition(new CpsFlowDefinition(rendered, true))
    job.save()
}

createOrUpdateJob(
    'satria-security-gate',
    'Pipeline uji lokal untuk mensimulasikan alur build-release ke SATRIA: intake release, create scan, polling result, gate decision, dan publish ticket opsional ke IRIS.'
)

createOrUpdateJob(
    'satria-gate-passed-demo',
    'Demo gate Jenkins lokal dengan keputusan akhir forced allowed agar operator dapat melihat skenario passed secara konsisten.',
    [
        "defaultValue: 'JENKINS-DEMO'"               : "defaultValue: 'JENKINS-GATE-PASSED'",
        "defaultValue: 'Jenkins Demo Service'"      : "defaultValue: 'Jenkins Gate Passed Demo'",
        "defaultValue: 'nginx:latest'"              : "defaultValue: 'nginx:latest'",
        "choices: ['', 'allowed', 'need_approval', 'blocked']": "choices: ['allowed', '', 'need_approval', 'blocked']",
    ]
)

createOrUpdateJob(
    'satria-gate-failed-demo',
    'Demo gate Jenkins lokal dengan keputusan akhir forced blocked agar operator dapat melihat skenario failed secara konsisten.',
    [
        "defaultValue: 'JENKINS-DEMO'"               : "defaultValue: 'JENKINS-GATE-FAILED'",
        "defaultValue: 'Jenkins Demo Service'"      : "defaultValue: 'Jenkins Gate Failed Demo'",
        "defaultValue: 'nginx:latest'"              : "defaultValue: 'nginx:latest'",
        "choices: ['', 'allowed', 'need_approval', 'blocked']": "choices: ['blocked', '', 'allowed', 'need_approval']",
    ]
)

jenkins.save()
