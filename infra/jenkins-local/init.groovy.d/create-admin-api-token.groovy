import hudson.model.User
import java.time.LocalDate
import jenkins.model.Jenkins
import jenkins.security.ApiTokenProperty

def adminId = System.getenv('JENKINS_ADMIN_ID') ?: 'admin'
def apiTokenValue = System.getenv('JENKINS_ADMIN_API_TOKEN')

if (!apiTokenValue?.trim()) {
    println('JENKINS_ADMIN_API_TOKEN is not set; skip API token bootstrap')
    return
}

def user = User.getById(adminId, false)
if (user == null) {
    println("Admin user ${adminId} not found; skip API token bootstrap")
    return
}

def tokenProperty = user.getProperty(ApiTokenProperty.class)
if (tokenProperty == null) {
    println("ApiTokenProperty is missing for ${adminId}; skip API token bootstrap")
    return
}

def tokenName = 'codex-local-bootstrap'
def existing = tokenProperty.tokenStore.tokenList.find { it.name == tokenName }
if (existing != null) {
    tokenProperty.tokenStore.revokeToken(existing.uuid)
    println("Revoked existing API token '${tokenName}' for ${adminId}")
}

tokenProperty.tokenStore.addFixedNewToken(tokenName, apiTokenValue, LocalDate.now().plusYears(5))
user.save()
Jenkins.instance.save()
println("Provisioned fixed API token '${tokenName}' for ${adminId}")
