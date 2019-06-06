function New-AzureRMServicePrincipalBySelfSignedCert {

    <#
.SYNOPSIS
Custom New-AzureRMServicePrincipalBySelfSignedCert PowerShell function automates the creation of a local self-signed certificate,
creates an AzureRM AD Application, uploads the Certificate to Azure and maps the cert credentials to the AD Application.

.DESCRIPTION
Custom New-AzureRMServicePrincipalBySelfSignedCert PowerShell function automates the creation of a local self-signed certificate,
creates an AzureRM AD Application, uploads the Certificate to Azure and maps the cert credentials to the AD Application.

.PARAMETER SubscriptionName
Subscription Name for the Azure Application.

.EXAMPLE
New-AzureRMServicePrincipalBySelfSignedCert

.FUNCTIONALITY
        PowerShell Language
/#>

    [CmdletBinding()]

    param(
        [parameter(Mandatory = $false)]
        [string]$SubscriptionName = "MyVSEnterpriseSandbox"  
    )
    Select-AzureRmSubscription -SubscriptionName $SubscriptionName

    #Create SPN:
    # Set Cert Date Range
    $currentDate = Get-Date
    $endDate = $currentDate.AddYears(1)
    $notAfter = $endDate.AddYears(2)
 
    # Make Cert
    $certName = "SandboxReadOnlySPN"
    $certStore = "Cert:\LocalMachine\My"
    $existingCertObject = Get-ChildItem -Path "Cert:\LocalMachine\My" | ? { $_.Subject -like "*CN=SandboxReadOnlySPN*" } -ErrorAction SilentlyContinue
    if ($existingCertObject) {
        $existingCertObject | Remove-Item -Force
    }
    $certThumbprint = (New-SelfSignedCertificate -DnsName “$certName” -CertStoreLocation $CertStore -KeyExportPolicy Exportable -Provider “Microsoft Enhanced RSA and AES Cryptographic Provider” -NotAfter $notAfter).Thumbprint
    $pfxPassword = Read-Host -Prompt “Enter password to protect exported certificate” -AsSecureString
    $pfxcertpath = "c:\AzureCertificateFunctions\SandboxReadOnlySPNCertificate.pfx"
    # $pfxcertpath1 = ($PSScriptRoot + $pfxcertpath)

    #Export the cert to a pfx file
    Export-PfxCertificate -Cert "$($certStore)\$($certThumbprint)" -FilePath $pfxcertpath -Password $pfxPassword
 
    # grab cert and key values
    $exportpfxPath = Get-ChildItem -Path $pfxcertpath
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate -ArgumentList @($exportpfxPath.FullName, $pfxPassword)
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
    $keyId = [guid]::NewGuid()

    # Incase it's needed, export the pfx file to the file system as a DER-encoded .cer file without its private key to be uploaded to Azure if and when required.
    # But in for this function, we use a KeyCredential object variable to autoprovision and map the local cert to the AD SPN
    $certpath = "c:\AzureCertificateFunctions\SandboxReadOnlyConvertPFXtoCer.cer"
    Export-Certificate -Type CERT -Cert "$($certStore)\$($certThumbprint)" -Force -FilePath $certpath

    # update key
    $keyCredential = New-Object -TypeName Microsoft.Azure.Graph.RBAC.Version1_6.ActiveDirectory.PSADKeyCredential
    $keyCredential.StartDate = $currentDate
    $keyCredential.EndDate = $endDate
    $keyCredential.KeyId = $keyId
    $keyCredential.CertValue = $keyValue

    # make spn
    $adAppName = $certName
    $adAppHomePage = ('https://' + $certName)
    $adAppIdentifierUri = ('https://' + $certName)
    $existingAzureRmADApplication = Get-AzureRmADApplication -DisplayName $adAppName -ErrorAction SilentlyContinue
    if ($existingAzureRmADApplication) {
        Write-Host "Removing existing AzureRMADApplication..."

        $existingAzureRmADApplication | Remove-AzureRmADApplication -Force

        Write-Host "Done removing existing AzureRMADApplication ..."

    }

    "Creating new AzureRMADApplication ..."
    $adApp = New-AzureRmADApplication -DisplayName $adAppName -HomePage $adAppHomePage -IdentifierUris $adAppIdentifierUri -KeyCredentials $keyCredential
    Write-Output "New Azure AD App Id: $($adApp.ApplicationId)"
    New-AzureRmADServicePrincipal -ApplicationId $adApp.ApplicationId

    $spnParameters = @{
        adAppId = $adApp.ApplicationId
    }

    return $spnParameters

}


function New-AzureRMRoleAssignmentforCertBasedSPN {
    <#
.SYNOPSIS
Custom New-AzureRMRoleAssignmentforCertBasedSPN PowerShell function creates a role assignment for the Azure RM AD Application within the previously defined subscription.

.DESCRIPTION
Custom New-AzureRMRoleAssignmentforCertBasedSPN PowerShell function creates a role assignment for the Azure RM AD Application within the previously defined subscription.

.PARAMETER AppID
The Application ID of the Application identity to be assigned a defined role.

.PARAMETER Role
The Role to be assigned the Application identity.

.EXAMPLE
New-AzureRMRoleAssignmentforCertBasedSPN -adAppId $returnedAppId.adAppId -role "Reader"

.FUNCTIONALITY
        PowerShell Language
/#>
    param (
        $adAppId,
        $role
    )
    
 
    #RBAC
    $NewRole = $null
    $Retries = 0;
    "Creating new AzureRMRoleAssignment for the SPN.."
    While ($NewRole -eq $null -and $Retries -le 6) {
        # Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
        Start-Sleep -Seconds 25
        New-AzureRmRoleAssignment -ServicePrincipalName $adAppId -RoleDefinitionName $role -ErrorAction SilentlyContinue
        $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $adAppId -ErrorAction SilentlyContinue
        $Retries++;
    }

}

#region Function Calls

$returnedAppId = New-AzureRMServicePrincipalBySelfSignedCert
"AppId is: " + $returnedAppId.adAppId
New-AzureRMRoleAssignmentforCertBasedSPN -adAppId $returnedAppId.adAppId -role "Reader"

"Clean up.."
Get-Variable | Remove-Variable -ErrorAction SilentlyContinue
#endregion