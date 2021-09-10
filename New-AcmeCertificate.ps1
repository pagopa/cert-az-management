[CmdletBinding()]
param (
    [string] $AcmeDirectory,
    [string] $AcmeContact,
    [string] $CertificateNames,
    [string] $KeyVaultResourceId,
    [string] $ForceRenewal
)

# Supress progress messages. Azure DevOps doesn't format them correctly (used by New-PACertificate)
# Note: by default, debug messages are not displayed in the console. Use -Debug param
$global:ProgressPreference = 'SilentlyContinue'

## A) Initial local environment setup and sync metadata from key vault (if any)

$isNewAccount = $false

# Split certificate names by comma or semi-colon and select the first
# For wildcard certificates, Posh-ACME replaces * with ! in the directory name
$CertificateNamesArr = $CertificateNames.Replace(',',';') -split ';' | ForEach-Object -Process { $_.Trim() }
$certificateName = ($CertificateNamesArr | Select-Object -First 1).Replace('*', '!')

# Create working directory
$workingDirectory = Join-Path -Path "." -ChildPath "pa"
New-Item -Path $workingDirectory -ItemType Directory -ErrorAction SilentlyContinue # TODO: Remove Error

# Acquire access token for Azure (as we want to leverage the existing connection)
$azureContext = Get-AzContext
$currentAzureProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
$currentAzureProfileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($currentAzureProfile);
$azureAccessToken = $currentAzureProfileClient.AcquireAccessToken($azureContext.Tenant.Id).AccessToken;

# Set Posh-ACME working directory
$env:POSHACME_HOME = $workingDirectory
# NOTE. The Posh-ACME module is not imported using Import-Module because for
# security reason we prefer to store the NuGet package to an internal repository.
# So, it is assumed that the module has been installed from a .nupkg file
# manually downloaded from the PowerShell Gallery, unzipped and copied in a
# directory added to the $env:PSModulePath variable before running this script.
## Import-Module Posh-ACME -Force

# Configure Posh-ACME server and retrieve the server name
Set-PAServer -DirectoryUrl $AcmeDirectory
$currentServerName = ((Get-PAServer).location) -split "/" | Where-Object -FilterScript { $_ } | Select-Object -Skip 1 -First 1
$azureKeyVaultSecretPrefix = "acme-" + $AcmeDirectory.ToLower().Replace('_', '-')

# Get the current LE account file content from key vault (if any):
# the secret name is "acme-le-stage-acct-json" | "acme-le-prod-acct-json"
$keyVaultResource = Get-AzResource -ResourceId $KeyVaultResourceId
$azureKeyVaultAccountName = $azureKeyVaultSecretPrefix + "-" + "acct-json"

# If we have an available ACME account in key vault, copy it to local acct.json file
$azureKeyVaultSecretAcc = (Get-AzKeyVaultSecret -Name $azureKeyVaultAccountName -VaultName $keyVaultResource.Name) #-ErrorAction SilentlyContinue
echo "azure Key Vault SecretAcc $azureKeyVaultSecretAcc"
if ($azureKeyVaultSecretAcc) {
    $accountDataFromKv = [PSCredential]::new("user",($azureKeyVaultSecretAcc).SecretValue).GetNetworkCredential().Password
    $accountNameFromKv = (ConvertFrom-Json –InputObject $accountDataFromKv).id

    # Determine paths to acct.json file (e.g. <serverName>/<accountName>/acct.json)
    $accountDirectoryPath = Join-Path -Path $workingDirectory -ChildPath $currentServerName | Join-Path -ChildPath $accountNameFromKv
    $accountJsonPath = Join-Path -Path $accountDirectoryPath -ChildPath "acct.json"

    # Create the acct.json file and directories
    New-Item -ItemType Directory -Force $accountDirectoryPath
    Out-File -FilePath $accountJsonPath -InputObject $accountDataFromKv

    echo "Account Name FromKv $accountNameFromKv"

    if ($accountNameFromKv) {
        # Update account with data in the file
        Set-PAAccount -ID $accountNameFromKv
    }

}

# Configure Posh-ACME account
$account = Get-PAAccount
if (-not $account) {
    # New account
    $account = New-PAAccount -Contact $AcmeContact -AcceptTOS
    $isNewAccount = $true
}
elseif ($account.contact -ne "mailto:$AcmeContact") {
    # Update account contact
    Set-PAAccount -ID $account.id -Contact $AcmeContact
}

# Re-determine paths to acct.json file (e.g. <serverName>/<accountName>/acct.json)
$accountDirectoryPath = Join-Path -Path $workingDirectory -ChildPath $currentServerName | Join-Path -ChildPath $account.id
$accountJsonPath = Join-Path -Path $accountDirectoryPath -ChildPath "acct.json"

# Determine paths to order.json file (e.g. <serverName>/<accountName>/<certName>/order.json)
$currentAccountName = (Get-PAAccount).id
$orderDirectoryPath = Join-Path -Path $workingDirectory -ChildPath $currentServerName | Join-Path -ChildPath $currentAccountName | Join-Path -ChildPath $certificateName
$orderJsonPath = Join-Path -Path $orderDirectoryPath -ChildPath "order.json"

# Get the current certificate order file content from key vault (if any):
# the secret name is "acme-le-stage-<certName>-order-json" | "acme-le-prod-<certName>-order-json"
$azureKeyVaultOrderName = $azureKeyVaultSecretPrefix + "-" + $certificateName.Replace(".", "-").Replace("!", "wildcard") + "-order-json"
if ($isNewAccount -eq $false) {
    # If we have an available order in key vault, copy it to local order.json file
    # only if that certificate order was generated with current ACME account;
    # otherwise ignore it to force its regeneration and update in key vault.
    $azureKeyVaultSecretOrder = Get-AzKeyVaultSecret -Name $azureKeyVaultOrderName -VaultName $keyVaultResource.Name -ErrorAction SilentlyContinue
    if ($azureKeyVaultSecretOrder) {
        $orderData = [PSCredential]::new("user",($azureKeyVaultSecretOrder).SecretValue).GetNetworkCredential().Password
        if ($orderData) {
            # Check that the location URL contains the current account ID...
            $orderDataLocation = (ConvertFrom-Json –InputObject $orderData).location
            if ($orderDataLocation -match '.*/order/' + $currentAccountName +'/.*') {
                New-Item -ItemType Directory -Force $orderDirectoryPath
                Out-File -FilePath $orderJsonPath -InputObject $orderData
            }
        }
    }
}

## B) Request certificate from LE server using ACME client

$paPluginArgs = @{
    AZSubscriptionId = $azureContext.Subscription.Id
    AZAccessToken    = $azureAccessToken;
}
if ($ForceRenewal -eq "true") {
    New-PACertificate -Domain $CertificateNamesArr -DnsPlugin Azure -PluginArgs $paPluginArgs -Force
}
else {
    New-PACertificate -Domain $CertificateNamesArr -DnsPlugin Azure -PluginArgs $paPluginArgs
}

## C) Update LE metadata in key vault's secrets (if data is changed)

# Sync account data in the working directory back to key vault
if (Test-Path -Path $accountJsonPath) {
    # Load current account data from local file
    $currentAccountData = Get-Content -Path $accountJsonPath -Raw

    # If we have a different account data from Key Vault, update it
    if ($currentAccountData -and ($currentAccountData -ne $accountDataFromKv)) {
        Write-Debug "Updating acct.json content to secret in key vault..."
        Set-AzKeyVaultSecret -VaultName $keyVaultResource.Name -SecretName $azureKeyVaultAccountName -SecretValue (ConvertTo-SecureString $currentAccountData -force -AsPlainText) | Out-Null
    }
}

# Sync order data in the working directory back to key vault
if (Test-Path -Path $orderJsonPath) {
    # Load current order data from local file
    $currentOrderData = Get-Content -Path $orderJsonPath -Raw

    # If we have a different order data from Key Vault, update it
    if ($orderData -ne $currentOrderData) {
        Write-Debug "Updating order.json content to secret in key vault..."
        Set-AzKeyVaultSecret -VaultName $keyVaultResource.Name -SecretName $azureKeyVaultOrderName -SecretValue (ConvertTo-SecureString $currentOrderData -force -AsPlainText) | Out-Null
    }
}
