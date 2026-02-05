# Automated cache refresh and upload script
# 1. Fetches user backup from upstream API
# 2. Generates cache locally
# 3. Uploads to cPanel via FTP
# 4. Triggers remote extraction

param(
    [string]$ApiUrl,
    [string]$ApiKey,
    [string]$Proxy,
    [string]$BackupFile,
    [string]$CacheDir,
    [string]$ZipFile,
    [string]$FtpHost,
    [int]$FtpPort = 21,
    [string]$FtpUser,
    [string]$FtpPass,
    [string]$HostAccountUsername,
    [string]$RemotePath,
    [int]$FtpRetries = 3,
    [int]$FtpRetryDelaySeconds = 10,
    [string]$ExtractUrl,
    [string]$ExtractToken,
    [int]$ExtractRetries = 3,
    [int]$ExtractRetryDelaySeconds = 5,
    [string]$InjectPlacement,
    [string]$InjectMessage1,
    [string]$InjectMessage2
)

$scriptRoot = $PSScriptRoot

function Normalize-Message {
    param([Parameter(Mandatory = $true)][string]$Message)

    if ($Message -match '[\u0600-\u06FF]') {
        return $Message
    }

    if ($Message -match '[ØÙ]') {
        try {
            $latin1 = [System.Text.Encoding]::GetEncoding('ISO-8859-1')
            $utf8 = [System.Text.Encoding]::UTF8
            $bytes = $latin1.GetBytes($Message)
            $fixed = $utf8.GetString($bytes)
            if ($fixed -match '[\u0600-\u06FF]') {
                return $fixed
            }
        } catch {
            return $Message
        }
    }

    return $Message
}

function Build-TrojanMessage {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Placement = "remark"
    )

    $Message = Normalize-Message -Message $Message

    $baseQuery = "security=tls&sni=fake_ip_for_sub_link&insecure=1&allowInsecure=1&type=tcp&headerType=none"
    $remark = ""
    $messageHost = "status.invalid"

    if ($Placement -eq "address") {
        $normalized = ($Message.Trim() -replace "\s+", "-")
        $normalized = $normalized -replace "[^a-zA-Z0-9\-\.]", ""
        if ($normalized -eq "") {
            $normalized = "message"
        }
        $messageHost = "$normalized.invalid"
    } else {
        $remark = [System.Uri]::EscapeDataString($Message)
    }

    $line = "trojan://1@${messageHost}:329?${baseQuery}"
    if ($remark -ne "") {
        $line += "#${remark}"
    }
    return $line
}

$ErrorActionPreference = "Stop"

function Stop-WithPause {
    param([string]$Message)
    if ($Message) {
        Write-Host $Message -ForegroundColor Red
    }
    Write-Host "Press Enter to close..." -ForegroundColor Yellow
    Read-Host | Out-Null
    exit 1
}

# Load config file if exists
$configPath = Join-Path $scriptRoot "Update-Cache.config.ps1"
if (Test-Path $configPath) {
    Write-Host "Loading configuration from Update-Cache.config.ps1..." -ForegroundColor Gray
    . $configPath
    
    # Apply config values if parameters not explicitly provided
    if (-not $PSBoundParameters.ContainsKey('ApiUrl')) { $ApiUrl = $Config.ApiUrl }
    if (-not $PSBoundParameters.ContainsKey('ApiKey')) { $ApiKey = $Config.ApiKey }
    if (-not $PSBoundParameters.ContainsKey('Proxy')) { $Proxy = $Config.Proxy }
    if (-not $PSBoundParameters.ContainsKey('BackupFile')) { $BackupFile = $Config.BackupFile }
    if (-not $PSBoundParameters.ContainsKey('CacheDir')) { $CacheDir = $Config.CacheDir }
    if (-not $PSBoundParameters.ContainsKey('ZipFile')) { $ZipFile = $Config.ZipFile }
    if (-not $PSBoundParameters.ContainsKey('FtpHost')) { $FtpHost = $Config.FtpHost }
    if (-not $PSBoundParameters.ContainsKey('FtpPort')) { $FtpPort = $Config.FtpPort }
    if (-not $PSBoundParameters.ContainsKey('FtpUser')) { $FtpUser = $Config.FtpUser }
    if (-not $PSBoundParameters.ContainsKey('FtpPass')) { $FtpPass = $Config.FtpPass }
    if (-not $PSBoundParameters.ContainsKey('HostAccountUsername')) { $HostAccountUsername = $Config.HostAccountUsername }
    if (-not $PSBoundParameters.ContainsKey('RemotePath')) { $RemotePath = $Config.RemotePath }
    if (-not $PSBoundParameters.ContainsKey('FtpRetries')) { $FtpRetries = $Config.FtpRetries }
    if (-not $PSBoundParameters.ContainsKey('FtpRetryDelaySeconds')) { $FtpRetryDelaySeconds = $Config.FtpRetryDelaySeconds }
    if (-not $PSBoundParameters.ContainsKey('ExtractUrl')) { $ExtractUrl = $Config.ExtractUrl }
    if (-not $PSBoundParameters.ContainsKey('ExtractToken')) { $ExtractToken = $Config.ExtractToken }
    if (-not $PSBoundParameters.ContainsKey('ExtractRetries')) { $ExtractRetries = $Config.ExtractRetries }
    if (-not $PSBoundParameters.ContainsKey('ExtractRetryDelaySeconds')) { $ExtractRetryDelaySeconds = $Config.ExtractRetryDelaySeconds }
    if (-not $PSBoundParameters.ContainsKey('InjectPlacement')) { $InjectPlacement = $Config.InjectPlacement }
    if (-not $PSBoundParameters.ContainsKey('InjectMessage1')) { $InjectMessage1 = $Config.InjectMessage1 }
    if (-not $PSBoundParameters.ContainsKey('InjectMessage2')) { $InjectMessage2 = $Config.InjectMessage2 }
}

function Resolve-RelativePath {
    param([string]$PathValue)

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $PathValue
    }
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }
    return (Join-Path $scriptRoot $PathValue)
}

$BackupFile = Resolve-RelativePath $BackupFile
$CacheDir = Resolve-RelativePath $CacheDir
$ZipFile = Resolve-RelativePath $ZipFile

Write-Host "=== Hiddify Cache Automation ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Fetch user backup from API
Write-Host "[1/5] Fetching user backup from API..." -ForegroundColor Yellow
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    $headers = @{
        "Accept" = "application/json"
        "Hiddify-API-Key" = $ApiKey
    }

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        throw "curl.exe not found in PATH."
    }
    $tmpFile = [System.IO.Path]::GetTempFileName()
    $proxyArg = @()
    if ($Proxy -and $Proxy.Trim() -ne '') {
        $proxyArg = @('--proxy', $Proxy)
    }
    & $curl @proxyArg -sS --retry 3 --retry-delay 1 --connect-timeout 10 --max-time 60 -H "Accept: application/json" -H "Hiddify-API-Key: $ApiKey" $ApiUrl -o $tmpFile
    if ($LASTEXITCODE -ne 0) {
        Remove-Item $tmpFile -Force
        throw "curl.exe request failed (exit code $LASTEXITCODE)."
    }
    $usersJson = (Get-Content -Raw -Encoding UTF8 $tmpFile).Trim()
    Remove-Item $tmpFile -Force
    $timestamp = (Get-Date).ToString("o")
    $backupJson = "{`n  `"generated_at`": `"$timestamp`",`n  `"users`": $usersJson`n}"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($BackupFile, $backupJson, $utf8NoBom)
    Write-Host "    User backup saved to $BackupFile" -ForegroundColor Green
} catch {
    Stop-WithPause "    Failed to fetch backup: $_"
}

# Step 2: Generate cache
Write-Host "[2/5] Generating cache from backup..." -ForegroundColor Yellow
try {
    # Set proxy for PHP cURL to reach upstream through VPN
    $env:RELAY_CURL_PROXY = $Proxy
    $injectLines = @()
    foreach ($message in @($InjectMessage1, $InjectMessage2)) {
        if ($message -and $message.Trim() -ne '') {
            $injectLines += (Build-TrojanMessage -Message $message -Placement $InjectPlacement)
        }
    }
    if ($injectLines.Count -ge 1) {
        $env:RELAY_SNAPSHOT_INJECT_1 = $injectLines[0]
    } else {
        Remove-Item Env:RELAY_SNAPSHOT_INJECT_1 -ErrorAction SilentlyContinue
    }
    if ($injectLines.Count -ge 2) {
        $env:RELAY_SNAPSHOT_INJECT_2 = $injectLines[1]
    } else {
        Remove-Item Env:RELAY_SNAPSHOT_INJECT_2 -ErrorAction SilentlyContinue
    }
    $snapshotScript = Join-Path $scriptRoot "..\apps\relay\snapshot-cache.php"
    & php $snapshotScript --backup=$BackupFile --force
    if ($LASTEXITCODE -ne 0) {
        throw "snapshot-cache.php failed with exit code $LASTEXITCODE"
    }
    Write-Host "    Cache generated successfully" -ForegroundColor Green
} catch {
    Stop-WithPause "    Cache generation failed: $_"
}

# Step 3: Zip cache directory
Write-Host "[3/5] Creating cache archive..." -ForegroundColor Yellow
try {
    if (Test-Path $ZipFile) {
        Remove-Item $ZipFile -Force
    }
    
    Compress-Archive -Path "$CacheDir/*" -DestinationPath $ZipFile -Force
    $zipSize = (Get-Item $ZipFile).Length / 1MB
    Write-Host "    Archive created: $ZipFile ($([math]::Round($zipSize, 2)) MB)" -ForegroundColor Green
} catch {
    Stop-WithPause "    Failed to create archive: $_"
}

# Step 4: Upload via FTP
Write-Host "[4/5] Uploading to cPanel via FTP..." -ForegroundColor Yellow
try {
    if ($FtpPass -eq "") {
        $FtpPass = Read-Host "Enter FTP password" -AsSecureString
        $FtpPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($FtpPass)
        )
    }
    
    # Use WinSCP for reliable FTP (download from https://winscp.net if not installed)
    $winscpPath = "${env:ProgramFiles(x86)}\WinSCP\WinSCPcom.exe"
    if (!(Test-Path $winscpPath)) {
        $winscpPath = "$env:ProgramFiles\WinSCP\WinSCPcom.exe"
    }
    if (!(Test-Path $winscpPath)) {
        $winscpPath = "${env:ProgramFiles(x86)}\WinSCP\WinSCP.com"
    }
    if (!(Test-Path $winscpPath)) {
        throw "WinSCP not found. Install from https://winscp.net or use manual FTP upload."
    }
    
    if ($RemotePath -and $RemotePath.Trim() -ne '') {
        $remotePath = $RemotePath.Trim()
    } else {
        $remotePath = "/"
    }

    if ($remotePath -eq "/" -and $HostAccountUsername -and $HostAccountUsername.Trim() -ne '') {
        $candidateHome = $HostAccountUsername.Trim()
        if ($candidateHome -match '^[A-Za-z0-9_]+$') {
            Write-Host "    Using FTP root (/). Server home likely /home/$candidateHome/public_ftp" -ForegroundColor Gray
        } else {
            Write-Host "    Using FTP root (/)." -ForegroundColor Gray
        }
    } else {
        Write-Host "    Target remote path: $remotePath" -ForegroundColor Gray
    }
    $ftpUserEncoded = [System.Uri]::EscapeDataString($FtpUser)
    $ftpPassEncoded = [System.Uri]::EscapeDataString($FtpPass)

    $attempt = 0
    $maxAttempts = [Math]::Max(1, $FtpRetries)
    $uploadSuccess = $false
    while ($attempt -lt $maxAttempts -and -not $uploadSuccess) {
        $attempt++
        Write-Host "    FTP attempt $attempt of $maxAttempts..." -ForegroundColor Gray
        $script = @"
option batch on
option confirm off
open ftp://${ftpUserEncoded}:${ftpPassEncoded}@${FtpHost}:${FtpPort}
cd $remotePath
put "$ZipFile"
exit
"@

        $scriptFile = [System.IO.Path]::GetTempFileName()
        $script | Set-Content -Path $scriptFile -Encoding ASCII
        
        $output = & $winscpPath /script=$scriptFile /log="$env:TEMP\winscp.log" 2>&1
        Remove-Item $scriptFile -Force

        if ($LASTEXITCODE -eq 0) {
            $uploadSuccess = $true
        } else {
            if ($attempt -lt $maxAttempts) {
                Write-Host "    FTP attempt failed. Retrying in $FtpRetryDelaySeconds seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $FtpRetryDelaySeconds
            }
        }
    }

    if (-not $uploadSuccess) {
        throw "WinSCP upload failed. Check log at: $env:TEMP\winscp.log"
    }

    Write-Host "    Upload completed successfully" -ForegroundColor Green
} catch {
    Stop-WithPause "    FTP upload failed: $_"
}

# Step 5: Trigger extraction
Write-Host "[5/5] Triggering remote extraction..." -ForegroundColor Yellow
try {
    # No proxy needed for extract endpoint (direct cPanel access)
    $tokenEncoded = [System.Uri]::EscapeDataString($ExtractToken)
    $extractHeaders = @{ "X-Extract-Token" = $ExtractToken }

    $attempt = 0
    $maxAttempts = [Math]::Max(1, $ExtractRetries)
    $extractSuccess = $false
    while ($attempt -lt $maxAttempts -and -not $extractSuccess) {
        $attempt++
        Write-Host "    Extract attempt $attempt of $maxAttempts..." -ForegroundColor Gray
        try {
            $extractResponse = Invoke-RestMethod -Uri "$ExtractUrl`?token=$tokenEncoded" -Method Get -Proxy $null -Headers $extractHeaders
            Write-Host "    $($extractResponse.message)" -ForegroundColor Green
            Write-Host "    Timestamp: $($extractResponse.timestamp)" -ForegroundColor Gray
            $extractSuccess = $true
        } catch {
            if ($attempt -lt $maxAttempts) {
                Write-Host "    Extract attempt failed. Retrying in $ExtractRetryDelaySeconds seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $ExtractRetryDelaySeconds
            } else {
                throw $_
            }
        }
    }
} catch {
    Write-Host "    Extraction trigger failed: $_" -ForegroundColor Red
    Write-Host "    You may need to manually extract cache.zip on the server" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Process Complete ===" -ForegroundColor Cyan
Write-Host "Local cache archive: $ZipFile" -ForegroundColor Gray
Write-Host "Remote cache updated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "Closing in 5 seconds..." -ForegroundColor Gray
Start-Sleep -Seconds 5
