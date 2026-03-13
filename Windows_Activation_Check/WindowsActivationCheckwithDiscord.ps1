# Windows Activation & Edition Detector with Discord Webhook
# Run as Administrator for best results

# ============================================================
#   CONFIGURE YOUR DISCORD WEBHOOK URL HERE
# ============================================================
$discordWebhook = "https://discord.com/api/webhooks/1474359023741440073/YZUROibJLztcF32AXwybgWhWRkylhL3RIO6olVD76LuEngSvwe1qoCdVE_hEHP74s7wS"
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Windows Activation Status Detector   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- User Input at Startup ---
Write-Host "[SCAN INFO]" -ForegroundColor Yellow
$organization = Read-Host "  Enter Organization Name"
$auditorName  = Read-Host "  Enter Your Name (who is running this scan)"
Write-Host ""

if ([string]::IsNullOrWhiteSpace($organization)) { $organization = "Not Specified" }
if ([string]::IsNullOrWhiteSpace($auditorName))  { $auditorName  = "Not Specified" }

Write-Host "  Organization : $organization" -ForegroundColor Cyan
Write-Host "  Auditor      : $auditorName" -ForegroundColor Cyan
Write-Host ""

# --- OS Edition Info ---
$os = Get-WmiObject -Class Win32_OperatingSystem
$caption      = $os.Caption
$buildNumber  = $os.BuildNumber
$version      = $os.Version
$computerName = $env:COMPUTERNAME
$username     = $env:USERNAME

Write-Host "[OS INFO]" -ForegroundColor Yellow
Write-Host "  Edition   : $caption"
Write-Host "  Version   : $version"
Write-Host "  Build     : $buildNumber"
Write-Host ""

# --- Activation Status ---
Write-Host "[ACTIVATION STATUS]" -ForegroundColor Yellow

$licenseStatus = @{
    0 = "Unlicensed"
    1 = "Licensed (Activated)"
    2 = "OOBGrace (Out-of-Box Grace Period)"
    3 = "OOTGrace (Out-of-Tolerance Grace Period)"
    4 = "NonGenuineGrace (Non-Genuine Grace Period)"
    5 = "Notification (Not Activated)"
    6 = "ExtendedGrace"
}

$slp = Get-WmiObject -Query "SELECT * FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey <> null" -ErrorAction SilentlyContinue

$productName = "N/A"
$partialKey  = "N/A"
$channel     = "N/A"
$statusText  = "N/A"
$statusCode  = -1

if ($slp) {
    foreach ($product in $slp) {
        $statusCode  = [int]$product.LicenseStatus
        $partialKey  = $product.PartialProductKey
        $channel     = $product.ProductKeyChannel
        $productName = $product.Name

        if ($licenseStatus.ContainsKey($statusCode)) {
            $statusText = $licenseStatus[$statusCode]
        } else {
            $statusText = "Unknown (Code: $statusCode)"
        }

        Write-Host "  Product    : $productName"
        Write-Host "  Partial Key: XXXXX-XXXXX-XXXXX-XXXXX-$partialKey"
        Write-Host "  Channel    : $channel"

        if ($statusCode -eq 1) {
            Write-Host "  Status     : $statusText" -ForegroundColor Green
        } elseif ($statusCode -eq 0 -or $statusCode -eq 5) {
            Write-Host "  Status     : $statusText" -ForegroundColor Red
        } else {
            Write-Host "  Status     : $statusText" -ForegroundColor DarkYellow
        }
        Write-Host ""
    }
} else {
    Write-Host "  Could not retrieve licensing info. Try running as Administrator." -ForegroundColor Red
    Write-Host ""
}

# --- Key Channel Analysis ---
Write-Host "[KEY TYPE ANALYSIS]" -ForegroundColor Yellow
$keyTypeText = "Unknown"

if ($slp) {
    $channel = ($slp | Select-Object -First 1).ProductKeyChannel
    switch -Wildcard ($channel) {
        "Retail"  { $keyTypeText = "Retail (Purchased legitimately)";               Write-Host "  Key Type  : $keyTypeText" -ForegroundColor Green }
        "OEM:DM"  { $keyTypeText = "OEM:DM (Digital pre-installed by manufacturer)"; Write-Host "  Key Type  : $keyTypeText" -ForegroundColor Green }
        "OEM:COA" { $keyTypeText = "OEM:COA (Sticker/COA key from manufacturer)";   Write-Host "  Key Type  : $keyTypeText" -ForegroundColor Green }
        "OEM*"    { $keyTypeText = "OEM (Pre-installed by manufacturer)";            Write-Host "  Key Type  : $keyTypeText" -ForegroundColor Green }
        "Volume*" { $keyTypeText = "Volume License (Enterprise/Education)";          Write-Host "  Key Type  : $keyTypeText" -ForegroundColor Cyan }
        "KMS*"    { $keyTypeText = "KMS Channel (possibly cracked)";                 Write-Host "  Key Type  : $keyTypeText" -ForegroundColor Magenta }
        default   { $keyTypeText = $channel;                                          Write-Host "  Key Type  : $keyTypeText" -ForegroundColor Gray }
    }
}
Write-Host ""

# --- KMS Detection ---
Write-Host "[KMS ACTIVATION DETECTION]" -ForegroundColor Yellow

$kmsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
$kmsServer  = (Get-ItemProperty -Path $kmsRegPath -Name "KeyManagementServiceName" -ErrorAction SilentlyContinue).KeyManagementServiceName
$kmsMachine = (Get-ItemProperty -Path $kmsRegPath -Name "KeyManagementServiceMachine" -ErrorAction SilentlyContinue).KeyManagementServiceMachine

$kmsFound      = $false
$kmsDisplay    = "None"
$isLegitKMS    = $false
$kmsAssessment = "No KMS server configured."

if ($kmsServer)       { $kmsDisplay = $kmsServer;  $kmsFound = $true }
elseif ($kmsMachine)  { $kmsDisplay = $kmsMachine; $kmsFound = $true }

$legitimateKMS = @("localhost", "127.0.0.1", "kms.corp", "kms.local", "kms.internal")

if ($kmsFound) {
    foreach ($legit in $legitimateKMS) {
        if ($kmsDisplay -like "*$legit*") { $isLegitKMS = $true }
    }

    if ($isLegitKMS) {
        $kmsAssessment = "Likely a legitimate corporate/internal KMS server."
        Write-Host "  KMS Server : $kmsDisplay" -ForegroundColor Cyan
        Write-Host "  Assessment : $kmsAssessment" -ForegroundColor Cyan
    } else {
        $kmsAssessment = "Third-party/public KMS server - likely a CRACK."
        Write-Host "  KMS Server : $kmsDisplay" -ForegroundColor Red
        Write-Host "  Assessment : $kmsAssessment" -ForegroundColor Red
    }
} else {
    Write-Host "  $kmsAssessment" -ForegroundColor Green
}
Write-Host ""

# --- Crack Tool Artifacts ---
Write-Host "[CRACK TOOL ARTIFACTS]" -ForegroundColor Yellow
$suspiciousItems = @()

$crackedRegPaths = @(
    "HKLM:\SOFTWARE\KMSAuto", "HKLM:\SOFTWARE\KMSpico",
    "HKCU:\SOFTWARE\KMSAuto", "HKCU:\SOFTWARE\KMSpico"
)
foreach ($path in $crackedRegPaths) {
    if (Test-Path $path) { $suspiciousItems += "Registry key: $path" }
}

$suspiciousTasks = @("KMSAuto", "KMSpico", "AutoKMS", "AutoKMS Net")
foreach ($task in $suspiciousTasks) {
    $t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if ($t) { $suspiciousItems += "Scheduled task: $($t.TaskName)" }
}

$suspiciousServices = @("KMSAuto", "KMSpico", "AutoKMS", "KMSELDI", "KMSEmulator")
foreach ($svc in $suspiciousServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) { $suspiciousItems += "Service: $($s.Name) [$($s.Status)]" }
}

$suspiciousPaths = @(
    "$env:SystemRoot\AutoKMS",         "$env:ProgramFiles\KMSpico",
    "$env:ProgramFiles\KMSAuto",       "$env:ProgramData\KMSpico",
    "$env:ProgramData\KMSAuto",        "$env:TEMP\KMSAuto",
    "$env:SystemRoot\System32\AutoKMS.exe"
)
foreach ($p in $suspiciousPaths) {
    if (Test-Path $p) { $suspiciousItems += "Path found: $p" }
}

if ($suspiciousItems.Count -gt 0) {
    foreach ($item in $suspiciousItems) { Write-Host "  [!] $item" -ForegroundColor Red }
} else {
    Write-Host "  No crack tool files or registry artifacts found." -ForegroundColor Green
}
Write-Host ""

# --- Summary & Verdict ---
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[SUMMARY]" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$verdict       = "UNKNOWN"
$verdictColor  = "Gray"
$verdictDetail = ""
$discordColor  = 9807270

$isActivated      = ($statusCode -eq 1)
$hasThirdPartyKMS = ($kmsFound -and -not $isLegitKMS)

if ($isActivated -and ($channel -match "Retail|OEM") -and -not $hasThirdPartyKMS -and $suspiciousItems.Count -eq 0) {
    $verdict       = "GENUINELY ACTIVATED"
    $verdictColor  = "Green"
    $verdictDetail = "Windows is properly activated with a legitimate Retail or OEM key."
    $discordColor  = 5763719

} elseif ($isActivated -and ($channel -match "Retail|OEM") -and $hasThirdPartyKMS) {
    $verdict       = "CRACKED (Online KMS)"
    $verdictColor  = "Red"
    $verdictDetail = "OEM/Retail channel but routed through a public KMS crack server.`nMethod : Online KMS (e.g. MAS script / kms.loli.best or similar)`nRisk   : Will deactivate if the KMS server goes offline."
    $discordColor  = 15548997

} elseif ($isActivated -and ($channel -match "Volume|KMS") -and $hasThirdPartyKMS) {
    $verdict       = "CRACKED (KMS Volume)"
    $verdictColor  = "Red"
    $verdictDetail = "Activated using a KMS volume key via a third-party crack server.`nMethod : KMSPico / KMSAuto / MAS or similar tool.`nRisk   : Will deactivate if the KMS server goes offline."
    $discordColor  = 15548997

} elseif ($isActivated -and ($channel -match "Volume|KMS") -and $suspiciousItems.Count -gt 0) {
    $verdict       = "CRACKED (Local KMS Tool)"
    $verdictColor  = "Red"
    $verdictDetail = "Activated via local KMS emulator with crack artifacts present.`nMethod : KMSPico / KMSAuto (local tool)."
    $discordColor  = 15548997

} elseif ($isActivated -and ($channel -match "Volume|KMS") -and -not $hasThirdPartyKMS) {
    $verdict       = "KMS ACTIVATED (Possibly Legitimate)"
    $verdictColor  = "DarkYellow"
    $verdictDetail = "Could be a genuine corporate/school volume license.`nCould also be a local KMS emulator with no leftover files."
    $discordColor  = 16776960

} elseif (-not $isActivated -and $hasThirdPartyKMS) {
    $verdict       = "CRACK ATTEMPTED BUT FAILED"
    $verdictColor  = "Red"
    $verdictDetail = "A KMS crack server is configured but Windows is not activated.`nThe crack server may be unreachable or the key may be blocked."
    $discordColor  = 15548997

} elseif (-not $isActivated) {
    $verdict       = "NOT ACTIVATED"
    $verdictColor  = "Red"
    $verdictDetail = "Windows is running without any valid activation."
    $discordColor  = 15548997
}

Write-Host ""
Write-Host "  VERDICT: $verdict" -ForegroundColor $verdictColor
Write-Host "  $verdictDetail" -ForegroundColor $verdictColor
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# --- Send to Discord ---
Write-Host ""
Write-Host "Sending results to Discord..." -ForegroundColor Cyan

$artifactList = if ($suspiciousItems.Count -gt 0) { $suspiciousItems -join "`n" } else { "None found" }
$timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$discordBody = [PSCustomObject]@{
    username = "Windows Activation Detector"
    embeds   = @(
        [PSCustomObject]@{
            title     = "Windows Activation Report"
            color     = $discordColor
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            fields    = @(
                [PSCustomObject]@{ name = "Organization";    value = $organization;  inline = $true }
                [PSCustomObject]@{ name = "Auditor";         value = $auditorName;   inline = $true }
                [PSCustomObject]@{ name = "Scan Time";       value = $timestamp;     inline = $true }
                [PSCustomObject]@{ name = "Computer Name";   value = $computerName;  inline = $true }
                [PSCustomObject]@{ name = "Windows User";    value = $username;      inline = $true }
                [PSCustomObject]@{ name = "OS Edition";      value = $caption;       inline = $false }
                [PSCustomObject]@{ name = "Version";         value = $version;       inline = $true }
                [PSCustomObject]@{ name = "Build";           value = $buildNumber;   inline = $true }
                [PSCustomObject]@{ name = "Product";         value = $productName;   inline = $false }
                [PSCustomObject]@{ name = "Partial Key";     value = "XXXXX-XXXXX-XXXXX-XXXXX-$partialKey"; inline = $true }
                [PSCustomObject]@{ name = "Channel";         value = $channel;       inline = $true }
                [PSCustomObject]@{ name = "License Status";  value = $statusText;    inline = $false }
                [PSCustomObject]@{ name = "Key Type";        value = $keyTypeText;   inline = $true }
                [PSCustomObject]@{ name = "KMS Server";      value = $kmsDisplay;    inline = $true }
                [PSCustomObject]@{ name = "KMS Assessment";  value = $kmsAssessment; inline = $false }
                [PSCustomObject]@{ name = "Crack Artifacts"; value = $artifactList;  inline = $false }
                [PSCustomObject]@{ name = "VERDICT";         value = "**$verdict**`n$verdictDetail"; inline = $false }
            )
            footer    = [PSCustomObject]@{ text = "Windows Activation Detector | $organization" }
        }
    )
} | ConvertTo-Json -Depth 10

try {
    Invoke-RestMethod -Uri $discordWebhook -Method Post -Body $discordBody -ContentType "application/json" | Out-Null
    Write-Host "Results shared with Karan successfully!" -ForegroundColor Green
} catch {
    Write-Host "Failed to share the results: $_" -ForegroundColor Red
    Write-Host "Check your webhook URL is correct." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
