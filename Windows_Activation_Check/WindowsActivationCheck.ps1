# Windows Activation & Edition Detector
# Run as Administrator for best results

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Windows Activation Status Detector   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- OS Edition Info ---
$os = Get-WmiObject -Class Win32_OperatingSystem
$caption = $os.Caption
$buildNumber = $os.BuildNumber
$version = $os.Version

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

if ($slp) {
    foreach ($product in $slp) {
        $statusCode = [int]$product.LicenseStatus
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

if ($slp) {
    foreach ($product in $slp) {
        $channel = $product.ProductKeyChannel
        switch -Wildcard ($channel) {
            "Retail"  { Write-Host "  Key Type  : Retail (Purchased legitimately)" -ForegroundColor Green }
            "OEM:DM"  { Write-Host "  Key Type  : OEM:DM (Digital pre-installed by manufacturer)" -ForegroundColor Green }
            "OEM:COA" { Write-Host "  Key Type  : OEM:COA (Sticker/COA key from manufacturer)" -ForegroundColor Green }
            "OEM*"    { Write-Host "  Key Type  : OEM (Pre-installed by manufacturer)" -ForegroundColor Green }
            "Volume*" { Write-Host "  Key Type  : Volume License (Enterprise/Education)" -ForegroundColor Cyan }
            "KMS*"    { Write-Host "  Key Type  : KMS Channel (possibly cracked)" -ForegroundColor Magenta }
            default   { Write-Host "  Key Type  : $channel" -ForegroundColor Gray }
        }
    }
}
Write-Host ""

# --- KMS Detection ---
Write-Host "[KMS ACTIVATION DETECTION]" -ForegroundColor Yellow

$kmsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
$kmsServer  = (Get-ItemProperty -Path $kmsRegPath -Name "KeyManagementServiceName" -ErrorAction SilentlyContinue).KeyManagementServiceName
$kmsMachine = (Get-ItemProperty -Path $kmsRegPath -Name "KeyManagementServiceMachine" -ErrorAction SilentlyContinue).KeyManagementServiceMachine

$kmsFound = $false
$kmsDisplay = ""

if ($kmsServer) {
    $kmsDisplay = $kmsServer
    $kmsFound = $true
} elseif ($kmsMachine) {
    $kmsDisplay = $kmsMachine
    $kmsFound = $true
}

# Known legitimate corporate/internal KMS indicators
$legitimateKMS = @("localhost", "127.0.0.1", "kms.corp", "kms.local", "kms.internal")
$isLegitKMS = $false

if ($kmsFound) {
    foreach ($legit in $legitimateKMS) {
        if ($kmsDisplay -like "*$legit*") {
            $isLegitKMS = $true
        }
    }

    if ($isLegitKMS) {
        Write-Host "  KMS Server : $kmsDisplay" -ForegroundColor Cyan
        Write-Host "  Assessment : Likely a legitimate corporate/internal KMS server." -ForegroundColor Cyan
    } else {
        Write-Host "  KMS Server : $kmsDisplay" -ForegroundColor Red
        Write-Host "  Assessment : Third-party/public KMS server detected - likely a CRACK." -ForegroundColor Red
    }
} else {
    Write-Host "  No KMS server configured." -ForegroundColor Green
}
Write-Host ""

# --- Crack Tool Artifacts ---
Write-Host "[CRACK TOOL ARTIFACTS]" -ForegroundColor Yellow

$suspiciousItems = @()

# Registry keys
$crackedRegPaths = @(
    "HKLM:\SOFTWARE\KMSAuto",
    "HKLM:\SOFTWARE\KMSpico",
    "HKCU:\SOFTWARE\KMSAuto",
    "HKCU:\SOFTWARE\KMSpico"
)
foreach ($path in $crackedRegPaths) {
    if (Test-Path $path) {
        $suspiciousItems += "Registry key: $path"
    }
}

# Scheduled tasks
$suspiciousTasks = @("KMSAuto", "KMSpico", "AutoKMS", "AutoKMS Net")
foreach ($task in $suspiciousTasks) {
    $t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if ($t) {
        $suspiciousItems += "Scheduled task: $($t.TaskName)"
    }
}

# Services
$suspiciousServices = @("KMSAuto", "KMSpico", "AutoKMS", "KMSELDI", "KMSEmulator")
foreach ($svc in $suspiciousServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        $suspiciousItems += "Service: $($s.Name) [$($s.Status)]"
    }
}

# Common crack folders/files
$suspiciousPaths = @(
    "$env:SystemRoot\AutoKMS",
    "$env:ProgramFiles\KMSpico",
    "$env:ProgramFiles\KMSAuto",
    "$env:ProgramData\KMSpico",
    "$env:ProgramData\KMSAuto",
    "$env:TEMP\KMSAuto",
    "$env:SystemRoot\System32\AutoKMS.exe"
)
foreach ($p in $suspiciousPaths) {
    if (Test-Path $p) {
        $suspiciousItems += "Path found: $p"
    }
}

if ($suspiciousItems.Count -gt 0) {
    foreach ($item in $suspiciousItems) {
        Write-Host "  [!] $item" -ForegroundColor Red
    }
} else {
    Write-Host "  No crack tool files or registry artifacts found." -ForegroundColor Green
}
Write-Host ""

# --- Final Summary ---
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[SUMMARY]" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($slp) {
    $mainProduct  = $slp | Select-Object -First 1
    $statusCode   = [int]$mainProduct.LicenseStatus
    $channel      = $mainProduct.ProductKeyChannel
    $isActivated  = ($statusCode -eq 1)
    $hasThirdPartyKMS = ($kmsFound -and -not $isLegitKMS)

    if ($isActivated -and ($channel -match "Retail|OEM") -and -not $hasThirdPartyKMS -and $suspiciousItems.Count -eq 0) {
        Write-Host ""
        Write-Host "  VERDICT: GENUINELY ACTIVATED" -ForegroundColor Green
        Write-Host "  Windows is properly activated with a legitimate Retail or OEM key." -ForegroundColor Green

    } elseif ($isActivated -and ($channel -match "Retail|OEM") -and $hasThirdPartyKMS) {
        Write-Host ""
        Write-Host "  VERDICT: CRACKED (Online KMS)" -ForegroundColor Red
        Write-Host "  OEM/Retail channel but routed through a public KMS crack server." -ForegroundColor Red
        Write-Host "  Method   : Online KMS (e.g. MAS script / kms.loli.best or similar)" -ForegroundColor Red
        Write-Host "  Risk     : Will deactivate if the KMS server goes offline." -ForegroundColor DarkYellow

    } elseif ($isActivated -and ($channel -match "Volume|KMS") -and $hasThirdPartyKMS) {
        Write-Host ""
        Write-Host "  VERDICT: CRACKED (KMS Volume)" -ForegroundColor Red
        Write-Host "  Activated using a KMS volume key via a third-party crack server." -ForegroundColor Red
        Write-Host "  Method   : KMSPico / KMSAuto / MAS or similar tool." -ForegroundColor Red
        Write-Host "  Risk     : Will deactivate if the KMS server goes offline." -ForegroundColor DarkYellow

    } elseif ($isActivated -and ($channel -match "Volume|KMS") -and $suspiciousItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  VERDICT: CRACKED (Local KMS Tool)" -ForegroundColor Red
        Write-Host "  Activated via local KMS emulator with crack artifacts present." -ForegroundColor Red
        Write-Host "  Method   : KMSPico / KMSAuto (local tool)." -ForegroundColor Red

    } elseif ($isActivated -and ($channel -match "Volume|KMS") -and -not $hasThirdPartyKMS) {
        Write-Host ""
        Write-Host "  VERDICT: KMS ACTIVATED (Possibly Legitimate)" -ForegroundColor DarkYellow
        Write-Host "  Could be a genuine corporate/school volume license." -ForegroundColor DarkYellow
        Write-Host "  Could also be a local KMS emulator with no leftover files." -ForegroundColor DarkYellow

    } elseif (-not $isActivated -and $hasThirdPartyKMS) {
        Write-Host ""
        Write-Host "  VERDICT: CRACK ATTEMPTED BUT FAILED" -ForegroundColor Red
        Write-Host "  A KMS crack server is configured but Windows is not activated." -ForegroundColor Red
        Write-Host "  The crack server may be unreachable or the key may be blocked." -ForegroundColor DarkYellow

    } elseif (-not $isActivated) {
        Write-Host ""
        Write-Host "  VERDICT: NOT ACTIVATED" -ForegroundColor Red
        Write-Host "  Windows is running without any valid activation." -ForegroundColor Red

    } else {
        Write-Host ""
        Write-Host "  VERDICT: UNKNOWN - Manual review recommended." -ForegroundColor DarkYellow
        Write-Host "  Status Code : $statusCode | Channel: $channel | KMS: $kmsFound" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
