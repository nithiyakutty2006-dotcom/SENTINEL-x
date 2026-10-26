$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue

if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA is not set for this Windows account.'
}
if (-not $pythonCommand) {
    throw 'python.exe was not found on PATH. Install Python or add it to PATH.'
}

$dataDir = Join-Path $env:LOCALAPPDATA 'SentinelX'
$secretPath = Join-Path $dataDir 'sensor-secret.dpapi'
$listeners = @(Get-NetTCPConnection -State Listen -LocalPort 8011 -ErrorAction SilentlyContinue)
if ($listeners.Count -gt 0) {
    $owners = foreach ($listener in $listeners) {
        $owner = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)" `
            -ErrorAction SilentlyContinue
        if ($owner) {
            '{0} (PID {1})' -f $owner.Name, $owner.ProcessId
        } else {
            'PID {0}' -f $listener.OwningProcess
        }
    }
    throw "Port 8011 is busy; owned by $($owners -join ', '). Stop it in its own terminal if appropriate."
}

$environmentNames = @(
    'SENTINEL_DATA_DIR', 'SENTINEL_ADMIN_USERNAME', 'SENTINEL_ADMIN_PASSWORD',
    'SENTINEL_SENSOR_ID', 'SENTINEL_SENSOR_SECRET', 'SENTINEL_SENSOR_URL'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$locationPushed = $false

try {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    if (-not (Test-Path -LiteralPath $secretPath)) {
        $secretBytes = New-Object byte[] 48
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $rng.GetBytes($secretBytes)
            $sensorSecret = [Convert]::ToBase64String($secretBytes).
                TrimEnd('=').
                Replace('+', '-').
                Replace('/', '_')
            $protectedSecret = ConvertFrom-SecureString (
                ConvertTo-SecureString $sensorSecret -AsPlainText -Force
            )
            Set-Content -LiteralPath $secretPath -Value $protectedSecret -NoNewline
        } finally {
            [Array]::Clear($secretBytes, 0, $secretBytes.Length)
            $rng.Dispose()
            Remove-Variable sensorSecret, protectedSecret -ErrorAction SilentlyContinue
        }
    }

    $secureStoredSecret = ConvertTo-SecureString (
        Get-Content -LiteralPath $secretPath -Raw
    )
    $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureStoredSecret)
    try {
        $env:SENTINEL_SENSOR_SECRET = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
        $secureStoredSecret.Dispose()
    }

    $adminSecure = Read-Host 'Enter the local admin password (used only if the database has no users)' -AsSecureString
    $adminPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminSecure)
    try {
        $env:SENTINEL_ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($adminPointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($adminPointer)
        $adminSecure.Dispose()
    }

    $env:SENTINEL_DATA_DIR = $dataDir
    $env:SENTINEL_ADMIN_USERNAME = 'admin'
    $env:SENTINEL_SENSOR_ID = 'windows-laptop-01'
    $env:SENTINEL_SENSOR_URL = 'http://127.0.0.1:8011'

    Push-Location $repoRoot
    $locationPushed = $true
    Write-Output 'Server running at http://127.0.0.1:8011/ - keep this window open'
    & $pythonCommand.Source -m uvicorn main:app --host 127.0.0.1 --port 8011
    if ($LASTEXITCODE -ne 0) {
        throw "Uvicorn exited with code $LASTEXITCODE. Review the startup error above."
    }
} finally {
    if ($locationPushed) {
        Pop-Location
    }
    foreach ($name in $environmentNames) {
        if ($null -eq $previousEnvironment[$name]) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            Set-Item "Env:$name" $previousEnvironment[$name]
        }
    }
}
