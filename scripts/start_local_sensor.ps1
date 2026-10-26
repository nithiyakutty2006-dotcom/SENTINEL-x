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
if (-not (Test-Path -LiteralPath $secretPath)) {
    throw 'The local sensor secret is not initialized. Start scripts\start_local_server.ps1 first.'
}

$environmentNames = @(
    'SENTINEL_DATA_DIR', 'SENTINEL_SENSOR_ID', 'SENTINEL_SENSOR_SECRET',
    'SENTINEL_SENSOR_URL'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $env:SENTINEL_DATA_DIR = $dataDir
    $env:SENTINEL_SENSOR_ID = 'windows-laptop-01'
    $env:SENTINEL_SENSOR_URL = 'http://127.0.0.1:8011'
    $secureStoredSecret = ConvertTo-SecureString (Get-Content -LiteralPath $secretPath -Raw)
    $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureStoredSecret)
    try {
        $env:SENTINEL_SENSOR_SECRET = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
        $secureStoredSecret.Dispose()
    }

    & curl.exe --noproxy '*' --max-time 5 --silent --show-error --fail `
        --output NUL 'http://127.0.0.1:8011/api/sensors/health'
    if ($LASTEXITCODE -ne 0) {
        throw 'The local backend is not reachable at http://127.0.0.1:8011. Start scripts\start_local_server.ps1 first.'
    }

    Push-Location $repoRoot
    try {
        & $pythonCommand.Source -m sensor.windows_sensor --check
        if ($LASTEXITCODE -ne 0) {
            throw "Sensor configuration check failed with code $LASTEXITCODE. The sensor was not started."
        }

        $availableInterfaces = @(
            Get-NetAdapter -IncludeHidden |
                Where-Object { $_.Status -eq 'Up' } |
                Select-Object -ExpandProperty Name
        )
        if ($availableInterfaces.Count -eq 0) {
            throw 'No active Windows network interfaces are available.'
        }

        Write-Output 'Select the exact active interface to monitor:'
        foreach ($availableInterface in $availableInterfaces) {
            Write-Output "  $availableInterface"
        }
        $selectedInterface = Read-Host 'Interface name'
        if ($availableInterfaces -notcontains $selectedInterface) {
            throw 'Select an exact interface name from the list above. The sensor was not started.'
        }

        & $pythonCommand.Source -m sensor.windows_sensor --run --interface $selectedInterface
        if ($LASTEXITCODE -ne 0) {
            throw "The sensor exited with code $LASTEXITCODE. Review its error above."
        }
    } finally {
        Pop-Location
    }
} finally {
    foreach ($name in $environmentNames) {
        if ($null -eq $previousEnvironment[$name]) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            Set-Item "Env:$name" $previousEnvironment[$name]
        }
    }
}
