Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EnvOrDefault {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Default
    )
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }
    return $value
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Ensure-Binary {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "SCAM_NODE_BIN does not exist: $Path"
    }
}

function Get-RunningPidFromFile {
    param([Parameter(Mandatory = $true)][string]$PidFile)

    if (-not (Test-Path -LiteralPath $PidFile)) {
        return $null
    }

    $raw = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    $pidValue = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$pidValue)) {
        return $null
    }

    $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($null -eq $proc) {
        return $null
    }

    return $pidValue
}

function Stop-PidFileProcess {
    param([Parameter(Mandatory = $true)][string]$PidFile)

    $pidValue = Get-RunningPidFromFile -PidFile $PidFile
    if ($null -eq $pidValue) {
        Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue
        return $false
    }

    try {
        Stop-Process -Id $pidValue -ErrorAction Stop
    }
    catch {
        Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
    }

    Start-Sleep -Milliseconds 300
    Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue
    return $true
}

function Start-BackgroundProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Bin,
        [Parameter(Mandatory = $true)][string[]]$Args,
        [Parameter(Mandatory = $true)][string]$StdOut,
        [Parameter(Mandatory = $true)][string]$StdErr,
        [Parameter(Mandatory = $true)][string]$PidFile,
        [Parameter(Mandatory = $true)][string]$Name
    )

    Ensure-Directory -Path (Split-Path -Parent $StdOut)
    Ensure-Directory -Path (Split-Path -Parent $StdErr)
    Ensure-Directory -Path (Split-Path -Parent $PidFile)

    $proc = Start-Process -FilePath $Bin -ArgumentList $Args -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr -PassThru -WindowStyle Hidden
    Set-Content -LiteralPath $PidFile -Value $proc.Id

    Start-Sleep -Milliseconds 300
    $runningPid = Get-RunningPidFromFile -PidFile $PidFile
    if ($null -eq $runningPid) {
        throw "$Name failed to start. Check logs: $StdOut / $StdErr"
    }

    return $runningPid
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Bin,
        [Parameter(Mandatory = $true)][string[]]$Args,
        [Parameter(Mandatory = $true)][string]$LogFile
    )

    Ensure-Directory -Path (Split-Path -Parent $LogFile)

    & $Bin @Args 2>&1 | Out-File -FilePath $LogFile -Append
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE: $Bin $($Args -join ' ')"
    }
}

function Show-LogTail {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$Lines = 120
    )

    Write-Host "--- $Label ---"
    if (Test-Path -LiteralPath $Path) {
        Get-Content -LiteralPath $Path -Tail $Lines
    }
    else {
        Write-Host "(missing $Path)"
    }
}
