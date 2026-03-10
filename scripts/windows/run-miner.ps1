Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/common.ps1"

param(
    [ValidateSet('start', 'stop', 'status', 'logs')]
    [string]$Command = 'status'
)

$ScamNodeBin = Get-EnvOrDefault -Name 'SCAM_NODE_BIN' -Default 'target\release\scam-node.exe'
$PoolAddr = [Environment]::GetEnvironmentVariable('POOL_ADDR')
$CoinbaseAddress = [Environment]::GetEnvironmentVariable('COINBASE_ADDRESS')
$ReadTimeoutSec = Get-EnvOrDefault -Name 'READ_TIMEOUT_SEC' -Default '2'
$MaxNoncePerCycle = Get-EnvOrDefault -Name 'MAX_NONCE_PER_CYCLE' -Default '250000'
$MaxShares = Get-EnvOrDefault -Name 'MAX_SHARES' -Default '0'
$MaxRuntimeSec = Get-EnvOrDefault -Name 'MAX_RUNTIME_SEC' -Default '0'
$ReconnectDelaySec = Get-EnvOrDefault -Name 'RECONNECT_DELAY_SEC' -Default '2'
$MaxReconnectAttempts = Get-EnvOrDefault -Name 'MAX_RECONNECT_ATTEMPTS' -Default '0'

$WorkDir = Get-EnvOrDefault -Name 'WORK_DIR' -Default 'target\run-miner'
$LogFile = Join-Path $WorkDir 'miner.log'
$ErrFile = Join-Path $WorkDir 'miner.err.log'
$PidFile = Join-Path $WorkDir 'miner.pid'

switch ($Command) {
    'start' {
        Ensure-Binary -Path $ScamNodeBin
        if ([string]::IsNullOrWhiteSpace($PoolAddr)) {
            throw 'set POOL_ADDR=<host:port>'
        }
        if ([string]::IsNullOrWhiteSpace($CoinbaseAddress)) {
            throw 'set COINBASE_ADDRESS=<address>'
        }

        $runningPid = Get-RunningPidFromFile -PidFile $PidFile
        if ($null -ne $runningPid) {
            Write-Host "[miner] already running (pid=$runningPid)"
            exit 0
        }

        Ensure-Directory -Path $WorkDir
        $args = @(
            'stratum-mine',
            '--pool', $PoolAddr,
            '--user', $CoinbaseAddress,
            '--read-timeout-sec', $ReadTimeoutSec,
            '--max-nonce-per-cycle', $MaxNoncePerCycle,
            '--max-shares', $MaxShares,
            '--max-runtime-sec', $MaxRuntimeSec,
            '--reconnect-delay-sec', $ReconnectDelaySec,
            '--max-reconnect-attempts', $MaxReconnectAttempts
        )

        $pidValue = Start-BackgroundProcess -Bin $ScamNodeBin -Args $args -StdOut $LogFile -StdErr $ErrFile -PidFile $PidFile -Name 'miner'
        Write-Host '[miner] up'
        Write-Host "[miner] pid: $pidValue"
        Write-Host "[miner] pool: $PoolAddr"
        Write-Host "[miner] user/coinbase address: $CoinbaseAddress"
        Write-Host "[miner] logs: $LogFile / $ErrFile"
    }
    'stop' {
        $stopped = Stop-PidFileProcess -PidFile $PidFile
        if ($stopped) {
            Write-Host '[miner] down'
        }
        else {
            Write-Host '[miner] not running'
        }
    }
    'status' {
        $runningPid = Get-RunningPidFromFile -PidFile $PidFile
        if ($null -ne $runningPid) {
            Write-Host "[miner] running (pid=$runningPid)"
            Write-Host "[miner] logs: $LogFile / $ErrFile"
        }
        else {
            Write-Host '[miner] stopped'
        }
    }
    'logs' {
        Show-LogTail -Path $LogFile -Label 'miner stdout'
        Show-LogTail -Path $ErrFile -Label 'miner stderr'
    }
    default {
        throw 'usage: run-miner.ps1 {start|stop|status|logs}'
    }
}
