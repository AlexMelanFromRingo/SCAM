Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/common.ps1"

param(
    [ValidateSet('start', 'stop', 'status', 'logs')]
    [string]$Command = 'status'
)

$ScamNodeBin = Get-EnvOrDefault -Name 'SCAM_NODE_BIN' -Default 'target\release\scam-node.exe'
$Network = Get-EnvOrDefault -Name 'NETWORK' -Default 'devnet'
$Config = Get-EnvOrDefault -Name 'CONFIG' -Default "config\$Network.toml"
$NodeDir = Get-EnvOrDefault -Name 'NODE_DIR' -Default 'target\run-node-miner'
$RuntimeDb = Get-EnvOrDefault -Name 'RUNTIME_DB' -Default (Join-Path $NodeDir 'runtime.redb')
$PeersDir = Get-EnvOrDefault -Name 'PEERS_DIR' -Default (Join-Path $NodeDir 'peers')
$UiDir = Get-EnvOrDefault -Name 'UI_DIR' -Default 'web'
$RelayBind = Get-EnvOrDefault -Name 'RELAY_BIND' -Default '0.0.0.0:18446'
$RpcBind = Get-EnvOrDefault -Name 'RPC_BIND' -Default '127.0.0.1:18081'
$StratumBind = Get-EnvOrDefault -Name 'STRATUM_BIND' -Default '127.0.0.1:3347'
$CoinbaseAddress = [Environment]::GetEnvironmentVariable('COINBASE_ADDRESS')
$OutboundConnect = Get-EnvOrDefault -Name 'OUTBOUND_CONNECT' -Default 'true'
$OutboundRedialSec = Get-EnvOrDefault -Name 'OUTBOUND_REDIAL_SEC' -Default '5'
$P2pReadTimeoutSec = Get-EnvOrDefault -Name 'P2P_READ_TIMEOUT_SEC' -Default '5'
$P2pWriteTimeoutSec = Get-EnvOrDefault -Name 'P2P_WRITE_TIMEOUT_SEC' -Default '5'
$AddPeers = [Environment]::GetEnvironmentVariable('ADD_PEERS')
$StratumReadTimeoutSec = Get-EnvOrDefault -Name 'STRATUM_READ_TIMEOUT_SEC' -Default '30'
$MinerReadTimeoutSec = Get-EnvOrDefault -Name 'MINER_READ_TIMEOUT_SEC' -Default '2'
$MinerMaxNoncePerCycle = Get-EnvOrDefault -Name 'MINER_MAX_NONCE_PER_CYCLE' -Default '250000'
$MinerMaxShares = Get-EnvOrDefault -Name 'MINER_MAX_SHARES' -Default '0'
$MinerMaxRuntimeSec = Get-EnvOrDefault -Name 'MINER_MAX_RUNTIME_SEC' -Default '0'

$LogDir = Join-Path $NodeDir 'logs'
$BootstrapLog = Join-Path $LogDir 'bootstrap.log'
$RelayLog = Join-Path $LogDir 'relay.log'
$RelayErr = Join-Path $LogDir 'relay.err.log'
$RpcLog = Join-Path $LogDir 'rpc.log'
$RpcErr = Join-Path $LogDir 'rpc.err.log'
$StratumLog = Join-Path $LogDir 'stratum.log'
$StratumErr = Join-Path $LogDir 'stratum.err.log'
$MinerLog = Join-Path $LogDir 'miner.log'
$MinerErr = Join-Path $LogDir 'miner.err.log'
$RelayPid = Join-Path $NodeDir 'relay.pid'
$RpcPid = Join-Path $NodeDir 'rpc.pid'
$StratumPid = Join-Path $NodeDir 'stratum.pid'
$MinerPid = Join-Path $NodeDir 'miner.pid'
$RelayTelemetry = Join-Path $NodeDir 'relay.telemetry.jsonl'
$StratumTelemetry = Join-Path $NodeDir 'stratum.telemetry.jsonl'

function Seed-PeerBookFromEnv {
    if ([string]::IsNullOrWhiteSpace($AddPeers)) {
        return
    }

    Ensure-Directory -Path $PeersDir
    $peers = $AddPeers -split '[,\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($peers.Count -eq 0) {
        return
    }

    Write-Host '[node-miner] seeding peer book from ADD_PEERS'
    foreach ($peer in $peers) {
        $args = @(
            'add-peer',
            '--network', $Network,
            '--peer', $peer,
            '--peers-dir', $PeersDir
        )
        Invoke-LoggedCommand -Bin $ScamNodeBin -Args $args -LogFile $BootstrapLog
    }
}

switch ($Command) {
    'start' {
        Ensure-Binary -Path $ScamNodeBin
        if ([string]::IsNullOrWhiteSpace($CoinbaseAddress)) {
            throw 'set COINBASE_ADDRESS=<address>'
        }

        Ensure-Directory -Path $NodeDir
        Ensure-Directory -Path $LogDir
        Ensure-Directory -Path $PeersDir

        Seed-PeerBookFromEnv

        $bootstrapArgs = @(
            'node',
            '--network', $Network,
            '--config', $Config,
            '--runtime-db', $RuntimeDb
        )
        Invoke-LoggedCommand -Bin $ScamNodeBin -Args $bootstrapArgs -LogFile $BootstrapLog

        Stop-PidFileProcess -PidFile $MinerPid | Out-Null
        Stop-PidFileProcess -PidFile $StratumPid | Out-Null
        Stop-PidFileProcess -PidFile $RpcPid | Out-Null
        Stop-PidFileProcess -PidFile $RelayPid | Out-Null

        $relayArgs = @(
            'relay-serve',
            '--network', $Network,
            '--config', $Config,
            '--runtime-db', $RuntimeDb,
            '--peers-dir', $PeersDir,
            '--bind', $RelayBind,
            '--read-timeout-sec', $P2pReadTimeoutSec,
            '--write-timeout-sec', $P2pWriteTimeoutSec,
            '--telemetry-out', $RelayTelemetry,
            '--telemetry-every-sec', '5'
        )
        if ($OutboundConnect.ToLowerInvariant() -eq 'true' -or $OutboundConnect -eq '1') {
            $relayArgs += @('--outbound-connect', '--outbound-redial-sec', $OutboundRedialSec)
        }
        $relayPidValue = Start-BackgroundProcess -Bin $ScamNodeBin -Args $relayArgs -StdOut $RelayLog -StdErr $RelayErr -PidFile $RelayPid -Name 'relay'

        $rpcArgs = @(
            'rpc-serve',
            '--network', $Network,
            '--config', $Config,
            '--runtime-db', $RuntimeDb,
            '--bind', $RpcBind,
            '--ui-dir', $UiDir,
            '--relay-telemetry', $RelayTelemetry,
            '--stratum-telemetry', $StratumTelemetry
        )
        $rpcPidValue = Start-BackgroundProcess -Bin $ScamNodeBin -Args $rpcArgs -StdOut $RpcLog -StdErr $RpcErr -PidFile $RpcPid -Name 'rpc'

        $stratumArgs = @(
            'stratum-serve',
            '--network', $Network,
            '--config', $Config,
            '--runtime-db', $RuntimeDb,
            '--bind', $StratumBind,
            '--read-timeout-sec', $StratumReadTimeoutSec,
            '--telemetry-out', $StratumTelemetry,
            '--telemetry-every-sec', '5'
        )
        $stratumPidValue = Start-BackgroundProcess -Bin $ScamNodeBin -Args $stratumArgs -StdOut $StratumLog -StdErr $StratumErr -PidFile $StratumPid -Name 'stratum'

        $minerArgs = @(
            'stratum-mine',
            '--pool', $StratumBind,
            '--user', $CoinbaseAddress,
            '--read-timeout-sec', $MinerReadTimeoutSec,
            '--max-nonce-per-cycle', $MinerMaxNoncePerCycle,
            '--max-shares', $MinerMaxShares,
            '--max-runtime-sec', $MinerMaxRuntimeSec
        )
        $minerPidValue = Start-BackgroundProcess -Bin $ScamNodeBin -Args $minerArgs -StdOut $MinerLog -StdErr $MinerErr -PidFile $MinerPid -Name 'miner'

        Write-Host '[node-miner] up'
        Write-Host "[node-miner] relay pid: $relayPidValue"
        Write-Host "[node-miner] rpc pid: $rpcPidValue"
        Write-Host "[node-miner] stratum pid: $stratumPidValue"
        Write-Host "[node-miner] miner pid: $minerPidValue"
        Write-Host "[node-miner] relay: $RelayBind"
        Write-Host "[node-miner] rpc/ui: http://$RpcBind/"
        Write-Host "[node-miner] stratum: $StratumBind"
        Write-Host "[node-miner] miner user/coinbase address: $CoinbaseAddress"
        if (-not [string]::IsNullOrWhiteSpace($AddPeers)) {
            Write-Host "[node-miner] bootstrap peers: $AddPeers"
        }
    }
    'stop' {
        $minerStopped = Stop-PidFileProcess -PidFile $MinerPid
        $stratumStopped = Stop-PidFileProcess -PidFile $StratumPid
        $rpcStopped = Stop-PidFileProcess -PidFile $RpcPid
        $relayStopped = Stop-PidFileProcess -PidFile $RelayPid
        if ($minerStopped -or $stratumStopped -or $rpcStopped -or $relayStopped) {
            Write-Host '[node-miner] down'
        }
        else {
            Write-Host '[node-miner] not running'
        }
    }
    'status' {
        $relayPidValue = Get-RunningPidFromFile -PidFile $RelayPid
        $rpcPidValue = Get-RunningPidFromFile -PidFile $RpcPid
        $stratumPidValue = Get-RunningPidFromFile -PidFile $StratumPid
        $minerPidValue = Get-RunningPidFromFile -PidFile $MinerPid
        $relayState = if ($null -eq $relayPidValue) { 'stopped' } else { "running (pid=$relayPidValue)" }
        $rpcState = if ($null -eq $rpcPidValue) { 'stopped' } else { "running (pid=$rpcPidValue)" }
        $stratumState = if ($null -eq $stratumPidValue) { 'stopped' } else { "running (pid=$stratumPidValue)" }
        $minerState = if ($null -eq $minerPidValue) { 'stopped' } else { "running (pid=$minerPidValue)" }
        Write-Host "[node-miner] relay=$relayState rpc=$rpcState stratum=$stratumState miner=$minerState"
    }
    'logs' {
        Show-LogTail -Path $RelayLog -Label 'relay stdout' -Lines 80
        Show-LogTail -Path $RelayErr -Label 'relay stderr' -Lines 80
        Show-LogTail -Path $RpcLog -Label 'rpc stdout' -Lines 80
        Show-LogTail -Path $RpcErr -Label 'rpc stderr' -Lines 80
        Show-LogTail -Path $StratumLog -Label 'stratum stdout' -Lines 80
        Show-LogTail -Path $StratumErr -Label 'stratum stderr' -Lines 80
        Show-LogTail -Path $MinerLog -Label 'miner stdout' -Lines 80
        Show-LogTail -Path $MinerErr -Label 'miner stderr' -Lines 80
    }
    default {
        throw 'usage: run-node-miner.ps1 {start|stop|status|logs}'
    }
}
