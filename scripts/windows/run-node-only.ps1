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
$NodeDir = Get-EnvOrDefault -Name 'NODE_DIR' -Default 'target\run-node-only'
$RuntimeDb = Get-EnvOrDefault -Name 'RUNTIME_DB' -Default (Join-Path $NodeDir 'runtime.redb')
$PeersDir = Get-EnvOrDefault -Name 'PEERS_DIR' -Default (Join-Path $NodeDir 'peers')
$UiDir = Get-EnvOrDefault -Name 'UI_DIR' -Default 'web'
$RelayBind = Get-EnvOrDefault -Name 'RELAY_BIND' -Default '0.0.0.0:18444'
$RpcBind = Get-EnvOrDefault -Name 'RPC_BIND' -Default '127.0.0.1:18080'
$OutboundConnect = Get-EnvOrDefault -Name 'OUTBOUND_CONNECT' -Default 'true'
$OutboundRedialSec = Get-EnvOrDefault -Name 'OUTBOUND_REDIAL_SEC' -Default '5'
$P2pReadTimeoutSec = Get-EnvOrDefault -Name 'P2P_READ_TIMEOUT_SEC' -Default '5'
$P2pWriteTimeoutSec = Get-EnvOrDefault -Name 'P2P_WRITE_TIMEOUT_SEC' -Default '5'
$AddPeers = [Environment]::GetEnvironmentVariable('ADD_PEERS')

$LogDir = Join-Path $NodeDir 'logs'
$BootstrapLog = Join-Path $LogDir 'bootstrap.log'
$RelayLog = Join-Path $LogDir 'relay.log'
$RelayErr = Join-Path $LogDir 'relay.err.log'
$RpcLog = Join-Path $LogDir 'rpc.log'
$RpcErr = Join-Path $LogDir 'rpc.err.log'
$RelayPid = Join-Path $NodeDir 'relay.pid'
$RpcPid = Join-Path $NodeDir 'rpc.pid'
$RelayTelemetry = Join-Path $NodeDir 'relay.telemetry.jsonl'

function Seed-PeerBookFromEnv {
    if ([string]::IsNullOrWhiteSpace($AddPeers)) {
        return
    }

    Ensure-Directory -Path $PeersDir
    $peers = $AddPeers -split '[,\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($peers.Count -eq 0) {
        return
    }

    Write-Host '[node-only] seeding peer book from ADD_PEERS'
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

        Stop-PidFileProcess -PidFile $RelayPid | Out-Null
        Stop-PidFileProcess -PidFile $RpcPid | Out-Null

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
            '--relay-telemetry', $RelayTelemetry
        )
        $rpcPidValue = Start-BackgroundProcess -Bin $ScamNodeBin -Args $rpcArgs -StdOut $RpcLog -StdErr $RpcErr -PidFile $RpcPid -Name 'rpc'

        Write-Host '[node-only] up'
        Write-Host "[node-only] relay pid: $relayPidValue"
        Write-Host "[node-only] rpc pid: $rpcPidValue"
        Write-Host "[node-only] relay: $RelayBind"
        Write-Host "[node-only] rpc/ui: http://$RpcBind/"
        Write-Host "[node-only] runtime db: $RuntimeDb"
        if (-not [string]::IsNullOrWhiteSpace($AddPeers)) {
            Write-Host "[node-only] bootstrap peers: $AddPeers"
        }
    }
    'stop' {
        $rpcStopped = Stop-PidFileProcess -PidFile $RpcPid
        $relayStopped = Stop-PidFileProcess -PidFile $RelayPid
        if ($rpcStopped -or $relayStopped) {
            Write-Host '[node-only] down'
        }
        else {
            Write-Host '[node-only] not running'
        }
    }
    'status' {
        $relayPidValue = Get-RunningPidFromFile -PidFile $RelayPid
        $rpcPidValue = Get-RunningPidFromFile -PidFile $RpcPid
        $relayState = if ($null -eq $relayPidValue) { 'stopped' } else { "running (pid=$relayPidValue)" }
        $rpcState = if ($null -eq $rpcPidValue) { 'stopped' } else { "running (pid=$rpcPidValue)" }
        Write-Host "[node-only] relay=$relayState rpc=$rpcState"
        Write-Host "[node-only] relay bind: $RelayBind"
        Write-Host "[node-only] rpc bind: $RpcBind"
    }
    'logs' {
        Show-LogTail -Path $RelayLog -Label 'relay stdout'
        Show-LogTail -Path $RelayErr -Label 'relay stderr'
        Show-LogTail -Path $RpcLog -Label 'rpc stdout'
        Show-LogTail -Path $RpcErr -Label 'rpc stderr'
    }
    default {
        throw 'usage: run-node-only.ps1 {start|stop|status|logs}'
    }
}
