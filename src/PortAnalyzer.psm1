Set-StrictMode -Version Latest

function Get-BindScope {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Address)
    if ($Address -in @('0.0.0.0', '::', '0:0:0:0:0:0:0:0')) { return 'All interfaces' }
    if ($Address -in @('127.0.0.1', '::1')) { return 'Loopback only' }
    return 'Specific address'
}

function Get-PortAnalyzerSnapshot {
    [CmdletBinding()]
    param()
    $errors = [System.Collections.Generic.List[string]]::new()
    $tcp = @()
    $udp = @()
    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Protocol='TCP'; LocalAddress=[string]$_.LocalAddress; LocalPort=[int]$_.LocalPort; RemoteAddress=[string]$_.RemoteAddress; RemotePort=[int]$_.RemotePort; State=[string]$_.State; OwningProcess=[int]$_.OwningProcess }
        })
    } catch { $errors.Add("TCP collection failed: $($_.Exception.Message)") }
    try {
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Protocol='UDP'; LocalAddress=[string]$_.LocalAddress; LocalPort=[int]$_.LocalPort; RemoteAddress=$null; RemotePort=$null; State='BOUND'; OwningProcess=[int]$_.OwningProcess }
        })
    } catch { $errors.Add("UDP collection failed: $($_.Exception.Message)") }
    $all = @($tcp) + @($udp)
    $cache = @{}
    foreach ($endpoint in $all) {
        $pidValue = $endpoint.OwningProcess
        if (-not $cache.ContainsKey($pidValue)) {
            try { $cache[$pidValue] = (Get-Process -Id $pidValue -ErrorAction Stop).ProcessName }
            catch { $cache[$pidValue] = 'Unknown' }
        }
        $endpoint | Add-Member ProcessName $cache[$pidValue] -Force
        $endpoint | Add-Member BindScope (Get-BindScope -Address $endpoint.LocalAddress) -Force
    }
    [pscustomobject]@{ CollectedAt=Get-Date; Tcp=@($tcp); Udp=@($udp); Endpoints=@($all); Errors=@($errors) }
}

function Get-PortAnalyzerFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Endpoints)
    $hints = @{ 21='FTP'; 23='Telnet'; 135='RPC Endpoint Mapper'; 139='NetBIOS'; 445='SMB'; 3389='Remote Desktop'; 5985='WinRM HTTP' }
    foreach ($endpoint in $Endpoints) {
        if ($endpoint.Protocol -eq 'TCP' -and $endpoint.State -eq 'Listen' -and $hints.ContainsKey([int]$endpoint.LocalPort)) {
            $service = $hints[[int]$endpoint.LocalPort]
            [pscustomobject]@{ RuleId='PA-LOCAL-SENSITIVE-LISTENER'; Severity=$(if ($endpoint.BindScope -eq 'All interfaces') {'Review'} else {'Info'}); Protocol='TCP'; Port=[int]$endpoint.LocalPort; ServiceHint=$service; ProcessName=[string]$endpoint.ProcessName; BindScope=[string]$endpoint.BindScope; Title="Review $service listener"; Evidence="$($endpoint.LocalAddress):$($endpoint.LocalPort) is in TCP Listen state"; Rationale='Port number does not identify the actual service version or prove a vulnerability.'; Recommendation='Confirm owning service, business need, patch level, authentication, and applicable firewall policy.'; Confidence='Low' }
        }
    }
}

function Start-PortAnalyzer {
    [CmdletBinding()]
    param([ValidateRange(1,60)][int]$RefreshSeconds=2, [switch]$Once, [switch]$Json)
    do {
        $snapshot = Get-PortAnalyzerSnapshot
        $findings = @(Get-PortAnalyzerFindings -Endpoints $snapshot.Endpoints)
        if ($Json) { [pscustomobject]@{ Snapshot=$snapshot; Findings=$findings } | ConvertTo-Json -Depth 6; return }
        Clear-Host
        Write-Host 'PORT ANALYZER' -ForegroundColor Cyan
        Write-Host ('Collected: {0:yyyy-MM-dd HH:mm:ss} | Refresh: {1}s | Ctrl+C to exit' -f $snapshot.CollectedAt,$RefreshSeconds) -ForegroundColor DarkGray
        Write-Host 'Read-only local inventory. LISTEN does not mean internet-reachable or vulnerable.' -ForegroundColor Yellow
        $listeners = @($snapshot.Tcp | Where-Object State -eq 'Listen' | Sort-Object LocalPort,LocalAddress)
        $connections = @($snapshot.Tcp | Where-Object State -ne 'Listen' | Sort-Object State,LocalPort)
        Write-Host ("`nTCP LISTENERS ({0})" -f $listeners.Count) -ForegroundColor Green
        if ($listeners.Count) { $listeners | Select-Object LocalPort,LocalAddress,BindScope,ProcessName,State | Format-Table -AutoSize | Out-Host } else { Write-Host 'None found.' }
        Write-Host ("`nTCP CONNECTIONS ({0})" -f $connections.Count) -ForegroundColor Cyan
        if ($connections.Count) { $connections | Select-Object -First 15 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessName | Format-Table -AutoSize | Out-Host } else { Write-Host 'None found.' }
        Write-Host ("`nUDP ENDPOINTS ({0})" -f $snapshot.Udp.Count) -ForegroundColor Cyan
        if ($snapshot.Udp.Count) { $snapshot.Udp | Sort-Object LocalPort | Select-Object -First 15 LocalPort,LocalAddress,BindScope,ProcessName | Format-Table -AutoSize | Out-Host } else { Write-Host 'None found.' }
        Write-Host ("`nREVIEW HINTS ({0})" -f $findings.Count) -ForegroundColor Yellow
        if ($findings.Count) { $findings | Select-Object Severity,Port,ServiceHint,BindScope,ProcessName,Recommendation | Format-Table -Wrap -AutoSize | Out-Host } else { Write-Host 'No heuristic matched. This is not a clean bill of health.' }
        if ($snapshot.Errors.Count) { Write-Host "`nCOLLECTION WARNINGS" -ForegroundColor Red; $snapshot.Errors | ForEach-Object { Write-Host " - $_" -ForegroundColor Red } }
        if (-not $Once) { Start-Sleep -Seconds $RefreshSeconds }
    } while (-not $Once)
}

Export-ModuleMember -Function Start-PortAnalyzer,Get-PortAnalyzerSnapshot,Get-PortAnalyzerFindings,Get-BindScope
