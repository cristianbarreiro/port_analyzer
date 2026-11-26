BeforeAll { Import-Module (Join-Path $PSScriptRoot '../src/PortAnalyzer.psm1') -Force }
Describe 'Get-BindScope' {
    It 'identifies wildcard binds' { (Get-BindScope '0.0.0.0') | Should -Be 'All interfaces'; (Get-BindScope '::') | Should -Be 'All interfaces' }
    It 'identifies loopback' { (Get-BindScope '127.0.0.1') | Should -Be 'Loopback only'; (Get-BindScope '::1') | Should -Be 'Loopback only' }
    It 'preserves specific addresses' { (Get-BindScope '192.168.1.10') | Should -Be 'Specific address' }
}
Describe 'Get-PortAnalyzerFindings' {
    It 'ignores established TCP connections' { $e=[pscustomobject]@{Protocol='TCP';State='Established';LocalPort=3389;LocalAddress='10.0.0.2';BindScope='Specific address';ProcessName='test'}; @(Get-PortAnalyzerFindings @($e)).Count | Should -Be 0 }
    It 'flags wildcard Telnet only as a low-confidence review hint' { $e=[pscustomobject]@{Protocol='TCP';State='Listen';LocalPort=23;LocalAddress='0.0.0.0';BindScope='All interfaces';ProcessName='test'}; $f=@(Get-PortAnalyzerFindings @($e))[0]; $f.Severity | Should -Be 'Review'; $f.Confidence | Should -Be 'Low' }
    It 'does not apply TCP hints to UDP' { $e=[pscustomobject]@{Protocol='UDP';State='BOUND';LocalPort=445;LocalAddress='0.0.0.0';BindScope='All interfaces';ProcessName='test'}; @(Get-PortAnalyzerFindings @($e)).Count | Should -Be 0 }
}
