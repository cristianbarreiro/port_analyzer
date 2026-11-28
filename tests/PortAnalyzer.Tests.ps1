BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/PortAnalyzer.psm1') -Force
}

Describe 'Get-BindScope' {
    It 'identifies IPv4 and IPv6 wildcard addresses' {
        Get-BindScope '0.0.0.0' | Should -Be 'All interfaces'
        Get-BindScope '::' | Should -Be 'All interfaces'
        Get-BindScope '0:0:0:0:0:0:0:0' | Should -Be 'All interfaces'
    }

    It 'identifies IPv4 and IPv6 loopback addresses' {
        Get-BindScope '127.0.0.1' | Should -Be 'Loopback only'
        Get-BindScope '127.0.0.2' | Should -Be 'Loopback only'
        Get-BindScope '::1' | Should -Be 'Loopback only'
        Get-BindScope '0:0:0:0:0:0:0:1' | Should -Be 'Loopback only'
    }

    It 'normalizes IPv4-mapped IPv6 addresses before classification' {
        Get-BindScope '::ffff:127.0.0.1' | Should -Be 'Loopback only'
        Get-BindScope '::ffff:192.0.2.10' | Should -Be 'Specific address'
    }

    It 'preserves specific addresses' {
        Get-BindScope '192.168.1.10' | Should -Be 'Specific address'
        Get-BindScope '2001:db8::10' | Should -Be 'Specific address'
    }

    It 'returns Unknown for malformed address input' {
        Get-BindScope 'not-an-ip-address' | Should -Be 'Unknown'
    }
}

Describe 'Get-PortAnalyzerFindings' {
    It 'accepts an empty endpoint collection' {
        @(Get-PortAnalyzerFindings -Endpoints @()).Count | Should -Be 0
    }

    It 'ignores established TCP connections' {
        $endpoint = [pscustomobject]@{
            Protocol = 'TCP'; State = 'Established'; LocalPort = 3389
            LocalAddress = '10.0.0.2'; BindScope = 'Specific address'; ProcessName = 'test'
        }
        @(Get-PortAnalyzerFindings -Endpoints @($endpoint)).Count | Should -Be 0
    }

    It 'flags wildcard Telnet only as a low-confidence review hint' {
        $endpoint = [pscustomobject]@{
            Protocol = 'TCP'; State = 'Listen'; LocalPort = 23
            LocalAddress = '0.0.0.0'; BindScope = 'All interfaces'; ProcessName = 'test'
        }
        $finding = @(Get-PortAnalyzerFindings -Endpoints @($endpoint))[0]
        $finding.Severity | Should -Be 'Review'
        $finding.Confidence | Should -Be 'Low'
        $finding.Protocol | Should -Be 'TCP'
    }

    It 'keeps a loopback listener informational' {
        $endpoint = [pscustomobject]@{
            Protocol = 'TCP'; State = 'Listen'; LocalPort = 3389
            LocalAddress = '127.0.0.1'; BindScope = 'Loopback only'; ProcessName = 'test'
        }
        $finding = @(Get-PortAnalyzerFindings -Endpoints @($endpoint))[0]
        $finding.Severity | Should -Be 'Info'
    }

    It 'does not apply TCP hints to UDP bindings' {
        $endpoint = [pscustomobject]@{
            Protocol = 'UDP'; State = 'BOUND'; LocalPort = 445
            LocalAddress = '0.0.0.0'; BindScope = 'All interfaces'; ProcessName = 'test'
        }
        @(Get-PortAnalyzerFindings -Endpoints @($endpoint)).Count | Should -Be 0
    }
}

Describe 'Get-PortAnalyzerProcessName' {
    InModuleScope PortAnalyzer {
        It 'handles PID 0 without attempting process lookup' {
            Mock Get-Process { throw 'Get-Process should not be called for PID 0.' }
            Get-PortAnalyzerProcessName -ProcessId 0 | Should -Be 'System Idle Process'
            Should -Invoke Get-Process -Times 0 -Exactly
        }

        It 'returns Unknown when a process exits or access is denied' {
            Mock Get-Process { throw 'Access is denied.' }
            Get-PortAnalyzerProcessName -ProcessId 4242 | Should -Be 'Unknown'
        }

        It 'returns the process name when lookup succeeds' {
            Mock Get-Process { [pscustomobject]@{ ProcessName = 'example' } }
            Get-PortAnalyzerProcessName -ProcessId 4242 | Should -Be 'example'
        }
    }
}
