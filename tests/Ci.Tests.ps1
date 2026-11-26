BeforeAll {
    Import-Module PSScriptAnalyzer
    $workflow = Get-Content (Join-Path $PSScriptRoot '../.github/workflows/ci.yml') -Raw
    $match = [regex]::Match($workflow, '(?m)^      - name: Run PSScriptAnalyzer\r?\n        shell: pwsh\r?\n        run: \|\r?\n((?:          .*\r?\n?)+)')
    if (-not $match.Success) { throw 'PSScriptAnalyzer workflow step not found.' }
    $analyzerStep = [scriptblock]::Create($match.Groups[1].Value)
}

Describe 'PSScriptAnalyzer CI step' {
    BeforeEach {
        Push-Location (Join-Path $PSScriptRoot '..')
    }
    AfterEach {
        Pop-Location
    }

    It 'analyzes both paths independently' {
        Mock Invoke-ScriptAnalyzer {}
        & $analyzerStep
        Should -Invoke Invoke-ScriptAnalyzer -Times 1 -Exactly -ParameterFilter { $Path -eq './src' -and $Recurse -and $Settings -eq './PSScriptAnalyzerSettings.psd1' }
        Should -Invoke Invoke-ScriptAnalyzer -Times 1 -Exactly -ParameterFilter { $Path -eq './Start-PortAnalyzer.ps1' -and $Recurse -and $Settings -eq './PSScriptAnalyzerSettings.psd1' }
    }

    It 'fails on analyzer errors from <Path>' -TestCases @(
        @{ Path = './src' }
        @{ Path = './Start-PortAnalyzer.ps1' }
    ) {
        param($Path)
        $errorPath = $Path
        Mock Invoke-ScriptAnalyzer {
            if ($Path -eq $errorPath) { [pscustomobject]@{ Severity = 'Error' } }
        }
        { & $analyzerStep } | Should -Throw 'PSScriptAnalyzer reported errors.'
    }

    It 'does not fail on warnings' {
        Mock Invoke-ScriptAnalyzer { [pscustomobject]@{ Severity = 'Warning' } }
        { & $analyzerStep } | Should -Not -Throw
    }
}
