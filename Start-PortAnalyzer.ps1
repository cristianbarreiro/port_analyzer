#requires -Version 7.4
[CmdletBinding()]
param([ValidateRange(1,60)][int]$RefreshSeconds=2,[switch]$Once,[switch]$Json)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/PortAnalyzer.psm1') -Force
Start-PortAnalyzer -RefreshSeconds $RefreshSeconds -Once:$Once -Json:$Json
