#Requires -Version 5.1
<#
.SYNOPSIS
    GlassWorm VS Code Extension Scanner
    
.DESCRIPTION
    Detects and removes malicious VS Code extensions infected by the GlassWorm worm.
    Based on Koi Security research (October 2025).
    
.PARAMETER Remove
    Automatically remove infected extensions
    
.PARAMETER SystemCheck
    Perform system-level compromise checks
    
.PARAMETER ReportPath
    Path to save JSON report
    
.EXAMPLE
    .\GlassWorm-Scanner.ps1
    
.EXAMPLE
    .\GlassWorm-Scanner.ps1 -Remove -SystemCheck
    
.LINK
    https://www.koi.ai/blog/glassworm-first-self-propagating-worm
#>

[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$SystemCheck,
    [string]$ReportPath = "glassworm_scan_report.json"
)

# Known infected extensions
$InfectedExtensions = @{
    "codejoy.codejoy-vscode-extension" = @("1.8.3", "1.8.4")
    "l-igh-t.vscode-theme-seti-folder" = @("1.2.3")
    "kleinesfilmroellchen.serenity-dsl-syntaxhighlight" = @("0.3.2")
    "JScearcy.rust-doc-viewer" = @("4.2.1")
    "SIRILMP.dark-theme-sm" = @("3.11.4")
    "CodeInKlingon.git-worktree-menu" = @("1.0.9", "1.0.91")
    "ginfuru.better-nunjucks" = @("0.3.2")
    "ellacrity.recoil" = @("0.7.4")
    "grrrck.positron-plus-1-e" = @("0.0.71")
    "jeronimoekerdt.color-picker-universal" = @("2.8.91")
    "srcery-colors.srcery-colors" = @("0.3.9")
    "sissel.shopify-liquid" = @("4.0.1")
    "TretinV3.forts-api-extention" = @("0.3.1")
    "cline-ai-main.cline-ai-agent" = @("3.1.3")
}

# Known malicious indicators
$C2Servers = @(
    "217.69.3.218",
    "199.247.10.166",
    "140.82.52.31"
)

$SolanaWallet = "28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2"

# Unicode variation selectors (invisible characters)
$VariationSelectors = @(
    [char]0xFE00, [char]0xFE01, [char]0xFE02, [char]0xFE03,
    [char]0xFE04, [char]0xFE05, [char]0xFE06, [char]0xFE07,
    [char]0xFE08, [char]0xFE09, [char]0xFE0A, [char]0xFE0B,
    [char]0xFE0C, [char]0xFE0D, [char]0xFE0E, [char]0xFE0F
)

$Findings = @()
$RemovedExtensions = @()

function Get-VSCodeExtensionsPath {
    $paths = @()
    
    $userProfile = $env:USERPROFILE
    $paths += Join-Path $userProfile ".vscode\extensions"
    $paths += Join-Path $userProfile ".vscode-insiders\extensions"
    
    return $paths | Where-Object { Test-Path $_ }
}

function Get-InstalledExtensions {
    $extensions = @()
    
    foreach ($extDir in Get-VSCodeExtensionsPath) {
        $folders = Get-ChildItem -Path $extDir -Directory
        
        foreach ($folder in $folders) {
            # Parse extension ID and version from folder name
            $dirName = $folder.Name
            
            if ($dirName -match '^(.+)-(\d+\.\d+\.\d+.*)$') {
                $extId = $Matches[1]
                $version = $Matches[2]
            } else {
                $extId = $dirName
                $version = "unknown"
            }
            
            # Try to get accurate info from package.json
            $packageJson = Join-Path $folder.FullName "package.json"
            
            if (Test-Path $packageJson) {
                try {
                    $package = Get-Content $packageJson -Raw | ConvertFrom-Json
                    $publisher = $package.publisher
                    $name = $package.name
                    $version = $package.version
                    
                    if ($publisher -and $name) {
                        $extId = "$publisher.$name"
                    }
                } catch {
                    # Continue with parsed values
                }
            }
            
            $extensions += [PSCustomObject]@{
                Id = $extId
                Version = $version
                Path = $folder.FullName
            }
        }
    }
    
    return $extensions
}

function Test-InvisibleUnicode {
    param([string]$FilePath)
    
    $foundSelectors = @()
    
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
        
        foreach ($selector in $VariationSelectors) {
            if ($content -match [regex]::Escape($selector)) {
                $foundSelectors += "U+{0:X4}" -f [int][char]$selector
            }
        }
    } catch {
        # Ignore errors
    }
    
    return $foundSelectors
}

function Test-MaliciousPatterns {
    param([string]$ExtensionPath)
    
    $indicators = @{
        C2Servers = @()
        SolanaReferences = $false
        InvisibleUnicode = @()
        SuspiciousFiles = @()
        GoogleCalendarC2 = $false
        CredentialTheft = $false
    }
    
    # Search through JS files
    $jsFiles = Get-ChildItem -Path $ExtensionPath -Filter "*.js" -Recurse -ErrorAction SilentlyContinue
    
    foreach ($file in $jsFiles) {
        try {
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            
            # Check for C2 servers
            foreach ($c2 in $C2Servers) {
                if ($content -match [regex]::Escape($c2)) {
                    $indicators.C2Servers += $c2
                }
            }
            
            # Check for Solana wallet
            if ($content -match [regex]::Escape($SolanaWallet)) {
                $indicators.SolanaReferences = $true
            }
            
            # Check for invisible Unicode
            $unicodeFound = Test-InvisibleUnicode -FilePath $file.FullName
            if ($unicodeFound) {
                $indicators.InvisibleUnicode += $unicodeFound
                $indicators.SuspiciousFiles += $file.FullName
            }
            
            # Check for Google Calendar C2
            if ($content -match 'calendar\.google\.com|googleapis\.com/calendar') {
                $indicators.GoogleCalendarC2 = $true
            }
            
            # Check for credential theft
            $credentialKeywords = @('npm', 'token', 'github', 'git credential', '.npmrc', 'vsix')
            foreach ($keyword in $credentialKeywords) {
                if ($content -match [regex]::Escape($keyword)) {
                    $indicators.CredentialTheft = $true
                    break
                }
            }
        } catch {
            # Ignore errors
        }
    }
    
    return $indicators
}

function Remove-InfectedExtension {
    param(
        [string]$ExtensionPath,
        [string]$ExtensionId
    )
    
    try {
        Write-Host "   🗑️  Removing extension: $ExtensionId" -ForegroundColor Yellow
        Remove-Item -Path $ExtensionPath -Recurse -Force
        $script:RemovedExtensions += $ExtensionId
        Write-Host "   ✅ Successfully removed!" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Failed to remove: $_" -ForegroundColor Red
    }
    Write-Host ""
}

function Start-ExtensionScan {
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host "GlassWorm VS Code Extension Scanner" -ForegroundColor Cyan
    Write-Host "Detecting malicious extensions from October 2025 supply chain attack" -ForegroundColor Cyan
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host ""
    
    $extensions = Get-InstalledExtensions
    
    if ($extensions.Count -eq 0) {
        Write-Host "❌ No VS Code extensions found!" -ForegroundColor Red
        return
    }
    
    Write-Host "📦 Found $($extensions.Count) installed extensions" -ForegroundColor White
    Write-Host ""
    
    $infectedCount = 0
    $suspiciousCount = 0
    
    foreach ($ext in $extensions) {
        $isKnownInfected = $false
        
        # Check if it's a known infected extension
        if ($InfectedExtensions.ContainsKey($ext.Id)) {
            $infectedVersions = $InfectedExtensions[$ext.Id]
            
            if ($infectedVersions -contains $ext.Version -or $ext.Version -eq "unknown") {
                $isKnownInfected = $true
                $infectedCount++
                
                Write-Host "🚨 CRITICAL: Known infected extension found!" -ForegroundColor Red
                Write-Host "   Extension: $($ext.Id)" -ForegroundColor White
                Write-Host "   Version: $($ext.Version)" -ForegroundColor White
                Write-Host "   Location: $($ext.Path)" -ForegroundColor White
                Write-Host ""
                
                $script:Findings += [PSCustomObject]@{
                    Id = $ext.Id
                    Version = $ext.Version
                    Path = $ext.Path
                    Status = "KNOWN_INFECTED"
                    RiskScore = 100
                }
                
                if ($Remove) {
                    Remove-InfectedExtension -ExtensionPath $ext.Path -ExtensionId $ext.Id
                }
            }
        }
        
        # Deep scan for malicious patterns
        if (-not $isKnownInfected) {
            $indicators = Test-MaliciousPatterns -ExtensionPath $ext.Path
            
            $riskScore = 0
            $reasons = @()
            
            if ($indicators.C2Servers.Count -gt 0) {
                $riskScore += 50
                $reasons += "C2 servers found: $($indicators.C2Servers -join ', ')"
            }
            
            if ($indicators.SolanaReferences) {
                $riskScore += 30
                $reasons += "Solana blockchain references"
            }
            
            if ($indicators.InvisibleUnicode.Count -gt 0) {
                $riskScore += 40
                $reasons += "Invisible Unicode characters: $($indicators.InvisibleUnicode | Select-Object -Unique)"
            }
            
            if ($indicators.GoogleCalendarC2) {
                $riskScore += 20
                $reasons += "Google Calendar API usage (potential C2)"
            }
            
            if ($indicators.CredentialTheft) {
                $riskScore += 15
                $reasons += "Credential access patterns"
            }
            
            if ($riskScore -ge 50) {
                $suspiciousCount++
                
                if ($riskScore -ge 80) {
                    Write-Host "🚨 HIGH RISK" -ForegroundColor Red
                } else {
                    Write-Host "⚠️  SUSPICIOUS" -ForegroundColor Yellow
                }
                
                Write-Host "   Extension: $($ext.Id)" -ForegroundColor White
                Write-Host "   Version: $($ext.Version)" -ForegroundColor White
                Write-Host "   Risk Score: $riskScore" -ForegroundColor White
                Write-Host "   Location: $($ext.Path)" -ForegroundColor White
                Write-Host "   Indicators:" -ForegroundColor White
                
                foreach ($reason in $reasons) {
                    Write-Host "      • $reason" -ForegroundColor Gray
                }
                Write-Host ""
                
                $script:Findings += [PSCustomObject]@{
                    Id = $ext.Id
                    Version = $ext.Version
                    Path = $ext.Path
                    Status = "SUSPICIOUS"
                    RiskScore = $riskScore
                    Indicators = $reasons
                }
                
                if ($Remove -and $riskScore -ge 80) {
                    Remove-InfectedExtension -ExtensionPath $ext.Path -ExtensionId $ext.Id
                }
            }
        }
    }
    
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host "📊 SCAN SUMMARY" -ForegroundColor Cyan
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host "Total Extensions Scanned: $($extensions.Count)" -ForegroundColor White
    Write-Host "🚨 Known Infected: $infectedCount" -ForegroundColor Red
    Write-Host "⚠️  Suspicious: $suspiciousCount" -ForegroundColor Yellow
    Write-Host "✅ Clean: $($extensions.Count - $infectedCount - $suspiciousCount)" -ForegroundColor Green
    
    if ($RemovedExtensions.Count -gt 0) {
        Write-Host ""
        Write-Host "🗑️  Removed Extensions: $($RemovedExtensions.Count)" -ForegroundColor Yellow
        foreach ($ext in $RemovedExtensions) {
            Write-Host "   • $ext" -ForegroundColor Gray
        }
    }
}

function Test-SystemCompromise {
    Write-Host ""
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host "🔍 CHECKING FOR SYSTEM COMPROMISE" -ForegroundColor Cyan
    Write-Host ("="*70) -ForegroundColor Cyan
    
    # Check for suspicious network connections
    Write-Host ""
    Write-Host "[1] Checking for suspicious network connections..." -ForegroundColor White
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $suspiciousFound = $false
        
        foreach ($c2 in $C2Servers) {
            $found = $connections | Where-Object { $_.RemoteAddress -eq $c2 }
            if ($found) {
                Write-Host "   🚨 SUSPICIOUS: Connection to known C2 server: $c2" -ForegroundColor Red
                $suspiciousFound = $true
            }
        }
        
        if (-not $suspiciousFound) {
            Write-Host "   ✅ No suspicious network connections detected" -ForegroundColor Green
        }
    } catch {
        Write-Host "   ℹ️  Unable to check network connections" -ForegroundColor Yellow
    }
    
    # Check for credential files
    Write-Host ""
    Write-Host "[2] Checking for potential credential theft..." -ForegroundColor White
    
    $sensitiveFiles = @(
        "$env:USERPROFILE\.npmrc",
        "$env:USERPROFILE\.gitconfig",
        "$env:USERPROFILE\.git-credentials"
    )
    
    foreach ($file in $sensitiveFiles) {
        if (Test-Path $file) {
            Write-Host "   ⚠️  Found: $file" -ForegroundColor Yellow
            Write-Host "      Recommendation: Review and rotate credentials" -ForegroundColor Gray
        }
    }
    
    # Check for suspicious processes
    Write-Host ""
    Write-Host "[3] Checking for suspicious processes..." -ForegroundColor White
    
    $suspiciousProcesses = @("node", "python", "powershell") | ForEach-Object {
        Get-Process -Name $_ -ErrorAction SilentlyContinue
    }
    
    if ($suspiciousProcesses) {
        Write-Host "   ℹ️  Found $($suspiciousProcesses.Count) potentially suspicious processes" -ForegroundColor Yellow
        Write-Host "      Review running processes manually for anomalies" -ForegroundColor Gray
    }
}

function Export-ScanReport {
    if ($Findings.Count -gt 0) {
        $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Host ""
        Write-Host "💾 Detailed report saved to: $ReportPath" -ForegroundColor Green
    }
}

function Show-Recommendations {
    Write-Host ""
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host "🛡️  SECURITY RECOMMENDATIONS" -ForegroundColor Cyan
    Write-Host ("="*70) -ForegroundColor Cyan
    
    Write-Host @"

1. IMMEDIATE ACTIONS:
   • Remove all infected extensions immediately
   • Restart VS Code completely
   • Check VS Code extension auto-update settings
   
2. CREDENTIAL SECURITY:
   • Rotate ALL credentials (GitHub, npm, Git, API tokens)
   • Review GitHub OAuth apps and revoke suspicious ones
   • Check npm access tokens: npm token list
   • Review .npmrc and .git-credentials files
   
3. CRYPTOCURRENCY WALLETS:
   • Check all cryptocurrency wallet extensions
   • Review transaction history for unauthorized transfers
   • Move funds to new wallets with new keys
   
4. SYSTEM SECURITY:
   • Scan for SOCKS proxy or VNC servers
   • Monitor network traffic for suspicious connections
   • Check running processes for unusual activity
   • Run Windows Defender or antivirus scan
   
5. PREVENTION:
   • Only install extensions from trusted publishers
   • Disable automatic extension updates
   • Regularly audit installed extensions
   • Use extension allow-lists in enterprise environments
   
6. MONITORING:
   • Watch for unauthorized code commits to repositories
   • Monitor npm package publishing activity
   • Check for unexpected VS Code extension updates
   
For more information:
https://www.koi.ai/blog/glassworm-first-self-propagating-worm

"@ -ForegroundColor White
}

# Main execution
Start-ExtensionScan

if ($SystemCheck) {
    Test-SystemCompromise
}

if ($Findings.Count -gt 0) {
    Export-ScanReport
}

Show-Recommendations
