<#
.SYNOPSIS
    Advanced PowerShell Obfuscation Engine
    
.DESCRIPTION
    Multi-layer obfuscation for signature evasion
    Randomizes variable names, string encoding, command syntax
#>

function Invoke-Obfuscation {
    param(
        [string]$Code,
        [int]$Iterations = 3
    )
    
    $obfuscated = $Code
    
    # Layer 1: Variable name randomization
    $obfuscated = Invoke-VariableObfuscation -Code $obfuscated
    
    # Layer 2: String obfuscation
    $obfuscated = Invoke-StringObfuscation -Code $obfuscated
    
    # Layer 3: Command obfuscation
    $obfuscated = Invoke-CommandObfuscation -Code $obfuscated
    
    # Layer 4: Add random whitespace and comments
    $obfuscated = Invoke-NoiseInjection -Code $obfuscated
    
    return $obfuscated
}

function Get-RandomVariableName {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $length = Get-Random -Minimum 8 -Maximum 15
    -join ((1..$length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Invoke-VariableObfuscation {
    param([string]$Code)
    
    $commonVars = @{
        'domain' = (Get-RandomVariableName)
        'user' = (Get-RandomVariableName)
        'computer' = (Get-RandomVariableName)
        'group' = (Get-RandomVariableName)
        'searcher' = (Get-RandomVariableName)
        'result' = (Get-RandomVariableName)
        'results' = (Get-RandomVariableName)
    }
    
    foreach ($var in $commonVars.Keys) {
        $Code = $Code -replace "\`$$var\b", "`$$($commonVars[$var])"
    }
    
    return $Code
}

function Invoke-StringObfuscation {
    param([string]$Code)
    
    # Find all strings and encode them
    $pattern = '"([^"]*)"'
    $matches = [regex]::Matches($Code, $pattern)
    
    foreach ($match in $matches) {
        $original = $match.Value
        $string = $match.Groups[1].Value
        
        if ($string.Length -gt 5) {
            # Base64 encode
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($string)
            $encoded = [Convert]::ToBase64String($bytes)
            $replacement = "([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('$encoded')))"
            $Code = $Code.Replace($original, $replacement)
        }
    }
    
    return $Code
}

function Invoke-CommandObfuscation {
    param([string]$Code)
    
    # Obfuscate common cmdlets
    $cmdletMap = @{
        'Write-Host' = '&(Get-Command *rite-Ho*)'
        'Write-Output' = '&(Get-Command *rite-Out*)'
        'Get-ADUser' = '&(Get-Command *et-ADU*)'
        'Get-ADComputer' = '&(Get-Command *et-ADCo*)'
    }
    
    foreach ($cmdlet in $cmdletMap.Keys) {
        $Code = $Code -replace $cmdlet, $cmdletMap[$cmdlet]
    }
    
    return $Code
}

function Invoke-NoiseInjection {
    param([string]$Code)
    
    $lines = $Code -split "`n"
    $noisy = @()
    
    foreach ($line in $lines) {
        $noisy += $line
        
        # Randomly add comments
        if ((Get-Random -Maximum 10) -gt 7) {
            $comment = "# " + (Get-RandomVariableName)
            $noisy += $comment
        }
    }
    
    return ($noisy -join "`n")
}

Export-ModuleMember -Function Invoke-Obfuscation
