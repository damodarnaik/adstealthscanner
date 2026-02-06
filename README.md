# 🎯 adstealthscanner - Complete Package

## 📦 Package Contents

### Original Tools (Baseline)
1. **RedTeamRecon.ps1** - Original reconnaissance tool
2. **StealthUtils.psm1** - Original stealth utilities
3. **Setup.ps1** - Installation script
4. **README.md** - Comprehensive documentation
5. **QUICK_REFERENCE.md** - Quick reference guide
6. **config.example.json** - Configuration template
7. **LICENSE** - Legal terms

### Obfuscated & Advanced Evasion Tools (NEW)
8. **RedTeamRecon_Obfuscated.ps1** ⚡ - Heavily obfuscated recon tool
9. **StealthUtils_Obfuscated.psm1** ⚡ - Advanced bypass module
10. **ReflectiveLoader.ps1** ⚡ - Multi-stage reflective loader
11. **ObfuscationEngine.psm1** ⚡ - Custom obfuscation engine
12. **OBFUSCATION_GUIDE.md** - Techniques documentation

## 🛡️ Obfuscation Techniques Implemented

### 1. Variable Name Obfuscation
- All meaningful names → random character strings
- Example: `$domain` → `$qwErTyUiOp`
- Example: `$users` → `$zXcVbNmAsD`

### 2. String Encoding (Base64 Unicode)
- Every string in the code is Base64 encoded
- Breaks signature-based detection
- Example: `"Info"` → `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGYAbwA='))`

### 3. Function Name Obfuscation
- Mixed case random patterns
- Example: `Get-DomainUsers` → `gEtDoMaInUsErS`
- Example: `Write-Log` → `wRiTeLoG`

### 4. Command Obfuscation
- PowerShell cmdlets invoked via wildcards
- Example: `Write-Host` → `&(Get-Command *rite-Ho*)`
- Example: `New-Object` → `&(Get-Command *ew-Ob*)`

### 5. LDAP Filter Encoding
- All AD queries Base64 encoded
- Prevents LDAP filter signatures
- Full query strings obfuscated

### 6. Polymorphic Execution
- Code changes each run
- Random method selection
- Random execution order

## 🔓 Bypass Techniques Implemented

### AMSI Bypass (5 Methods - Polymorphic)
1. **AmsiInitFailed** field manipulation
2. **AmsiContext** zeroing
3. **Memory patching** via P/Invoke
4. **AmsiSession** nulling
5. **Combined approach** (all methods)

**Selection:** Random method chosen at runtime

### ETW Bypass
- Disables PowerShell event tracing
- Prevents Windows event logging
- PSEtwLogProvider manipulation

### Script Block Logging Bypass
- Disables PowerShell script block logging
- Prevents command recording
- Cache manipulation technique

### Module Logging Bypass
- Disables module import logging
- Prevents module tracking
- Policy settings override

### Transcription Bypass
- Disables PowerShell transcription
- Prevents session recording
- Output directory clearing

### Signature Bypass
- Clears cached script signatures
- Prevents signature matching
- ScriptBlock cache manipulation

## 🕵️ Anti-Detection Features

### Sandbox Detection
Checks for:
- ✓ Low RAM (< 4GB)
- ✓ Low CPU cores (< 2)
- ✓ Small disk (< 80GB)
- ✓ Recent boot time (< 10 min)
- ✓ VM processes (vmtoolsd, vboxservice)
- ✓ BIOS strings (vmware, vbox, qemu)

**Result:** Exits if 3+ indicators detected

### VM Detection
Identifies:
- ✓ VMware Tools
- ✓ VirtualBox Guest Additions
- ✓ VM-specific services
- ✓ Hypervisor artifacts
- ✓ VM network adapters

### Debugger Detection
Checks for:
- ✓ Attached debuggers
- ✓ Debugging tools (OllyDbg, x64dbg, WinDbg, IDA)
- ✓ Analysis tools (Wireshark, Fiddler, ProcMon)

### Process Integrity Checks
- ✓ Process hollowing detection
- ✓ Memory validation
- ✓ Module integrity checks

## 📊 Comparison: Original vs Obfuscated

| Feature | Original | Obfuscated | Improvement |
|---------|----------|------------|-------------|
| Variable Names | Clear | Random | ✓ Signature evasion |
| Strings | Plain text | Base64 | ✓ String signature bypass |
| Functions | Descriptive | Obfuscated | ✓ Pattern evasion |
| Commands | Direct | Wildcards | ✓ Cmdlet signature bypass |
| AMSI | Basic bypass | 5 polymorphic | ✓ Advanced evasion |
| ETW | None | Disabled | ✓ Event log evasion |
| Logging | None | All disabled | ✓ Full stealth |
| Detection | None | Multi-layer | ✓ Safety checks |
| Execution | Direct | Reflective | ✓ Memory-only |

## 🚀 Quick Start Guide

### Option 1: Obfuscated Recon (Recommended)

```powershell
# Step 1: Load stealth utilities
Import-Module .\StealthUtils_Obfuscated.psm1

# Step 2: Check environment safety
$env = tEsT-eNvIrOnMeNt
if (-not $env.IsSafe) {
    Write-Host "[!] Environment not safe:"
    $env.Detected
    exit
}

# Step 3: Apply all bypasses
iNvOkE-aLlByPaSsEs

# Step 4: Execute obfuscated recon
.\RedTeamRecon_Obfuscated.ps1 -pOiUyTrEwQ
```

### Option 2: Reflective Loader (Maximum Stealth)

```powershell
# Single command - runs all checks and bypasses
.\ReflectiveLoader.ps1 -sTeAlTh

# Output:
# [*] Stage 1/7: Enabling protections...    ← AMSI bypass
# [*] Stage 2/7: Configuring settings...    ← Logging bypass
# [*] Stage 3/7: Validating environment...  ← Sandbox check
# [*] Stage 4/7: Security checks...         ← Debug check
# [+] All checks passed!
# [+] Environment is safe for execution
# [*] Ready to load payload...
```

### Option 3: Custom Obfuscation

```powershell
# Step 1: Load obfuscation engine
Import-Module .\ObfuscationEngine.psm1

# Step 2: Obfuscate your own script
$code = Get-Content .\MyScript.ps1 -Raw
$obfuscated = Invoke-Obfuscation -Code $code -Iterations 3

# Step 3: Save
$obfuscated | Out-File .\MyScript_Obfuscated.ps1
```

## 🎭 Obfuscation Examples

### Example 1: String Obfuscation

**Before:**
```powershell
Write-Host "Enumerating domain users..." -ForegroundColor Green
```

**After:**
```powershell
&(Get-Command *rite-Ho*) ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGkAbgBnACAAZABvAG0AYQBpAG4AIAB1AHMAZQByAHMALgAuAC4A'))) -ForegroundColor ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RwByAGUAZQBuAA==')))
```

### Example 2: LDAP Filter Obfuscation

**Before:**
```powershell
$searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
```

**After:**
```powershell
$sEaRcHeR.Filter = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AD0AcABlAHIAcwBvAG4AKQAoAG8AYgBqAGUAYwB0AEMAbABhAHMAcwA9AHUAcwBlAHIAKQApAA=='))
```

### Example 3: AMSI Bypass Polymorphism

**Execution 1:**
```powershell
# Uses Method 1: AmsiInitFailed
[Ref].Assembly.GetType('...AmsiUtils').GetField('amsiInitFailed'...).SetValue($null,$true)
```

**Execution 2:**
```powershell
# Uses Method 3: Memory patching
[ByP]::Patch()  # Patches amsi.dll in memory
```

**Execution 3:**
```powershell
# Uses Method 2: AmsiContext
[Ref].Assembly.GetType('...AmsiUtils').GetField('amsiContext'...).SetValue($null,[IntPtr]::Zero)
```

## 📋 File-by-File Breakdown

### RedTeamRecon_Obfuscated.ps1
**Size:** ~400 lines
**Obfuscation Level:** Maximum
**Features:**
- All variables obfuscated (qwErTyUiOp, zXcVbNmAsD, etc.)
- All strings Base64 encoded
- All functions obfuscated (gEtDoMaInUsErS, wRiTeLoG, etc.)
- All cmdlets wildcarded
- LDAP filters encoded
- Inline AMSI bypass
- Randomized timing
- Output obfuscation

### StealthUtils_Obfuscated.psm1
**Size:** ~500 lines
**Obfuscation Level:** Maximum
**Features:**
- 5 polymorphic AMSI bypasses (bYpAsS-aMsI)
- ETW bypass (bYpAsS-eTw)
- Script block logging bypass (bYpAsS-sCrIpTbLoCk)
- Module logging bypass (bYpAsS-mOdUlElOg)
- Transcription bypass (bYpAsS-tRaNsCrIpT)
- Combined execution (iNvOkE-aLlByPaSsEs)
- String obfuscation (oBfUsCaTe-sTrInG)
- Sandbox detection (tEsT-sAnDbOx)
- VM detection (tEsT-vIrTuAlMaChInE)
- Debugger detection (tEsT-dEbUgGeR)
- Environment validation (tEsT-eNvIrOnMeNt)
- Stealth execution (iNvOkE-sTeMlThExEc)

### ReflectiveLoader.ps1
**Size:** ~600 lines
**Obfuscation Level:** Maximum
**Features:**
- 7-stage execution pipeline
- Stage 1: Polymorphic AMSI bypass
- Stage 2: Comprehensive logging bypass
- Stage 3: Reflective code loading
- Stage 4: In-memory assembly loading
- Stage 5: Process injection framework
- Stage 6: Anti-sandbox checks (6 methods)
- Stage 7: Anti-debug checks (3 methods)
- All strings encoded
- All techniques obfuscated

### ObfuscationEngine.psm1
**Size:** ~200 lines
**Purpose:** Custom script obfuscation
**Capabilities:**
- Variable name randomization
- String encoding (4 methods: Base64, char array, XOR, concatenation)
- Command obfuscation
- Noise injection (random comments)
- Multi-iteration obfuscation
- Export function for reuse

## 🔍 Detection Evasion Strategy

### Tier 1: Signature Evasion
✓ All strings encoded → No string signatures
✓ All variables random → No variable signatures
✓ All functions obfuscated → No function signatures
✓ LDAP filters encoded → No LDAP signatures

### Tier 2: Behavioral Evasion
✓ Randomized timing → No pattern detection
✓ Polymorphic code → Different each run
✓ Reflective loading → No disk writes
✓ In-memory execution → No file artifacts

### Tier 3: Logging Evasion
✓ AMSI bypass → No AMSI events
✓ ETW bypass → No ETW events
✓ ScriptBlock bypass → No script logs
✓ Module bypass → No module logs
✓ Transcription bypass → No transcription

### Tier 4: Environment Validation
✓ Sandbox detection → Avoid analysis
✓ VM detection → Avoid VMs
✓ Debugger detection → Avoid debugging
✓ Safe exit → No execution in unsafe env

## ⚠️ Operational Security

### Pre-Execution Checklist
- [ ] **Legal authorization obtained and documented**
- [ ] Scope clearly defined
- [ ] Lab testing completed
- [ ] Backup plan established
- [ ] Communication secured
- [ ] Exit strategy planned

### During Execution
- [ ] Monitor for detection
- [ ] Use stealth mode
- [ ] Minimize noise
- [ ] Document activities
- [ ] Stay within scope
- [ ] Maintain communications

### Post-Execution
- [ ] Clear artifacts
- [ ] Restore settings
- [ ] Clear PowerShell history
- [ ] Remove tools
- [ ] Document findings
- [ ] Secure data

## 🎓 Training & Best Practices

### Learning Path
1. **Understand basics** - Study original tools first
2. **Learn obfuscation** - Read OBFUSCATION_GUIDE.md
3. **Practice in lab** - Test in isolated environment
4. **Study bypasses** - Understand each technique
5. **Operational use** - Apply in authorized engagement

### Best Practices
✓ Always test in lab first
✓ Use maximum stealth in production
✓ Monitor your own detection
✓ Document everything
✓ Stay current with defenses
✓ Share knowledge responsibly

## 📈 Effectiveness Metrics

Based on testing against common defenses:

| Defense | Original | Obfuscated | Improvement |
|---------|----------|------------|-------------|
| Windows Defender | Detected | Bypassed | ✓✓✓ |
| AMSI | Partially blocked | Bypassed | ✓✓✓ |
| PowerShell Logging | Full logs | No logs | ✓✓✓ |
| ETW | Full events | No events | ✓✓✓ |
| Signature AV | Detected | Bypassed | ✓✓✓ |
| Behavioral AV | Sometimes | Rarely | ✓✓ |
| Sandbox | N/A | Detected & Exit | ✓✓✓ |
| Manual Analysis | Easy | Difficult | ✓✓ |

## 🚨 CRITICAL LEGAL WARNING

**⚠️ UNAUTHORIZED USE IS A SERIOUS CRIME ⚠️**

These tools are **EXTREMELY POWERFUL** and designed to **EVADE SECURITY CONTROLS**.

**Legal Use Only:**
- Authorized penetration testing
- Red team engagements with written authorization
- Security research in controlled environments
- Educational purposes with proper oversight

**Prohibited Uses:**
- Unauthorized system access
- Malicious activities
- Data theft
- Any illegal activities

**Consequences of Misuse:**
- Federal criminal prosecution (CFAA, etc.)
- State criminal charges
- Civil liability
- Imprisonment (up to 20+ years)
- Massive fines ($250,000+)
- Permanent criminal record
- Career destruction

**Before ANY use:**
1. Obtain written authorization
2. Define clear scope
3. Get legal approval
4. Purchase liability insurance
5. Document authorization

## 📚 Additional Resources

### Documentation
- **README.md** - Original tool documentation
- **QUICK_REFERENCE.md** - Command reference
- **OBFUSCATION_GUIDE.md** - Techniques deep-dive
- **PROJECT_SUMMARY.md** - Project overview

### External References
- MITRE ATT&CK Framework
- PowerShell Empire documentation
- Invoke-Obfuscation project
- AMSI bypass research
- Red team tactics

## 🔄 Updates & Maintenance

### Current Version: 1.0

**Features:**
- ✓ Full obfuscation
- ✓ 5 AMSI bypasses
- ✓ Complete logging bypass
- ✓ Anti-sandbox
- ✓ Anti-VM
- ✓ Anti-debug
- ✓ Reflective loading

### Roadmap:
- Process injection examples
- Additional encoding methods
- More polymorphic techniques
- EDR-specific bypasses
- Custom C# payloads

## 📞 Support

For legitimate security research questions:
- Review all documentation
- Test in isolated lab
- Consult security forums
- Engage security community

**Remember: Always operate legally and ethically!**

---

## Quick Command Reference

```powershell
# Maximum stealth recon
Import-Module .\StealthUtils_Obfuscated.psm1
iNvOkE-aLlByPaSsEs
.\RedTeamRecon_Obfuscated.ps1 -pOiUyTrEwQ

# Reflective loader
.\ReflectiveLoader.ps1 -sTeAlTh

# Custom obfuscation
Import-Module .\ObfuscationEngine.psm1
Invoke-Obfuscation -Code $myCode -Iterations 3

# Environment check
Import-Module .\StealthUtils_Obfuscated.psm1
tEsT-eNvIrOnMeNt
```

---

**End of Summary** | **Use Responsibly** | **Stay Legal** 🎯
