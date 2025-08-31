param(
    # Parameters ONLY for PRIVESC operations (non-interactive mode)
    [Alias('Pid','ProcId','ProcessId','Id')]
    [UInt32]$TargetPid = $PID,
    [switch]$TokenSummary,
    [switch]$EnableAllPrivs,
    [switch]$PrivilegeInfo,
    [switch]$UnquotedServicePaths,
    [switch]$FodhelperUACBypass,
    [switch]$UseLinked,
    [switch]$UseThread
)

# =======================
# Load modules (all)
# ==================
try { . "$PSScriptRoot\modules\utils.ps1"   } catch {}
try { . "$PSScriptRoot\modules\enum.ps1"    } catch {}
try { . "$PSScriptRoot\modules\privesc.ps1" } catch {}

# =======================
# Header and UI utilities
# =======================
function Get-QuickContext {
    $user   = "$env:USERDOMAIN\$env:USERNAME"
    $domain = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { $env:USERDOMAIN }
    $isAdmin = try {
        $wp = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $false }
    $uac = try {
        $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
        [bool]$v.EnableLUA
    } catch { $null }
    [pscustomobject]@{
        Computer  = $env:COMPUTERNAME
        User      = $user
        Domain    = $domain
        IsAdmin   = $isAdmin
        UAC       = $uac
        PSVersion = "$($PSVersionTable.PSVersion)"
        Arch      = $env:PROCESSOR_ARCHITECTURE
        Time      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Show-Header { param([UInt32]$PidTarget = $PID)
    $ctx = Get-QuickContext
    $title    = "PostExEnum"
    $info1    = "Host: $($ctx.Computer)   User: $($ctx.User)   Domain: $($ctx.Domain)"
    $info2    = ("Target PID: {0}   Admin: {1}   UAC: {2}   PS: {3} ({4})" -f `
                 $PidTarget,
                 ($(if($ctx.IsAdmin){"Yes"}else{"No"})),
                 ($(if($ctx.UAC -eq $true){"On"}elseif($ctx.UAC -eq $false){"Off"}else{"?"})),
                 $ctx.PSVersion, $ctx.Arch)
    $ts       = "Date/Time: $($ctx.Time)"
    $w=78; $top="┌"+("─"*($w-2))+"┐"; $bottom="└"+("─"*($w-2))+"┘"
    function Pad([string]$s){ "│ "+$s.PadRight($w-4)+" │" }
    function Center([string]$s){ $pad=[Math]::Max(0,($w-4-$s.Length)/2); "│ "+(" "*[int][Math]::Floor($pad))+$s+(" "*[int][Math]::Ceiling($pad))+" │" }
    Clear-Host
    Write-Host $top
    Write-Host (Center $title)
    Write-Host ("│"+(" "*($w-2))+"│")
    Write-Host (Pad $info1) -ForegroundColor Yellow
    Write-Host (Pad $info2) -ForegroundColor Yellow
    Write-Host (Pad $ts)    -ForegroundColor Yellow
    Write-Host $bottom
    Write-Host ""
}

function Pause { [void](Read-Host "`n[PRESS ENTER]") }

function Read-YesNo([string]$Prompt,[bool]$Default=$false){
    $suf=if($Default){"[Y/n]"}else{"[y/N]"}; $ans=Read-Host "$Prompt $suf"
    if([string]::IsNullOrWhiteSpace($ans)){return $Default}
    $c=$ans.Trim().Substring(0,1).ToLower()
    ($c -eq 'y' -or $c -eq '1')
}

function Show-Section([string]$Text){
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ("─"*60) -ForegroundColor DarkCyan
}

function Supports-Param([string]$Cmd,[string]$Param){
    $c = Get-Command $Cmd -ErrorAction SilentlyContinue
    return ($c -and $c.Parameters.ContainsKey($Param))
}

# =====================================
# List public functions (no helpers)
# =====================================
$EnumFunctions = @('Enum-GPO') |
    Where-Object { Get-Command $_ -ErrorAction SilentlyContinue }

$PrivFunctions = @(
    'Get-TokenSummary',
    'Enable-TokenAllPrivileges',
    'Get-UserPrivilegeInfo',
    'Find-UnquotedServicePaths',
    'FodhelperUACBypass'
) | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue }

# =========================================
# NON-INTERACTIVE MODE (PRIVESC only)
# =========================================
if ($TokenSummary -or $EnableAllPrivs -or $PrivilegeInfo -or $UnquotedServicePaths -or $FodhelperUACBypass) {
    if ($TokenSummary) {
        if (Get-Command Get-TokenSummary -ErrorAction SilentlyContinue) {
            $p = @{ Id = $TargetPid }
            if (Supports-Param 'Get-TokenSummary' 'UseLinked') { $p.UseLinked = $UseLinked }
            if (Supports-Param 'Get-TokenSummary' 'UseThread') { $p.UseThread = $UseThread }
            Get-TokenSummary @p
        } else { Write-Warning "Get-TokenSummary is not available." }
    }
    if ($EnableAllPrivs) {
        if (Get-Command Enable-TokenAllPrivileges -ErrorAction SilentlyContinue) {
            $p = @{ Id = $TargetPid }
            if (Supports-Param 'Enable-TokenAllPrivileges' 'UseLinked') { $p.UseLinked = $UseLinked }
            if (Supports-Param 'Enable-TokenAllPrivileges' 'UseThread') { $p.UseThread = $UseThread }
            $res = Enable-TokenAllPrivileges @p
            $res | Format-List
            if ($res -and $res.PSObject.Properties.Name -contains 'Details' -and $res.Details) {
                $res.Details | Where-Object { $_.Changed } | Format-Table -AutoSize
            }
        } else { Write-Warning "Enable-TokenAllPrivileges is not available." }
    }
    if ($PrivilegeInfo) {
        if (Get-Command Get-UserPrivilegeInfo -ErrorAction SilentlyContinue) {
            Get-UserPrivilegeInfo
        } else { Write-Warning "Get-UserPrivilegeInfo is not available." }
    }
    if ($UnquotedServicePaths) {
        if (Get-Command Get-UnquotedServicePaths -ErrorAction SilentlyContinue) {
            Find-UnquotedServicePaths
        } else { Write-Warning "Find-UnquotedServicePaths is not available." }
    }
    if ($FodhelperUACBypass) {
        if (Get-Command Get-FodhelperUACBypass -ErrorAction SilentlyContinue) {
            Get-FodhelperUACBypass 
        } else { Write-Warning "Get-FodhelperUACBypass is not available." }
    }
    return
}

# =====================
# INTERACTIVE MODE (UI)
# =====================
do {
    Show-Header -PidTarget $TargetPid

    # Build dynamic options map
    $menuIndex = 1
    $indexMap = @{}

    Show-Section "Enumeration"
    foreach ($fn in $EnumFunctions) {
        Write-Host ("  {0}) {1}" -f $menuIndex, $fn)
        $indexMap[$menuIndex] = @{ Type='enum'; Name=$fn }
        $menuIndex++
    }
    if ($EnumFunctions.Count -eq 0) {
        Write-Host "  (No enumeration functions loaded)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Show-Section "Privileges / Token"
    foreach ($fn in $PrivFunctions) {
        Write-Host ("  {0}) {1}" -f $menuIndex, $fn)
        $indexMap[$menuIndex] = @{ Type='priv'; Name=$fn }
        $menuIndex++
    }
    if ($PrivFunctions.Count -eq 0) {
        Write-Host "  (No privesc functions loaded)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host ("  C) Change target PID (current: {0})" -f $TargetPid)
    Write-Host "  0) Exit`n"

    $op = Read-Host "Select an option"
    if ($op -eq '0') { break }
    if ($op -match '^[cC]$') {
        $new = Read-Host "Enter new PID"
        if ($new -match '^\d+$') { 
            $TargetPid = [uint32]$new
            Write-Host "Target PID set to $TargetPid" 
        } else { 
            Write-Warning "Invalid PID." 
        }
        Start-Sleep -Milliseconds 800
        continue
    }
    if (-not ($op -match '^\d+$') -or -not $indexMap.ContainsKey([int]$op)) {
        Write-Warning "Invalid option"
        Start-Sleep -Milliseconds 900
        continue
    }

    $choice = $indexMap[[int]$op]

    switch ($choice.Type) {
        'enum' {
            & $choice.Name
            Pause
        }
        'priv' {
            switch ($choice.Name) {
                'Get-TokenSummary' {
                    $ul = Read-YesNo "Use linked token (UAC) if present?" $true
                    $ut = Read-YesNo "Use thread token (if impersonating)?" $false
                    $p = @{ Id = $TargetPid }
                    if (Supports-Param 'Get-TokenSummary' 'UseLinked') { $p.UseLinked = $ul }
                    if (Supports-Param 'Get-TokenSummary' 'UseThread') { $p.UseThread = $ut }
                    Get-TokenSummary @p
                    Pause
                }
                'Enable-TokenAllPrivileges' {
                    $ul = Read-YesNo "Use linked token (UAC) if present?" $true
                    $ut = Read-YesNo "Use thread token (if impersonating)?" $false
                    $p = @{ Id = $TargetPid }
                    if (Supports-Param 'Enable-TokenAllPrivileges' 'UseLinked') { $p.UseLinked = $ul }
                    if (Supports-Param 'Enable-TokenAllPrivileges' 'UseThread') { $p.UseThread = $ut }
                    $res = Enable-TokenAllPrivileges @p
                    $res | Format-List
                    if ($res -and $res.PSObject.Properties.Name -contains 'Details' -and $res.Details) {
                        $res.Details | Where-Object { $_.Changed } | Format-Table -AutoSize
                    }
                    Pause
                }
                default {
                    & $choice.Name
                    Pause
                }
            }
        }
    }
} while ($true)