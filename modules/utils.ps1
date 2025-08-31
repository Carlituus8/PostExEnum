function Export-Restuls {
    param(
        [Parameter(Mandatory, ValueFromPipeline = $true)]
        [object[]]$InputData,

        [Parameter(Mandatory)]
        [string]$ExportPath,

        [ValidateSet("json", "csv", "auto")]
        [string]$Format = "auto"
    )

    begin {
        $results = @()
    }

    process {
        $results = $InputData
    }

    end {
        # Auto detec format from extension
        if ($Format -eq "auto") {
            $extension = [System.IO.Path]::GetExtension($ExportPath).ToLower()
            switch ($extension) {
                ".json" { $Format = "json" }
                ".csv"  { $Format = "csv" }
                default {
                    Write-Warning "Could not detect format from extension. Use -Format explicitly (json or csv)."
                    return
                }
            }
        }

        try {
            if ($Format -eq "json") {
                $results | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 $ExportPath
                Write-Host "[+] Exported to JSON at: $ExportPath"
            }
            elseif ($Format -eq "csv") {
                $results | Export-Csv -NoTypeInformation -Path $ExportPath
                Write-Host "[+] Exported to CSV at: $ExportPath"
            }
        }
        catch {
            Write-Warning "[!] Failed to export: $_"
        }
    }
}

function Test-WriteAccess {
    param(
        [Parameter(Mandatory=$true)][string]$Directory
    )
    try {
        if (-not (Test-Path -LiteralPath $Directory)) { return $false }
        $tmp = Join-Path $Directory ("._" + [guid]::NewGuid().ToString("N") + ".tmp")
        New-Item -Path $tmp -ItemType File -Force -ErrorAction Stop | Out-Null
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
        return $true
    } catch { 
        return $false 
    }
}

function Convert-SID {
<#
.SYNOPSIS
Converts a raw SID pointer to a readable name and SID string.

.DESCRIPTION
This function accepts a raw IntPtr to a SID structure and attempts to convert it
to a readable NTAccount name and SID value using .NET classes.
It is typically used to resolve SIDs extracted from unmanaged memory.

.PARAMETER Ptr
A pointer (IntPtr) to a SID structure, such as from a TOKEN_GROUPS buffer.

.OUTPUTS
String. Format: DOMAIN\Name (S-1-5-21-...)

.EXAMPLE
Convert-SID -Ptr $entry.Sid
#>

    param (
        [Parameter(Mandatory)]
        [System.IntPtr]$Ptr
    )
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($Ptr)
        $name = $sid.Translate([System.Security.Principal.NTAccount])
        return "$name ($($sid.Value))"
    } catch {
        return "[Unresolved] ($Ptr)"
    }
}

function Convert-SIDObject {
<#
.SYNOPSIS
Converts a .NET IdentityReference SID object to a readable name and SID string.

.DESCRIPTION
This function is used when working with managed .NET SID objects (e.g., from WindowsIdentity.Groups).
It translates the SID to a NTAccount (DOMAIN\Username) and includes the SID string.

.PARAMETER SidObject
A System.Security.Principal.IdentityReference object (usually a SID from .NET).

.OUTPUTS
String. Format: DOMAIN\Name (S-1-5-21-...)

.EXAMPLE
$identity.Groups | ForEach-Object { Convert-SIDObject $_ }
#>

    param (
        [Parameter(Mandatory)]
        [System.Security.Principal.IdentityReference]$SidObject
    )
    try {
        "$($SidObject.Translate([System.Security.Principal.NTAccount])) ($($SidObject.Value))"
    } catch {
        "[Unknown or inaccessible] ($($SidObject.Value))"
    }
}

# Free the token buffer (when get open it for extracting token information)
function Free-TokenBuffer {
    param([IntPtr]$Buffer)

    if ($Buffer -and $Buffer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($Buffer)
    }
}

# Close the handle
function Close-Token {
    param([IntPtr]$TokenHandle)

    if ($TokenHandle -and $TokenHandle -ne [IntPtr]::Zero) {
        $success = $Kernel32::CloseHandle($TokenHandle)

        if (-not $success) {
            Write-Verbose ("CloseHandle failed. Win32Error={0}" -f ([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
    }
}