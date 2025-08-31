function Enum-GPOApplied {
    Write-Host "`n[+] Applied GPOs to COMPUTER:" -ForegroundColor Green
    try {
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "You must run Powershell as Administrator to use /SCOPE:Computer in gpresult."
        }
        gpresult /SCOPE:Computer /v
    } catch {
        Write-Warning "Failed to retrieve computer GPOs."
    }

    Write-Host "`n[+] Applied GPOs to CURRENT USER:" -ForegroundColor Green
    try {
        gpresult /SCOPE:User /v
    } catch {
        Write-Warning "Failed to retrieve user GPOs."
    }
}

function Enum-GPOLocalFolders {
    Write-Host "`n[+] Local GPO folder structure:" -ForegroundColor Green
    $folders = Get-ChildItem -Path "C:\Windows\System32\GroupPolicy" -Recurse -Directory -ErrorAction SilentlyContinue
    if ($folders) {
        $folders | Select-Object FullName
    } else {
        Write-Host " └─ No local GPO folders found." -ForegroundColor DarkGray
    }
}

function Enum-GPOScripts {
    Write-Host "`n[+] GPO-defined scripts (Startup / Logon):" -ForegroundColor Green
    $startup = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup" -ErrorAction SilentlyContinue
    $logon   = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon" -ErrorAction SilentlyContinue

    if (-not $startup -and -not $logon) {
        Write-Host " └─ No startup or logon scripts were found." -ForegroundColor DarkGray
    } else {
        if ($startup) {
            Write-Host "`n[+] Startup scripts (HKLM):" -ForegroundColor Cyan
            $startup | Format-List
        }
        if ($logon) {
            Write-Host "`n[+] Logon scripts (HKCU):" -ForegroundColor Cyan
            $logon | Format-List
        }
    }
}

function Find-GPPPasswords {
    Write-Host "`n[+] Searching for GPP passwords in known preference files..." -ForegroundColor Cyan

    $gppFiles = @("Groups.xml", "Services.xml", "ScheduledTasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")
    $paths = @(
        "$env:ProgramData\Microsoft\Group Policy\History",
        "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History"
    )

    $found = $false

    foreach ($path in $paths) {
        if (Test-Path $path) {
            foreach ($gppFile in $gppFiles) {
                Get-ChildItem -Recurse -Include $gppFile -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $found = $true
                    Write-Host "`n[+] Found: $($_.FullName)" -ForegroundColor Yellow
                    try {
                        [xml]$xml = Get-Content $_.FullName
                        $entries = $xml.DocumentElement.SelectNodes("//*[@cpassword]")
                        foreach ($entry in $entries) {
                            $username = $entry.Properties.userName
                            $cpassword = $entry.Properties.cpassword
                            if (-not $cpassword) {
                                $cpassword = $entry.cpassword
                            }

                            if ($cpassword) {
                                Write-Host " └─ FileType : $gppFile" -ForegroundColor Blue
                                Write-Host " └─ Username : $username" -ForegroundColor Green
                                Write-Host " └─ cpassword: $cpassword" -ForegroundColor Red
                                Write-Host " └─    Decrypt : gpp-decrypt $cpassword" -ForegroundColor Magenta
                            }
                        }
                    } catch {
                        Write-Warning "Error parsing XML from $($_.FullName): $_"
                    }
                }
            }
        }
    }

    if (-not $found) {
        Write-Host "[-] No GPP password files were found." -ForegroundColor DarkGray
    }
}

function Enum-GPO {
    Enum-GPOApplied
    Enum-GPOLocalFolders
    Enum-GPOScripts
    Find-GPPPasswords
}