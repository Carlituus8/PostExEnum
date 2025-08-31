@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'PostExEnum.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# ID used to uniquely identify this module
GUID = 'b1234567-89ab-4cde-8123-456789abcdef'

# Author of this module
Author = 'Carlos Romera'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PostExEnum: post-exploitation enumeration, privilege escalation'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module (lo que expones a la shell al importar)
FunctionsToExport = @('*')

# List of all files packaged with this module
FileList = @(
    'PostExEnum.psm1',
    'modules\privesc.ps1',
    'modules\enum.ps1'
)

}