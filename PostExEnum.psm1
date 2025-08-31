# Dot-source all scripts in modules\
Get-ChildItem (Join-Path $PSScriptRoot 'modules') -Filter *.ps1 | ForEach-Object {
    . $_.FullName
}