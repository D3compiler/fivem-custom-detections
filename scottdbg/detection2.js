rule HydroGen {
    strings:
        $stringEXE = "This program cannot be run in DOS mode"
        $string1 = "D3DXCreateTextureFromFileInMemory"
        $string2 = "USER32.dll"
        $string3 = "KERNEL32.dll"
        $string4 = "ntdll.dll"
        $string5 = "d3d9.dll"
        $string6 = "WS2_32.dll"
        $string7 = "OLEAUT32.dll"
        $string8 = "d3dx9_43.dll"
        $string9 = "ADVAPI32.dll"
        $string10 = "SHELL32.dll"

    condition:
        all of them
}