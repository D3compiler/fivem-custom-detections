rule Skript {
    meta:
        name = "Skript Loader"
        severity = "severe"
        description = "1"
        author = "@godsnico"
    
    strings:
        $string1 = "D3D11CreateDeviceAndSwapChain"
        $string2 = "AcquireSRWLockExclusive"
        $string3 = "CreateFileW"
        $string4 = "CreateThread"
        $string5 = ".text"
        $string6 = ".stbtext"
    
    condition:
        all of them
}

rule TZX {
    meta:
        name = "TZX Loader"
        severity = "severe"
        description = "2"
        author = "@godsnico"
        
   strings:
      $s1 = "taskhostw.exe" fullword wide
      $s2 = "TZX.exe" fullword ascii
      $s3 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii
      $s4 = "a* QZBw0[U" fullword ascii
      $s5 = "Ie+%d%5vOX`" fullword ascii
      $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s7 = "W|L`o:\"p`" fullword ascii
      $s8 = "]o:\\Sh" fullword ascii
      $s9 = "e9y.YMH" fullword ascii
      $s10 = "k:\\Qsi" fullword ascii
      $s11 = "_'N:\\&" fullword ascii
      $s12 = "\\7sPye" fullword ascii
      $s13 = "lZ:\\Dyw" fullword ascii
      $s14 = "fcMDj*#" fullword ascii
      $s15 = "BXU.SMU%" fullword ascii
      $s16 = "SAPAVAQM" fullword ascii
      $s17 = "Windaos" fullword wide
      $s18 = "AfOkqa8" fullword ascii
      $s19 = "dwBieBPD0" fullword ascii
      $s20 = "}N%L%|]" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule Gosth {
    meta:
        name = "Gosth Loader"
        severity = "severe"
        description = "3"
        author = "@godsnico"
        
    strings:
        $x1 = "@.pedrin0" fullword ascii
        $x2 = "`.pedrin1" fullword ascii
        $x3 = ".pedrin2" fullword ascii
        $s4 = "api-ms-win-crt-locale-l1-1-0.dll" fullword ascii
        $s5 = "api-ms-win-crt-filesystem-l1-1-0.dll" fullword ascii
        $s6 = "api-ms-win-crt-math-l1-1-0.dll" fullword ascii
        $s7 = "api-ms-win-crt-runtime-l1-1-0.dll" fullword ascii
        $s8 = "!This program cannot be run in DOS mode." fullword ascii
        $s9 = "pn5Or@!S" fullword ascii
        $s10 = "&tA-MC&tA" fullword ascii
        $s11 = "__current_exception" fullword ascii
        $s12 = "_unlock_file" fullword ascii
        $s13 = "r~K7?~V@R" fullword ascii
        $s14 = "?out@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEBD1AEAPEBDPEAD3AEAPEAD@Z" fullword ascii
        $s15 = "OKERNEL32.dll" fullword ascii
        
    condition:
        uint16(0) == 0x5a4d and filesize < 25000KB and
        1 of ($x*) and 4 of them
}

rule HX {
  meta:
        name = "HX Loader"
        severity = "severe"
        description = "4"
        author = "@godsnico"
        
   strings:
      $s1 = "tGDI32.dll" fullword ascii
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s3 = "* RMkq" fullword ascii
      $s4 = "dLOGQO " fullword ascii
      $s5 = "* +A8M{=" fullword ascii
      $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s7 = "mcmd7is" fullword ascii
      $s8 = "he:\"QN" fullword ascii
      $s9 = "C:\"ZJL|i\"cPf" fullword ascii
      $s10 = "Vel.MSe)<L!?R" fullword ascii
      $s11 = "ARWAWSVD" fullword ascii
      $s12 = "cm#DLl" fullword ascii
      $s13 = "2%ckt%" fullword ascii
      $s14 = "`@$P -=" fullword ascii
      $s15 = "- b!qP" fullword ascii
      $s16 = " *my -" fullword ascii
      $s17 = "E -=\\z~k" fullword ascii
      $s18 = "Xt%ED%i" fullword ascii
      $s19 = "?}\"w* " fullword ascii
      $s20 = "OQ;hP* " fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule PrivaZer {
    meta:
        name = "PrivaZer Cleaner"
        severity = "severe"
        description = "5"
        author = "@godsnico"
        
   strings:
      $x1 = "PrivaZer.exe" fullword ascii
      $x2 = "PrivaZer_Pro.new.exe" fullword ascii
      $x3 = "PrivaZer.default.ini" fullword ascii
      $x4 = "PrivaZer.ini" fullword ascii
      $x5 = "PrivaZer" fullword ascii
      $s6 = "support@privazer.com" fullword ascii
      $s7 = "https://www.privazer.com/PrivaZer.exe" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 28000KB and
      1 of ($x*) and 2 of them
}

rule RevoUninstaller {
    meta:
        name = "RevoUnistaller Cleaner"
        severity = "severe"
        description = "6"
        author = "@godsnico"
        
   strings:
      $x1 = "RevoUnin.exe" fullword ascii
      $x2 = "Revo Uninstaller" fullword ascii
      $x3 = "https://www.revouninstaller.com" fullword ascii
      $x4 = "Revo Uninstaller-command-manager-profile" fullword ascii
      $s5 = "Revo Uninstaller Pro" fullword ascii
      $s6 = "https://www.facebook.com/pages/Revo-Uninstaller/53526911789" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      1 of ($x*) and 2 of them
}

rule CCleaner {
    meta:
        name = "CCleaner Cleaner"
        severity = "severe"
        description = "7"
        author = "@godsnico"
        
   strings:
      $x1 = "Ccleaner.exe" fullword ascii
      $x2 = "Ccleaner64.exe" fullword ascii
      $x3 = "CCleaner.Windows.IPC.NamedPipes" fullword ascii
      $x4 = "CCleanerDU.dll" fullword ascii
      $s6 = "ccleaner.com" fullword ascii
      $s7 = "dlc.ccleaner.com" fullword ascii
      $s8 = "https://www.ccleaner.com" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 40000KB and
      1 of ($x*) and 2 of them
}

rule Generic_A {
    meta:
        name = "Suspicious Hook A"
        severity = "warning"
        description = "8"
        author = "@godsnico"
        
   strings:
      $s1 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s2 = "W1,$_@" fullword ascii
      $s3 = "14$_A:" fullword ascii
      $s4 = "AR1,$L" fullword ascii
      $s5 = "AR1,$D" fullword ascii
      $s6 = "1<$A[A" fullword ascii
      $s7 = "1,$_fA" fullword ascii
      $s8 = "W1,$fA" fullword ascii
      $s9 = "$A[fE;" fullword ascii
      $s10 = "AR1,$I" fullword ascii
      $s11 = "14$]Hc" fullword ascii
      $s12 = "U14$fD" fullword ascii
      $s13 = "AR1,$A" fullword ascii
      $s14 = "AR1<$AZ@" fullword ascii
      $s15 = "1<$AZHc" fullword ascii
      $s16 = "AS1,$A[@" fullword ascii
      $s17 = "$A[fD;" fullword ascii
      $s18 = "1,$fD#" fullword ascii
      $s19 = "AR1<$fA" fullword ascii
      $s20 = "AR1,$AZHc" fullword ascii
      
   condition:
   
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule SusanoLoader {
    meta:
        name = "Susano Loader"
        severity = "severe"
        description = "244"
        author = "@godsnico"
      
   strings:
      $s1 = "GRich0'"
      $s2 = "uaG6"
      $s3 = "@.text"
      $s4 = ".boot"
      $s5 = "@.idata"
      $s6 = "ntdll.dll"

   condition: 
      all of them
}


rule Generic_B {
    meta:
        name = "Suspicious Hook B"
        severity = "warning"
        description = "9"
        author = "@godsnico"
        
   strings:
      $s1 = "h.rsrc" fullword ascii
      $s2 = "AS1,$A" fullword ascii
      $s3 = ".AaVXM" fullword ascii
      $s4 = "AS1<$I" fullword ascii
      $s5 = "AS1,$A[Hc" fullword ascii
      $s6 = "1<$A[Hc" fullword ascii
      $s7 = "Oh4e1z" fullword ascii
      $s8 = "AS1,$fE" fullword ascii
      $s9 = "AS1<$A" fullword ascii
      $s10 = "1,$A[A" fullword ascii
      $s11 = "1<$fA#" fullword ascii
      $s12 = "AS1,$A[" fullword ascii
      $s13 = "1,$_Hc" fullword ascii
      $s14 = "1,$A[Hc" fullword ascii
      $s15 = "AS1<$fA" fullword ascii
      $s16 = "AS1,$fA" fullword ascii
      $s17 = "14$_Hc" fullword ascii
      
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule Generic_C {
    meta:
        name = "Suspicious Hook C"
        severity = "warning"
        description = "10"
        author = "@godsnico"
        
   strings:
      $s12 = "anguagesA EnumUILanguagesW EnumerateLocalComputerNamesA EnumerateLocalComputerNamesW EraseTape EscapeCommFunction ExecuteUmsThre" ascii
      $s13 = "r DrawMenuBarTemp DrawStateA DrawStateW DrawTextA DrawTextExA DrawTextExW DrawTextW DwmGetDxRgn DwmGetDxSharedSurface DwmGetRemo" ascii
      $s14 = "c LdrInitializeEnclave LdrInitializeThunk LdrLoadAlternateResourceModule LdrLoadAlternateResourceModuleEx LdrLoadDll LdrLoadEncl" ascii
      $s15 = "ansactionManager ZwCreateUserProcess ZwCreateWaitCompletionPacket ZwCreateWaitablePort ZwCreateWnfStateName ZwCreateWorkerFactor" ascii
      $s16 = "etNLSVersionEx GetNamedPipeAttribute GetNamedPipeClientComputerNameA GetNamedPipeClientComputerNameW GetNamedPipeClientProcessId" ascii
      $s17 = "ToStringW RtlEthernetStringToAddressA RtlEthernetStringToAddressW RtlExecuteUmsThread RtlExitUserProcess RtlExitUserThread RtlEx" ascii
      $s18 = "GetNamedPipeClientSessionId GetNamedPipeHandleStateA GetNamedPipeHandleStateW GetNamedPipeServerProcessId GetNamedPipeServerSess" ascii
      $s19 = "C:\\Users\\Daniel\\Documents\\Projects\\Pessoal\\Captures\\x64\\Release\\Fivem-External.pdb" fullword ascii
      $s20 = "obSet ZwCreateKey ZwCreateKeyTransacted ZwCreateKeyedEvent ZwCreateLowBoxToken ZwCreateMailslotFile ZwCreateMutant ZwCreateNamed" ascii
   condition:
      1 of ($x*) and 7 of them
}

rule Generic_E {
    meta:
        name = "Generic Cheat E"
        severity = "severe"
        description = "15"
        author = "@godsnico"
        
   strings:
      $s1 = "FiveM-ExternalCheat" fullword ascii
      $s2 = "Fivem-External" fullword ascii
      $s3 = "Fivem External" fullword ascii
      $s4 = "TDLoader" fullword ascii
      
   condition:
      1 of them
}

rule Generic_F {
    meta:
        name = "Generic Cheat F"
        severity = "severe"
        description = "16"
        author = "@godsnico"
        
   strings:
      $s1 = "Fivem-External.pdb" fullword ascii
      $s2 = "silent_aimbot_fov_color" fullword ascii
      $s3 = "Silent Aimbot FOV Color" fullword ascii
      $s4 = "Show Aimbot FOV" fullword ascii
      $s5 = "aimbot_silent_fov" fullword ascii
      
   condition:
      1 of them
}

rule Generic_G {
    meta:
        name = "Generic Cheat G"
        severity = "severe"
        description = "16"
        author = "@godsnico"
        
   strings:
      $s1 = "Aimbot FOV Color" fullword ascii
      $s2 = "Aimbot Bind" fullword ascii
      $s3 = "Dual Aimbot" fullword ascii
      $s4 = "aimbot_fov" fullword ascii
      
   condition:
      1 of them
}

rule Generic_I {
    meta:
        name = "Generic Cheat I"
        severity = "severe"
        description = "18"
        author = "@godsnico"
        
   strings:
      $s1 = "Skeleton Color" fullword ascii
      $s2 = "Aimbot Settings" fullword ascii
      $s3 = "Hotkey Noclip" fullword ascii
      $s4 = "aimbot_smoothing_x" fullword ascii
      $s5 = "aimbot_smoothing_y" fullword ascii
      $s6 = "players_skeleton_color" fullword ascii
      
   condition:
      1 of them
}

rule Generic_L {
    meta:
        name = "Generic Cheat L"
        severity = "severe"
        description = "19"
        author = "@godsnico"
        
   strings:
      $s1 = "Enabled##Aimbot" fullword ascii
      $s2 = "Draw##AimbotBone" fullword ascii
      $s3 = "Selected##AimbotBone" fullword ascii
      $s4 = "Color##AimbotBone" fullword ascii
      $s5 = "Enable##AimbotSmooth" fullword ascii
      $s6 = "Speed##Aimbot" fullword ascii
      $s7 = "Enabled##AimbotFov" fullword ascii
      $s8 = "Color##AimbotFov" fullword ascii
      $s9 = "Size##AimbotFov" fullword ascii
   
   condition:
      1 of them
}

rule XRC {
    meta:
        name = "XRC Loader"
        severity = "severe"
        description = "22"
        author = "@godsnico"
        
    strings:
        $xrc_specific1 = "(Auto-disabled ImGuiDebugLogFlags_EventClipper to avoid spamming)"
        $xrc_specific2 = "r\\x64\\Release\\Fivem-External.pdb"
        $xrc_specific3 = "flag-checkered"
        $xrc_specific4 = "_get_stream_buffer_pointers"

        $xrc_hex_string1 = { 28  41  75  74  6F  2D  64  69  73  61  62  6C  65  64  20  49  6D  47  75  69  44  65  62  75  67  4C  6F  67  46  6C  61  67 73  5F  45  76  65  6E  74  43  6C  69  70  70  65  72  20  74 6F  20  61  76  6F  69  64  20  73  70  61  6D  6D  69  6E  67 29 }
        $xrc_hex_string2 = { 72  5C  78  36  34  5C  52  65  6C  65  61  73  65  5C  46  69 76  65  6D  2D P




function timeAgo(milliseconds) {
    let seconds = Math.floor(milliseconds / 1000);
    let minutes = Math.floor(seconds / 60);
    let hours = Math.floor(minutes / 60);
    let days = Math.floor(hours / 24);
    
    if (days > 0) return days + "d ago";
    if (hours > 0) return hours + "h ago";
    if (minutes > 0) return minutes + "m ago";
    return seconds + "s ago";
}

let fivemPath = uninstallDir("FiveM");
if (!fivemPath) {
    result("FiveM installation not found", warning);
    return;
}

let cachePath = fivemPath + "\\FiveM.app\\data\\cache\\servers";
walk(cachePath, function(filepath) {
    let currentTime = time() * 1000;
    
    let editTime = lastWrite(filepath);
    if (editTime < 10000000000) editTime *= 1000;
    let editDiff = currentTime - editTime;
    
    let createTime = createdAt(filepath);
    if (createTime < 10000000000) createTime *= 1000;
    let createDiff = currentTime - createTime;
    
    for (let i = 0; i < server_list.length; i++) {
        let name = server_list[i].split(":::")[0];
        let ico_name = server_list[i].split(":::")[1];
        
        if (filepath.endsWith(ico_name)) {
            result("[[" + name + "]] Connected @ First: [[" + timeAgo(createDiff) + "]] | Last: [[" + timeAgo(editDiff) + "]]", good);
            log("[[" + name + "]] Connected @ First: [[" + editTime + "]] | Last: " + createTime);
            break;
        }
    }
});
rule ProcessHollowing {
    meta:
        name = "Process Hollowing Method"
        severity = "severe"
        description = "1"
        author = "@godsnico"
      
   strings:
      $s1 = "ResumeThread"
      $s2 = "SetThreadContext"
      $s3 = "WriteProcessMemory"
      $s4 = "Wow64SetThreadContext"

   condition: 
      all of them
}


rule ThreadExecution {
    meta:
        name = "Thread Execution Hijacking"
        severity = "severe"
        description = "2"
        author = "@godsnico"
      
   strings:
      $s1 = "ResumeThread"
      $s2 = "GetThreadContext"
      $s3 = "SetThreadContext"
      $s4 = "Wow64GetThreadContext"
      $s5 = "Wow64SetThreadContext"

   condition: 
      all of them
}

rule ShellCode {
	meta:
        name = "ShellCode Injector"
        severity = "severe"
        description = "3"
        author = "@godsnico"

	strings:
		$s1 = "PPidSpoof" fullword ascii
		$s2 = "ProcHollowing" fullword ascii
		$s3 = "CreateProcess" fullword ascii
		$s4 = "DynamicCodeInject" fullword ascii
		$s5 = "PPIDDynCodeInject" fullword ascii
		$s6 = "MapAndStart" fullword ascii
		$s7 = "PPIDAPCInject" fullword ascii
		$s8 = "PPIDDLLInject" fullword ascii
		$s9 = "CopyShellcode" fullword ascii
		$s10 = "GetEntryFromBuffer" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 5 of ( $s* )
}

rule CobaltStrike {
	meta:
        name = "CobaltStirke Malaware"
        severity = "warning"
        description = "Trojan"
        author = "@godsnico"

	strings:
		$s1 = "https://%hu.%hu.%hu.%hu:%u" ascii wide
		$s2 = "https://microsoft.com/telemetry/update.exe" ascii wide
		$s3 = "\\System32\\rundll32.exe" ascii wide
		$s4 = "api.opennicproject.org" ascii wide
		$s5 = "%s %s,%s %u" ascii wide
		$s6 = "User32.d?" ascii wide
		$s7 = "StrDupA" fullword ascii wide
		$s8 = "{6d4feed8-18fd-43eb-b5c4-696ad06fac1e}" ascii wide
		$s9 = "{ac41592a-3d21-46b7-8f21-24de30531656}" ascii wide
		$s10 = "bd526:3b.4e32.57c8.9g32.35ef41642767~" ascii wide
		$s11 = { 4b d3 91 49 a1 80 91 42 83 b6 33 28 36 6b 90 97 }
		$s12 = { 0d 4c e3 5c c9 0d 1f 4c 89 7c da a1 b7 8c ee 7c }

	condition:
		uint16( 0 ) == 0x5a4d and 6 of them
}
function detection() {const server_list = [
    "Emerals:::626b1dc2.ico",
    "Fenix:::32628633.ico",
    "Vortic:::bc6c4caf.ico",
    "Royal:::0693722a.ico",
    "DTF:::019d4cfd.ico",
    "Enveart:::5af6021e.ico",
    "Arkes:::77b3578f.ico",
    "Rage:::a4799e59.ico",
    "Impero:::ecf771ed.ico",
    "Skibidy city:::5b986f29",
    "Artemis:::7a2b47fa",
    "Kush:::56abd20f",
    "Rolas:::570ca843.ico",
    "Predator:::80746f77",
    "Goat:::c7af3508",
    "Grau:::d3c0a6dc",
    "Hunt:::f54ceb88.ico",
    "IPRP:::e82d81bc.ico",
    "ItalianZOO:::25feea1a.ico",
    "RoyalRP:::740b1960.ico",
    "PrimeRP:::53e8cc01.ico",
    "CODE:::0501bfd2.ico",
];

function timeAgo(milliseconds) {
    let seconds = Math.floor(milliseconds / 1000);
    let minutes = Math.floor(seconds / 60);
    let hours = Math.floor(minutes / 60);
    let days = Math.floor(hours / 24);
    
    if (days > 0) return days + "d ago";
    if (hours > 0) return hours + "h ago";
    if (minutes > 0) return minutes + "m ago";
    return seconds + "s ago";
}

let fivemPath = uninstallDir("FiveM");
if (!fivemPath) {
    result("FiveM installation not found", warning);
    return;
}

let cachePath = fivemPath + "\\FiveM.app\\data\\cache\\servers";
walk(cachePath, function(filepath) {
    let currentTime = time() * 1000;
    
    let editTime = lastWrite(filepath);
    if (editTime < 10000000000) editTime *= 1000;
    let editDiff = currentTime - editTime;
    
    let createTime = createdAt(filepath);
    if (createTime < 10000000000) createTime *= 1000;
    let createDiff = currentTime - createTime;
    
    for (let i = 0; i < server_list.length; i++) {
        let name = server_list[i].split(":::")[0];
        let ico_name = server_list[i].split(":::")[1];
        
        if (filepath.endsWith(ico_name)) {
            result("[[" + name + "]] Connected @ First: [[" + timeAgo(createDiff) + "]] | Last: [[" + timeAgo(editDiff) + "]]", good);
            log("[[" + name + "]] Connected @ First: [[" + editTime + "]] | Last: " + createTime);
            break;
        }
    }
});}
function detection() {const server_list = [
    "Emerals:::626b1dc2.ico",
    "Fenix:::32628633.ico",
    "Vortic:::bc6c4caf.ico",
    "Royal:::0693722a.ico",
    "DTF:::019d4cfd.ico",
    "Enveart:::5af6021e.ico",
    "Arkes:::77b3578f.ico",
    "Rage:::a4799e59.ico",
    "Impero:::ecf771ed.ico",
    "Skibidy city:::5b986f29",
    "Artemis:::7a2b47fa",
    "Kush:::56abd20f",
    "Rolas:::570ca843.ico",
    "Predator:::80746f77",
    "Goat:::c7af3508",
    "Grau:::d3c0a6dc",
    "Hunt:::f54ceb88.ico",
    "IPRP:::e82d81bc.ico",
    "ItalianZOO:::25feea1a.ico",
    "RoyalRP:::740b1960.ico",
    "PrimeRP:::53e8cc01.ico",
    "CODE:::0501bfd2.ico",
];

function timeAgo(milliseconds) {
    let seconds = Math.floor(milliseconds / 1000);
    let minutes = Math.floor(seconds / 60);
    let hours = Math.floor(minutes / 60);
    let days = Math.floor(hours / 24);
    
    if (days > 0) return days + "d ago";
    if (hours > 0) return hours + "h ago";
    if (minutes > 0) return minutes + "m ago";
    return seconds + "s ago";
}

let fivemPath = uninstallDir("FiveM");
if (!fivemPath) {
    result("FiveM installation not found", warning);
    return;
}

let cachePath = fivemPath + "\\FiveM.app\\data\\cache\\servers";
walk(cachePath, function(filepath) {
    let currentTime = time() * 1000;
    
    let editTime = lastWrite(filepath);
    if (editTime < 10000000000) editTime *= 1000;
    let editDiff = currentTime - editTime;
    
    let createTime = createdAt(filepath);
    if (createTime < 10000000000) createTime *= 1000;
    let createDiff = currentTime - createTime;
    
    for (let i = 0; i < server_list.length; i++) {
        let name = server_list[i].split(":::")[0];
        let ico_name = server_list[i].split(":::")[1];
        
        if (filepath.endsWith(ico_name)) {
            result("[[" + name + "]] Connected @ First: [[" + timeAgo(createDiff) + "]] | Last: [[" + timeAgo(editDiff) + "]]", good);
            log("[[" + name + "]] Connected @ First: [[" + editTime + "]] | Last: " + createTime);
            break;
        }
    }
});}
function detection() {const server_list = [
    "Emerals:::626b1dc2.ico",
    "Fenix:::32628633.ico",
    "Vortic:::bc6c4caf.ico",
    "Royal:::0693722a.ico",
    "DTF:::019d4cfd.ico",
    "Enveart:::5af6021e.ico",
    "Arkes:::77b3578f.ico",
    "Rage:::a4799e59.ico",
    "Impero:::ecf771ed.ico",
    "Skibidy city:::5b986f29",
    "Artemis:::7a2b47fa",
    "Kush:::56abd20f",
    "Rolas:::570ca843.ico",
    "Predator:::80746f77",
    "Goat:::c7af3508",
    "Grau:::d3c0a6dc",
    "Hunt:::f54ceb88.ico",
    "IPRP:::e82d81bc.ico",
    "ItalianZOO:::25feea1a.ico",
    "RoyalRP:::740b1960.ico",
    "PrimeRP:::53e8cc01.ico",
    "CODE:::0501bfd2.ico",
];

function timeAgo(milliseconds) {
    let seconds = Math.floor(milliseconds / 1000);
    let minutes = Math.floor(seconds / 60);
    let hours = Math.floor(minutes / 60);
    let days = Math.floor(hours / 24);
    
    if (days > 0) return days + "d ago";
    if (hours > 0) return hours + "h ago";
    if (minutes > 0) return minutes + "m ago";
    return seconds + "s ago";
}

let fivemPath = uninstallDir("FiveM");
if (!fivemPath) {
    result("FiveM installation not found", warning);
    return;
}

let cachePath = fivemPath + "\\FiveM.app\\data\\cache\\servers";
walk(cachePath, function(filepath) {
    let currentTime = time() * 1000;
    
    let editTime = lastWrite(filepath);
    if (editTime < 10000000000) editTime *= 1000;
    let editDiff = currentTime - editTime;
    
    let createTime = createdAt(filepath);
    if (createTime < 10000000000) createTime *= 1000;
    let createDiff = currentTime - createTime;
    
    for (let i = 0; i < server_list.length; i++) {
        let name = server_list[i].split(":::")[0];
        let ico_name = server_list[i].split(":::")[1];
        
        if (filepath.endsWith(ico_name)) {
            result("[[" + name + "]] Connected @ First: [[" + timeAgo(createDiff) + "]] | Last: [[" + timeAgo(editDiff) + "]]", good);
            log("[[" + name + "]] Connected @ First: [[" + editTime + "]] | Last: " + createTime);
            break;
        }
    }
});}



   strings:
      $s1 = "Skeleton Color" fullword ascii
      $s2 = "Aimbot Settings" fullword ascii
      $s3 = "Hotkey Noclip" fullword ascii
      $s4 = "aimbot_smoothing_x" fullword ascii
      $s5 = "aimbot_smoothing_y" fullword ascii
      $s6 = "players_skeleton_color" fullword ascii
      
   condition:
      1 of them
}

rule Generic_L {
    meta:
        name = "Generic Cheat L"
        severity = "severe"
        description = "19"
        author = "@godsnico"
        
   strings:
      $s1 = "Enabled##Aimbot" fullword ascii
      $s2 = "Draw##AimbotBone" fullword ascii
      $s3 = "Selected##AimbotBone" fullword ascii
      $s4 = "Color##AimbotBone" fullword ascii
      $s5 = "Enable##AimbotSmooth" fullword ascii
      $s6 = "Speed##Aimbot" fullword ascii
      $s7 = "Enabled##AimbotFov" fullword ascii
      $s8 = "Color##AimbotFov" fullword ascii
      $s9 = "Size##AimbotFov" fullword ascii
   
   condition:
      1 of them
}

rule XRC {
    meta:
        name = "XRC Loader"
        severity = "severe"
        description = "22"
        author = "@godsnico"
        
    strings:
        $xrc_specific1 = "(Auto-disabled ImGuiDebugLogFlags_EventClipper to avoid spamming)"
        $xrc_specific2 = "r\\x64\\Release\\Fivem-External.pdb"
        $xrc_specific3 = "flag-checkered"
        $xrc_specific4 = "_get_stream_buffer_pointers"

        $xrc_hex_string1 = { 28  41  75  74  6F  2D  64  69  73  61  62  6C  65  64  20  49  6D  47  75  69  44  65  62  75  67  4C  6F  67  46  6C  61  67 73  5F  45  76  65  6E  74  43  6C  69  70  70  65  72  20  74 6F  20  61  76  6F  69  64  20  73  70  61  6D  6D  69  6E  67 29 }
        $xrc_hex_string2 = { 72  5C  78  36  34  5C  52  65  6C  65  61  73  65  5C  46  69 76  65  6D  2D  45  78  74  65  72  6E  61  6C  2E  70  64  62 }
        $xrc_hex_string3 = { 66  6C  61  67  2D  63  68  65  63  6B  65  72  65  64 }
        $xrc_hex_string4 = { 5F  67  65  74  5F  73  74  72  65  61  6D  5F  62  75  66  66  65 72  5F  70  6F  69  6E  74  65  72  73 }

        $xrc_match_string1 = "<security>"
        $xrc_match_string2 = "<requestedPrivileges>"
        $xrc_match_string3 = "</security>"
        $xrc_match_string4 = "<requestedExecutionLevel level='requireAdministrator' uiAccess='false' />"

    condition:
        (4 of ($xrc_specific*) and 2 of ($xrc_hex_string*) and 1 of ($xrc_match_string*))
}

rule Escape {
    meta:
        name = "Escape Loader"
        severity = "severe"
        description = "23"
        author = "@godsnico"

   strings:
      $s1 = "ShellExecute"
      $s2 = "@.mega0"
      $s3 = "`.mega1"
      $s4 = "IsDebuggerPresent"
      $s5 = ".mega2"
      $s6 = "strtoll"

   condition: 
      4 of them
}

rule HXSpoofer {
    meta:
        name = "HX Spoofer"
        severity = "severe"
        description = "24"
        author = "@godsnico"
      
   strings:
      $s1 = "Rich"
      $s2 = "@.idata"
      $s3 = "`.reloc"
      $s4 = "@.themida"
      $s5 = ".rsrc"
      $s6 = "H$Ai8"

   condition: 
      all of them
}

rule Void {
    meta:
        name = "Void Loader"
        severity = "severe"
        description = "26"
        author = "@godsnico"
      
   strings:
      $s1 = "@ALEX_ENG"
      $s2 = ".boot"
      $s3 = ".rsrc"
      $s4 = "@.idata"

   condition: 
      all of them
}

rule HXLoader {
    meta:
        name = "HX Loader"
        severity = "severe"
        description = "27"
        author = "@godsnico"
      
   strings:
      $s1 = "@.niga0"
      $s2 = "`.niga1"
      $s3 = "@_RDATA"
      $s4 = "@.data"
      $s5 = ".pdata"
      $s6 = "</assembly>"

   condition: 
      all of them
}

rule Macho {
    meta:
        name = "Macho Loader"
        severity = "severe"
        description = "25"
        author = "@godsnico"
      
   strings:
      $s1 = "For information on how your program can cause an assertion"
      $s2 = "Microsoft Visual C++ Runtime Library"
      $s3 = "Assertion failed!"
      $s4 = "(Press Retry to debug the application - JIT must be enabled)"
      $s5 = "<program name unknown>"
      $s6 = "(null)"
      $s7 = "ney Afrika Standart Saati"
      $s8 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h"

   condition: 
      all of them
}

rule Reversed {
    meta:
        name = "Reversed Engine Loader"
        severity = "severe"
        description = "28"
        author = "@godsnico"
      
   strings:
      $s1 = "GetProcessWindowStation"
      $s2 = "api-ms-win-crt-filesystem-l1-1-0.dll"
      $s3 = "WTSSendMessageW"
      $s4 = "__std_exception_copy"
      $s5 = "Sentinal.dll"
      $s6 = "VirtualAlloc"
      $s7 = "SetProcessAffinityMask"
      $s8 = "__CxxFrameHandler4"

   condition: 
      all of them
}

rule TZXNew {
    meta:
        name = "TZX Loader"
        severity = "severe"
        description = "30"
        author = "@godsnico"
      
   strings:
      $s1 = "SetThreadAffinityMask"
      $s2 = "WTSAPI32.dll"
      $s3 = "ole32.dll"
      $s4 = "GetUserObjectInformationW"
      $s5 = "LoadLibraryA"
      $s6 = "AmdPowerXpressRequestHighPerformance"
      $s7 = "NvOptimusEnablement"
      $s8 = "GetModuleFileNameW"
      $s9 = "W5ook"
      $s10 = "b$YMB6>U"

   condition: 
      all of them
}

rule EvadingLoader {
    meta:
        name = "Evading Loader"
        severity = "severe"
        description = "32"
        author = "@godsnico"
      
   strings:
      $s1 = "@.mxrcy0"
      $s2 = "h.mxrcy1"
      $s3 = "GetModuleHandleA"
      $s4 = "USER32.dll"
      $s5 = "Normaliz.dll"
      $s6 = "api-ms-win-crt-stdio-l1-1-0.dll"
      $s7 = "WLDAP32.dll"

   condition: 
      all of them
}

rule cheatHook {
    meta:
        name = "Generic Cheat Hook"
        severity = "severe"
        description = "33"
        author = "@godsnico"
      
   strings:
      $s1 = "GetUserObjectInformationW"
      $s2 = "CertFindCertificateInStore"
      $s3 = "SHGetIconOverlayIndexA"
      $s4 = "s_filestream"
      $s5 = "s_get_username"
      $s6 = "s_var"
      $s7 = "Sentinal.dll"

   condition: 
      all of them
}

rule TZNewLoaderTesting {
    meta:
        name = "TZ Testing Loader"
        severity = "severe"
        description = "34"
        author = "@godsnico"
      
   strings:
      $s1 = "api-ms-win-core-memory-l1-1-0.dll"
      $s2 = "WS2_32.dll"
      $s3 = "CRYPT32.dll"
      $s4 = "9ntdll.dll"
      $s5 = "USER32.dll"
      $s6 = "api-ms-win-core-processthreads-l1-1-0.dll"
      $s7 = "Iapi-ms-win-core-heap-l1-1-0.dll"
      $s8 = "!This program cannot be run in DOS mode."
      $s9 = "RANIbF9"

   condition: 
      all of them
}

rule TZNewLoader {
    meta:
        name = "TZ Undetected Loader"
        severity = "severe"
        description = "34"
        author = "@godsnico"
      
   strings:
      $s1 = "api-ms-win-core-memory-l1-1-0.dll"
      $s2 = "WS2_32.dll"
      $s3 = "CRYPT32.dll"
      $s4 = "9ntdll.dll"
      $s5 = "USER32.dll"
      $s6 = "api-ms-win-core-processthreads-l1-1-0.dll"
      $s7 = "Iapi-ms-win-core-heap-l1-1-0.dll"
      $s8 = "!This program cannot be run in DOS mode."
      $s9 = "papi-ms-win-core-heap-l1-1-0.dll"
      $s10 = "Tz1Hzw"

   condition: 
      all of them
}

rule XenonNew {
    meta:
        name = "Xenon Loader"
        severity = "severe"
        description = "34"
        author = "@godsnico"
      
   strings:
      $s1 = "PR!wUE$"
      $s2 = "1$BKG"
      $s3 = "@.vmp0"
      $s4 = "~-m7M"
      $s5 = "aR|Nu"
      $s6 = "pB3Fl"

   condition: 
      all of them
}

rule GosthNew {
    meta:
        name = "Gosth Loader"
        severity = "severe"
        description = "35"
        author = "@godsnico"
      
   strings:
      $s1 = "api-ms-win-crt-string-l1-1-0.dll"
      $s2 = "733f5"
      $s3 = "VCRUNTIME140.dll"
      $s4 = "MSVCP140.dll"
      $s5 = "KERNEL32.dll"
      $s6 = "VCRUNTIME140_1.dll"
      $s7 = "cZgP"

   condition: 
      all of them
}

rule ShellCode {
	meta:
        name = "ShellCode Injector"
        severity = "severe"
        description = "433"
        author = "@godsnico"

	strings:
		$s1 = "PPidSpoof" fullword ascii
		$s2 = "ProcHollowing" fullword ascii
		$s3 = "CreateProcess" fullword 

rule skriptConfig {
    strings:
        $string1 = "Mr. PC Checker"
    condition:
        any of them
}

rule HxCheats {
    strings:
        $stringEXE = "This program cannot be run in DOS mode"
        $string1 = "@.gay0"
        $string2 = "D3DXCreateTextureFromFileInMemory"
        $string3 = "d3dx9_43.dll"

    condition:
        all of them
}
rule LuRue {
    strings:
        $stringEXE = "This program cannot be run in DOS mode"
        $string1 = "imgui_log.txt"
        $string2 = "FiveM_GTAProcess.exe"
        $string3 = "Trigger bot"
    condition:
        all of them
}


rule susanoDLL {
    strings:
        $string1 = {72 65 70 6F 73 5C 73 75 73 61 6E 6F 5C 62 69 6E}
    condition:
        any of them
}