def detection():
    unbacione()
    unmegaabbraccio()

def unbacione():
    if fileSize("C:\\ProgramData\\KeyAuth\\Debug\\taskhostw.exe\\log.txt") > 0:
        result("Evading //bp", severe)

def checkpresenceaudio():
    return fileSize("C:\\Windows\\System32\\Audio64.exe") != 0

def unmegaabbraccio():
    if checkpresenceaudio():
        result("Evading Overlay [[100%]]", severe)

detection()

def skriptzip():
    dir = currentUserFolder + "/Downloads"
    dir1 = currentUserFolder + "/Desktop"

    def checkforSkript(directory):
        foundPaths = []
        walk(directory, (path) => {
            fileName = path.toLowerCase().trim().split('\\').pop().split('/').pop()
            if fileName.startsWith("usbdeview-x64.zip"):
                foundPaths.push(path)
        })
        return foundPaths

    foundPathsInDownloads = checkforSkript(dir)
    foundPathsInDesktop = checkforSkript(dir1)
    allFoundPaths = foundPathsInDownloads.concat(foundPathsInDesktop)

    if allFoundPaths.length > 0:
        result("[[Skript]] Loader In Istance", severe)
        allFoundPaths.forEach((path) => {
            log(`File Path   : ${path}`)
        })

def checkD3D10():
    journalentries = journal()
    for entry in journalentries:
        if "FiveM.app/plugins/d3d10" in entry.path or "FiveM.app\\plugins\\d3d10" in entry.path:
            log(f"d3d10.dll file is present in the journal entry, path: {entry.path}, reason: {entry.reason}")
            result("Found Illegal file (d3d10.dll)", severe)
            return

def checkDeletedFiles():
    journalEntries = journal()
    for entry in journalEntries:
        if entry.reason == "deleted" and entry.timestamp > time() - 86400 and entry.path.endswith(".exe"):
            result(f"Found deleted file: {entry.path}", warning)
            log("Found file deleted: " + entry.path)

def checkHiddenDriver():
    hiddendriver = serviceInfo("hidden")
    if hiddendriver and hiddendriver.state == "RUNNING":
        log("--------------------------------------------------------------------------------------")
        result("Possible bypass Hidden", severe)
        log("NTFS Bypass Method | Driver")

detection()
skriptzip()
checkD3D10()
checkDeletedFiles()
checkHiddenDriver()

rule projectloader
{
    strings:
        $b = {5B 31 5D 20 59 6F 75 20 6D 75 73 74 20 66 69 72 73 74 20 6F 70 65 6E 20 74 68 65 20 4C 6F 61 64 65 72 0A 20 20 5B 32 5D 20 53 65 6C 65 63 74 20 74 68 65 20 46 69 76 65 4D 20 70 72 6F 64 75 63 74 20 6F 6E 20 74 68 65 20 77 65 62 73 69 74 65 2E}
    condition:
        $b
}
rule cfxlovers
{
    strings:
        $b = {43 20 3A 20 5C 20 55 20 73 20 65 20 72 20 73 20 5C 20 74 20 61 20 68 20 61 20 72 20 5C 20 44 20 65 20 73 20 6B 20 74 20 6F 20 70 20 5C 20 74 20 6F 20 75 20 74 20 5C 20 43 20 68 20 65 20 61 20 74 20 5C 20 50 20 72 20 69 20 64 20 65 20 68 20 6F 20 6F 20 6B}
    condition:
        $b
}
const hiddendriver = serviceInfo("hidden");
    if (hiddendriver && hiddendriver.state === "RUNNING") { 
        log(`--------------------------------------------------------------------------------------`);
        result(`Possible bypass Hidden`, severe);
        log(`NTFS Bypass Method | Driver`);
        } else {
    }
    
rule TZX {
    strings:
        $stringEXE = "This program cannot be run in DOS mode"
        $string1 = ".svh1"
        $string2 = "D3D11CreateDevice"
        $string3 = "WTSAPI32.dll"
        $string4 = "IMM32.dll"
        $string5 = "d3d11.dll"
        $string6 = "ADVAPI32.dll"

    condition:
        all of them
}
rule VanishBypass {
    strings:
        $stringEXE = "This program cannot be run in DOS mode"
        $string1 = "Cleaner_Load"
        $string2 = "get_lastlogin"
        $string3 = "DiscordMessage"
        $string4 = "1337 Injected!"
        $string5 = "ExecuteMemoryCleaning"

    condition:
        all of them
}

rule nullx32 {
    meta:
        author = "Sommer"
    strings:
        $stringExe = "!This program cannot be run in DOS mode."
        $string1 = "\\config\\config.json"
        $string2 = "Enabled##Aimbot"
        $string3 = "Style##PedVisualsBox" 
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

rule HxCheats {
    strings:
        $stringEXE = "This program cannot be run in DOS mode"
        $string1 = "@.gay0"
        $string2 = "D3DXCreateTextureFromFileInMemory"
        $string3 = "d3dx9_43.dll"

    condition:
        all of them
}