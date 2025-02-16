EVADING:


function detection() {function unbacione() {
    if (fileSize("C:\\ProgramData\\KeyAuth\\Debug\\taskhostw.exe\\log.txt") > 0) {
        result("Evading //bp", severe);
    }
}


function checkpresenceaudio() {
    if (fileSize("C:\\Windows\\System32\\Audio64.exe") == 0) {
        return false;
    }
    return true;
}
function unmegaabbraccio() {
if (checkpresenceaudio()) {
    result(`Evading Overlay [[100%]]`, severe);
}
}
unbacione();
unmegaabbraccio();}
function detection() {function unbacione() {
    if (fileSize("C:\\ProgramData\\KeyAuth\\Debug\\taskhostw.exe\\log.txt") > 0) {
        result("Evading //bp", severe);
    }
}


function checkpresenceaudio() {
    if (fileSize("C:\\Windows\\System32\\Audio64.exe") == 0) {
        return false;
    }
    return true;
}
function unmegaabbraccio() {
if (checkpresenceaudio()) {
    result(`Evading Overlay [[100%]]`, severe);
}
}
unbacione();
unmegaabbraccio();}
function unbacione() {
    if (fileSize("C:\\ProgramData\\KeyAuth\\Debug\\taskhostw.exe\\log.txt") > 0) {
        result("Evading //bp", severe);
    }
}


function checkpresenceaudio() {
    if (fileSize("C:\\Windows\\System32\\Audio64.exe") == 0) {
        return false;
    }
    return true;
}
function unmegaabbraccio() {
if (checkpresenceaudio()) {
    result(`Evading Overlay [[100%]]`, severe);
}
}
unbacione();

unmegaabbraccio();


XERECAO: 

function checkxrc() {
    let filepath = "C:\\Program Files\\LGHUB\\system_tray";

    walk(filepath, (path) => {
        if (path.toLowerCase().endsWith(".exe")) {
            let checkxrc = yara(path, entrpy);
            let filename = path.split('\\').pop();
            
            log(filename);
            checkxrc.forEach(match => {
                result(`[[XRC]] Loader [[BL]]`, severe);
                log(`-------------- | XRC Loader | --------------`);
                log(`File Found    : ` + path);
            });
        }
    });
}

checkxrc();


ENTROPY:


const entrpy = `import "math"
rule entropy_check {
    condition:
        math.entropy(0, filesize) >= 7.0
};


AI FOLDER: 

let dirs = subDirs(currentUserFolder + "/AppData/Local/FiveM/FiveM.app/citizen/common/data")
let current_time = time()
// Check if a ai folder is present
log(`AI Folder checks started at ${current_time}`)
let is_present = false
dirs.forEach(folder =>{
    log(`Testing ${folder}`)
    if (folder.includes("ai")){
        is_present = true
        return
    }
    if (is_present){
        result(`Found Illegal Modification (AI Folder)`, severe);
        log(`AI folder is present on the PC`)
        return
    }
    log(`AI folder not found`)
})
log(`------------------`)


let jrnl = journal()

jrnl.forEach(entry =>{
    if (entry.path.includes("common/data/ai")){
        result(`Found Illegal Modification (AI Folder) on IMPERORP not BAN`, severe);
        let seconds = Math.round((current_time - entry.timestamp))
        log(`AI folder has been modified ${seconds} seconds ago.`)
        log(`Debug: ${entry.path}, ${entry.reason}`)
        log(`---------`)
        return
    }
    
})

log("Ai folder check finished!")


YARA:


let journalEntries = journal();
for (let i = 0; i < journalEntries.length; i++) {
    let entry = journalEntries[i];
    if (entry.reason === "deleted" && entry.timestamp > time() - 86400 && entry.path.endsWith(".exe")) {
        result(`Found deleted file: ${entry.path}`, warning);
        log("Found file deleted: " + entry.path);
    }
}


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
