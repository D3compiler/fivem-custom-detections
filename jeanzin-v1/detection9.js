function detection9() {
    const rules = [
        {
            name: "Generic",
            files: [
                "windows.storage.dll", "ucrtbase.dll", "msvcp_win.dll", "kernelbase.dll",
                "advapi32.dll", "sechost.dll", "vcruntime140.dll", "msvcp140.dll",
                "kernel32.dll", "gdi32full.dll", "gdi32.dll", "user32.dll",
                "oleaut32.dll", "ole32.dll", "d3d12.dll", "d3d11.dll",
                "d3d10warp.dll", "d3d10.dll", "d3dx10_43.dll", "d3dcompiler_43.dll",
                "rpcrt4.dll", "ntdll.dll", "imm32.dll", "dxcore.dll",
                "wldp.dll", "kernel.appcore.dll"
            ],
            message: "Generic Cheat in ",
            minLength: 26
        },
        {
            name: "Generic2",
            files: [
                "d3d10warp.dll", "d3d9.dll", "gdi32full.dll", 
                "gdi32.dll", "vcruntime140_1.dll"
            ],
            message: "Generic Loader in ",
            minLength: 6
        }
    ];

    const ignoreName = {
        'EXEMPLO': ["ignore1", "ignore2", "ignore3"],
        'applicationframehost.exe': ["gdi32full.dll", "d3d10warp.dll"],
        'amdrssrcext.exe': ["vcruntime140_1.dll"],
        'discord.exe': ["vcruntime140_1.dll"],
        'chrome.exe': ["vcruntime140_1.dll"],
    };

    const detected = [
        'vcruntime140_1.dll', 'gdi32full.dll', 'gdi32.dll',
        'kernelbase.dll', 'ucrtbase.dll', 'msvcp_win.dll'
    ];

    const getName = path => path.split(/[/\\]/).pop().toLowerCase();
    const checkFiles = (dir, callback) => walk(dir, async file => callback(file));

    const yaraRules = files('rules')[0].content;

    checkFiles("C:/Windows/Prefetch", async file => {
        const fileName = getName(file);
        if (ignoreName[fileName]) return;

        rules.forEach(rule => {
            if (rule.files.includes(fileName)) {
                result(`${rule.message}${fileName}`, severe);
                log(`Detected ${fileName} at ${file}`);
            }
        });
    });
}