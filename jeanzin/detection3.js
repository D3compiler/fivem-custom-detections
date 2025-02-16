function detection3() {
    const whitelistFile = files('whitelist')[0];
    if (whitelistFile) {
        const whitelistData = JSON.parse(whitelistFile.content);
        if (whitelistData && Array.isArray(whitelistData.modules)) {
            const whitelistModules = new Set(whitelistData.modules.map(module => module.toLowerCase().trim()));
            const sysmain_pid = serviceInfo('sysmain').pid;
            if (sysmain_pid) {
                const processInfoData = processInfo(sysmain_pid);
                const detectedModules = [];
                processInfoData.modules.forEach(module => {
                    const moduleLower = module.toLowerCase().trim();
                    if (moduleLower.includes('winsxs') || moduleLower.includes('windowsapps')) return;
                    if (moduleLower.endsWith('.db') || moduleLower.endsWith('.nls') || moduleLower.endsWith('.clb') || moduleLower.endsWith('.mui') || moduleLower.endsWith('.pfpre')) return;
                    if (moduleLower.includes('.nls') || moduleLower.includes('.mkd')) return;
                    if (whitelistModules.has(moduleLower)) return;
                    else detectedModules.push(moduleLower);
                });
                if (detectedModules.length > 0) {
                    result("Detected Fat Bypass in Use", severe);
                    detectedModules.forEach(module => {
                        log('Detected this: ' + module);
                    });
                } else {
                    log('brand new me');
                }
            } else {
                log('Need Restaure PC');
            }
        }
    }
}