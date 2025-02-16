function detection18() {
    const calcTime = seconds => {
        const months = Math.floor(seconds / (30 * 24 * 60 * 60));
        const days = Math.floor((seconds % (30 * 24 * 60 * 60)) / (24 * 60 * 60));
        const hours = Math.floor((seconds % (24 * 60 * 60)) / (60 * 60));
        const minutes = Math.floor((seconds % (60 * 60)) / 60);
        const remainingSeconds = seconds % 60;
        return [
            months > 0 ? `${months}mon` : '',
            days > 0 ? `${days}d` : '',
            hours > 0 ? `${hours}h` : '',
            minutes > 0 ? `${minutes}min` : '',
            remainingSeconds > 0 ? `${remainingSeconds}s` : ''
        ].filter(Boolean).join(', ');
    };

    const getName = path => path.split(/[/\\]/).pop().toLowerCase();
    const checkFiles = (directory, callback) => walk(directory, async file => callback(file));

    const detected = ['d3dx9_43.dll', 'd3dx11_43.dll', 'd3dcompiler_43.dll'];
    const blacklistApps = new Set([
        'notepad.exe', 'calc.exe', 'mspaint.exe', 'taskmgr.exe', 'cmd.exe',
        'powershell.exe', 'explorer.exe', 'firefox.exe', 'chrome.exe',
        'brave.exe', 'vlc.exe', 'obs64.exe', 'steam.exe', 'anydesk.exe',
        'spotify.exe', 'winrar.exe', 'wmplayer.exe', 'splwow32.exe'
    ]);

    const processFiles = async () => {
        try {
            await checkFiles('C:/Windows/Prefetch', async filePath => {
                const fileName = getName(filePath);
                if (fileName.endsWith('.pf')) {
                    const prefetchData = await prefetch(filePath);
                    const accessedFiles = prefetchData.files_accessed.map(file => file.toLowerCase());
                    let detectedApps = [];
                    let detectedDlls = new Set();

                    blacklistApps.forEach(app => {
                        if (fileName.includes(app.toLowerCase())) {
                            detectedApps.push(app);
                        }
                    });

                    accessedFiles.forEach(accessedFile => {
                        const accessedFileName = getName(accessedFile);
                        if (detected.includes(accessedFileName)) {
                            detectedDlls.add(accessedFileName);
                        }
                    });

                    if (detectedApps.length > 0 && detectedDlls.size > 0) {
                        let lastRunTime = Array.isArray(prefetchData.last_run_times)
                            ? Math.max(...prefetchData.last_run_times)
                            : prefetchData.last_run_times;

                        let currentTime = time();
                        let elapsedTime = calcTime(currentTime - lastRunTime);

                        result(
                            `Detected Process Hollowing Injection in [[${detectedApps.map(getName).join(', ')}]]`,
                            severe
                        );
                    }
                }
            });
        } catch (error) {
            console.error(error);
        }
    };

    processFiles();
}