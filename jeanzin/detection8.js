function detection8() {
    const journalEntries = journal();
    const loggedPaths = new Set();
    const dllBlacklist = new Set([
        'msedge.dll', 'wmiapsrv.dll', 'unsecapp.dll', 'wbemtest.dll', 'winmgmt.dll',
        'splwow32.dll', 'wmiadap.dll', 'wmiprvse.dll', 'wmic.dll', 'mofcomp.dll',
        'chrome.dll', 'vlc.dll'
    ]);
    const processedDlls = new Set();

    const getName = path => path.split(/[/\\]/).pop().toLowerCase();
    const isDir = path => path.endsWith('/');
    const calcTime = seconds => {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const remainingSeconds = seconds % 60;
        return [
            hours > 0 ? `${hours}h` : '',
            minutes > 0 ? `${minutes}m` : '',
            remainingSeconds > 0 ? `${remainingSeconds}s` : ''
        ].filter(Boolean).join(', ');
    };

    const paths = [
        'C:/Program Files/', 
        'C:/Program Files (x86)/Microsoft/EdgeCore/',
        'C:/Program Files (x86)/Microsoft/Edge/Application/',
        'C:/Windows/System32/wbem/',
        'C:/Program Files (x86)/VideoLAN/VLC/'
    ];

    const ignorePaths = [
        '/Microsoft OneDrive/', '/Windows.old/', '/AppData/Local/Temp/',
        '/gitkraken/', '/Spotify/', '/League of Legends/', '/Rollback/'
    ];

    const igPath = path => ignorePaths.some(ignored => path.toLowerCase().includes(ignored.toLowerCase()));
    const isExactPath = path => paths.includes(path);

    journalEntries.forEach(entry => {
        const entryPath = entry.fullPath.toLowerCase();
        if (igPath(entryPath)) return;

        if (!entryPath.endsWith('.dll')) {
            const elapsedTime = time() - entry.timestamp;
            if (elapsedTime > 86400) return; // Ignore entries older than a day
        }

        if (isDir(entryPath)) {
            const dirName = entryPath.substring(0, entryPath.lastIndexOf('/'));
            const fileName = getName(entryPath);

            if (entryPath.endsWith('.dll')) {
                if (processedDlls.has(fileName)) return;
                processedDlls.add(fileName);

                if (dllBlacklist.has(fileName) && isExactPath(dirName)) {
                    result('Generic Bypass at Skript.gg Confirmed', severe);
                }
            }
        }
    });
}