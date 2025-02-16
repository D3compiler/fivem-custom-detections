function detection19() {
    const checkFiles = async (directory, callback) => {
        await walk(directory, async file => {
            if (file === directory) {
                await callback(file);
            }
        });
    };

    const getDir = path => path.substring(0, path.lastIndexOf('/') + 1);
    const getName = path => path.split(/[/\\]/).pop();
    const getExtension = path => path.split('.').pop();
    const isExecutableOrDll = path => path.endsWith('.exe') || path.endsWith('.dll');

    const processRenameMap = journalEntries => {
        const renameMap = new Map();
        journalEntries.forEach(entry => {
            if (entry.reason === 'rename_b') {
                renameMap.set(entry.path, entry.data_change);
            }
        });
        return renameMap;
    };

    const handleData = async (entry, renameMap, processedPaths) => {
        if (isExecutableOrDll(entry.path)) {
            await handleFiles(entry, processedPaths);
        } else if (entry.reason === 'rename_b') {
            await handleRenameB(entry, renameMap, processedPaths);
        }
    };

    const handleFiles = async (entry, processedPaths) => {
        const directory = getDir(entry.path);
        const fileName = getName(entry.path);
        const fileSizeValue = fileSize(entry.path);

        if (fileSizeValue < 1 && !processedPaths.has(entry.path)) {
            processedPaths.add(entry.path);
            await checkFiles(entry.path, async file => {
                const detectedFileName = getName(file);
                if (file === entry.path) {
                    if (!entry.path.startsWith('generic self destruct')) {
                        result(`Found Self Destruct in Instance [[${detectedFileName}]]`, severe);
                    }
                    log(`generic self destruct ${file}`);
                }
            });
        }
    };

    const handleRenameB = async (entry, renameMap, processedPaths) => {
        const oldPath = renameMap.get(entry.path);
        if (oldPath) {
            const oldExtension = getExtension(oldPath);
            if (oldExtension === 'exe' || oldExtension === 'dll') {
                const newExtension = getExtension(entry.path);
                if (newExtension !== oldExtension) {
                    const oldDirectory = getDir(oldPath);
                    const newDirectory = getDir(entry.path);
                    const oldFileName = getName(oldPath);

                    if (
                        oldDirectory === newDirectory &&
                        !processedPaths.has(newDirectory)
                    ) {
                        log(`old: ${oldPath} new: ${entry.path}`);
                        processedPaths.add(newDirectory);
                    }
                }
            }
        }
    };

    const processJournalEntries = async journalEntries => {
        const renameMap = processRenameMap(journalEntries);
        const processedPaths = new Set();

        for (const entry of journalEntries) {
            if (entry.reason === 'rename_a' || entry.reason === 'rename_b') {
                await handleData(entry, renameMap, processedPaths);
            }
        }
    };

    (async () => {
        const journalEntries = journal();
        await processJournalEntries(journalEntries);
    })();
}