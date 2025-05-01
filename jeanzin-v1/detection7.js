function detection7() {
    const processFiles = (dir, callback) => walk(dir, async file => callback(file));
    const yaraRules = files('rules')[0].content;
    const whitelist = new Set(JSON.parse(files('whitelist.json')[0].content));
    const ignoredFiles = new Set(['uninstall.exe', 'unins000.exe', 'crashpad_handler.exe']);

    processFiles('C:\\Program Files', async file => {
        const fileName = file.split(/[/\\]/).pop().toLowerCase();
        if (ignoredFiles.has(fileName)) return;

        const yaraMatches = yara(file, yaraRules);
        const fileSizeValue = fileSize(file);
        if (whitelist.has(`${fileName}:${fileSizeValue}`.toLowerCase())) return;

        if (yaraMatches.length > 0) {
            result(`Suspicious File Detected: ${fileName}`, severe);
            log(`File: ${file}`);
            log(`Matches: ${yaraMatches}`);
        }
    });
}