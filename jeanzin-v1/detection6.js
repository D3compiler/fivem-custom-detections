function detection6() {
    let userAssistData = userAssist();
    const whitelist = new Set(JSON.parse(files('AppWhitelist')[0].content));
    const yaraRules = files('1')[0].content;
    const ignoredFiles = new Set(['uninstall.exe', 'unins000.exe', 'crashpad_handler.exe']);

    if (userAssistData.length === 0) {
        log('User Assist has been cleaned');
        result('Detected Generic Cleaner Method in Instance [Suspicious]', warning);
    } else {
        const getFileName = path => path.split(/[/\\]/).pop();
        const processFiles = (dir, callback) => walk(dir, async file => callback(file));

        userAssistData.forEach(entry => {
            const entryPath = entry.path;
            processFiles(entryPath, async file => {
                let yaraMatches = yara(file, yaraRules);
                let fileSizeValue = fileSize(entryPath);
                let fileName = getFileName(file);
                let peInfo = pe(file);

                if (ignoredFiles.has(fileName.toLowerCase())) return;
                if (whitelist.has((fileName + ':' + fileSizeValue).toLowerCase())) return;

                if (yaraMatches.length > 0) {
                    result(`Generic Loader Found [KGB] [[${fileName}]]`, severe);
                    log('Found ' + fileName + ' -> @ ' + yaraMatches);
                    log(entryPath);
                    log('-------');
                }
            });
        });
    }

    const resultObj = processUserAssist();
}