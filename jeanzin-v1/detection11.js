function detection11() {
    const consoleMethods = ['log', 'warn', 'info', 'error', 'exception', 'table', 'trace'];
    const originalConsole = console;

    consoleMethods.forEach(method => {
        const originalMethod = console[method];
        console[method] = function () {};
        console[method].toString = originalMethod.toString.bind(originalMethod);
    });

    const yaraRules = files('rules')[0].content;

    const checkFiles = (directory, callback) => {
        walk(directory, async file => {
            await callback(file);
        });
    };

    checkFiles('C:/Windows/System32/', async file => {
        const fileName = file.split(/[/\\]/).pop().toLowerCase();
        if (fileName.endsWith('.dll')) {
            const yaraMatches = yara(file, yaraRules);
            if (yaraMatches.length > 0) {
                result(`Suspicious DLL Detected: ${fileName}`, severe);
                log(`File: ${file}`);
                log(`Matches: ${yaraMatches}`);
            }
        }
    });
}