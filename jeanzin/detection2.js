function detection2() {
    const yaraRules = files('.')[0].content;
    const getName = (path) => path.split(/[/\\]/).pop();
    const getFolder = (path) => {
        let parts = path.replace(/[/\\][^/\\]*$/, '').split(/[/\\]/);
        let lastPart = parts.pop();
        if (lastPart.startsWith('special_') || lastPart.startsWith('tmp_')) return null;
        let match = lastPart.match(/^[^_]+_([^_]+)_/);
        return match ? match[1].toLowerCase() : null;
    };
    const checkFiles = (dir, callback) => {
        walk(dir, async (file) => {
            await callback(file);
        });
    };
    const processedResults = new Set();
}