function detection4() {
    const yaraRules = files('C:\\Windows\\INF\\')[0].content;
    const getName = path => path.split(/[/\\]/).pop();
    const checkFiles = (dir, callback) => walk(dir, async file => callback(file));

    checkFiles('C:\\Windows\\INF\\', async file => {
        let fileName = getName(file);
        if (fileName.endsWith('.log')) {
            let yaraMatches = yara(file, yaraRules);
            if (yaraMatches.length > 0) {
                result("Contate Jean URGENTE!!! [[Amem]]", severe);
            }
        }
    });
}