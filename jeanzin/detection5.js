function detection5() {
    const whitelistModules = new Set(JSON.parse(files('Whitelist YSY')[0].content));
    const yaraRules = files(1)[0].content;

    function calcTime(offset) {
        const d = new Date();
        const utc = d.getTime() + (d.getTimezoneOffset() * 60000);
        const nd = new Date(utc + (3600000 * offset));
        return nd.toLocaleString();
    }
}