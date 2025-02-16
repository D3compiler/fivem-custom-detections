function detection1() {
    const consoleLog = console.log;
    const methods = ['log', 'warn', 'info', 'error', 'exception', 'table', 'trace'];
    
    for (let i = 0; i < methods.length; i++) {
        const method = methods[i];
        console[method] = function() {};
    }
    
    console.log = function() {};
    
    const result = "Console methods have been disabled.";
    consoleLog(result);
    return result;
}