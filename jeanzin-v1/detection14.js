function detection15() {
    const yaraRules = files('RPF Detection')[0].content;
    const yaraCheats = files(1)[0].content;
    let drivesList = drives();
    let defendService = serviceInfo('windefend');
    let vgkService = serviceInfo('vgk');

    const getName = path => path.split(/[/\\]/).pop();
    const checkFiles = (directory, callback) => walk(directory, async file => callback(file));

    function checkService(service, serviceName, resultMessage) {
        if (Object.keys(service).length > 0 && service.state !== 'running') {
            log(`${serviceName} service is not running`);
            result(`${resultMessage} has been disabled in System`, severe);
        } else if (Object.keys(service).length === 0 && serviceName === 'vgk') {
            log(`${serviceName} service is not found`);
            result(`${resultMessage} service is missing`, severe);
        }
    }

    checkService(vgkService, 'vgk', 'VGK Service');
    checkService(defendService, 'Defend', 'Windows Defender');

    const findDir = (paths, fileName, drives) => {
        let foundPath = '';
        paths.forEach(path => {
            walk(path, async file => {
                if (file.includes(fileName)) {
                    foundPath = path;
                    return true;
                }
            });
        });

        if (!foundPath) {
            drives.forEach(drive => {
                let subDirsList = subDirs(drive);
                subDirsList.forEach(subDir => {
                    walk(`${drive}/${subDir}`, async file => {
                        if (file.includes(fileName)) {
                            foundPath = file;
                            return true;
                        }
                    });
                    if (foundPath) return true;
                });
            });
        }

        return { found: !!foundPath, path: foundPath || '' };
    };

    let fivemProcessId = processIDs('FiveM_GTAProcess');
    let fivemDetails;

    if (fivemProcessId.length > 0) {
        const fivemInfo = processInfo(fivemProcessId[0]);
        let exePath = fivemInfo.exe;
        let fvmPath = exePath.replace(/\\data\\cache\\subprocess\\FiveM_b[^\\]+_GTAProcess\.exe/, '');
        fivemDetails = { found: true, path: fvmPath };
    } else {
        fivemDetails = findDir(
            [
                `${currentUserFolder}/AppData/Local/FiveM/`,
                `${currentUserFolder}/AppData/Roaming/FiveM/`,
                `${currentUserFolder}/Documents/FiveM/`
            ],
            'FiveM.exe',
            drivesList
        );
    }

    const gtaDetails = findDir(
        [
            'C:/Program Files/Rockstar Games/Grand Theft Auto V',
            'C:/Program Files/Epic Games/GTAV',
            uninstallDir('Grand Theft Auto V')
        ],
        'x64w.rpf',
        drivesList
    );

    let projectLoaderDirs = subDirs(`${currentUserFolder}/AppData/Local/ProjectLoader`);
    projectLoaderDirs.forEach(dir => {
        if (dir.includes('loader.exe')) {
            log(`Project Loader detected in ${dir}`);
            result('Project Loader has been Detected.', severe);
        }
    });

    let keyAuthDirs = subDirs('C:/KeyAuth/');
    let isKeyAuthPresent = keyAuthDirs.some(dir => dir.includes('keyauth.dll'));

    if (isKeyAuthPresent) {
        log('KeyAuth DLL detected');
        result('KeyAuth DLL has been detected.', severe);
    }
}