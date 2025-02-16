function detection() {
  const allPids = processIDs('*');
  const filteredPids = allPids.filter(pid => pid !== 0 && pid !== 4);

  const stringPatterns = [
    'Godmode', 'Aimbot', 'keyauth', 'KeyAuth', 'Snaplines',
    'd3d11hook.cpp', 'imgui.cpp', 'imgui_widgets.cpp', 'imgui_tables.cpp',
    'imgui_draw.cpp', 'imstb_truetype.h', 'imgui_internal.h',
    'Save config', 'Fivem Bypass', 'Fivem Cheat',
    'imgui_impl_dx11', 'imgui_impl_win32', 'imgui_impl_dx9',
    '@.themida', '@.winlice', 'Check if Invisible',
    'Show Fov', 'Fov Color', 'Target NPC', 'Aim Settings'
  ];

  function checkProcessForStrings(pid) {
    try {
      const foundStrings = strings([pid], [stringPatterns], true);
      if (foundStrings && foundStrings.length > 0) {
        return {
          pid: pid,
          foundStrings: foundStrings
        };
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  const foundPids = [];
  
  for (const pid of filteredPids) {
    const result = checkProcessForStrings(pid);
    if (result !== null) {
      foundPids.push(result);
    }
  }

  for (const test of foundPids) {
    const info = processInfo(test.pid);
    if (info) {
      const appName = info.name;
      if (appName.startsWith("echo-")) {
        continue;
      }
      result(`Detected Possible Generic Loader [[${appName}]]`, severe);
      log(`Detected strings in ${appName}: ${test.foundStrings}`);
    }
  }
}