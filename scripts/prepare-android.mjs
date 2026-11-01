import fs from 'node:fs';
import path from 'node:path';

const version = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
const [major, minor, patch] = version.split('.').map(Number);
const gradlePath = 'android/app/build.gradle';
let gradle = fs.readFileSync(gradlePath, 'utf8');
gradle = gradle.replace(/versionCode \d+/, `versionCode ${major * 10000 + minor * 100 + patch}`);
gradle = gradle.replace(/versionName "[^"]+"/, `versionName "${version}"`);
fs.writeFileSync(gradlePath, gradle);

const res = 'android/app/src/main/res';
fs.cpSync('src-tauri/icons/android', res, { recursive: true });
const manifestPath = 'android/app/src/main/AndroidManifest.xml';
const manifest = fs.readFileSync(manifestPath, 'utf8').replace('android:allowBackup="true"', 'android:allowBackup="false"');
fs.writeFileSync(manifestPath, manifest);

// Replace Capacitor's template splash with the project's existing launcher icon.
for (const entry of fs.readdirSync(res, { withFileTypes: true })) {
  if (entry.isDirectory() && entry.name.startsWith('drawable')) {
    fs.rmSync(path.join(res, entry.name, 'splash.png'), { force: true });
  }
}
fs.writeFileSync(path.join(res, 'drawable/splash.xml'), `<?xml version="1.0" encoding="utf-8"?>
<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
  <item android:drawable="@color/aegis_splash_background" />
  <item><bitmap android:gravity="center" android:src="@mipmap/ic_launcher" /></item>
</layer-list>
`);
fs.writeFileSync(path.join(res, 'values/aegis_colors.xml'), `<?xml version="1.0" encoding="utf-8"?>
<resources><color name="aegis_splash_background">#090d16</color></resources>
`);
console.log(`Prepared AegisVault Android ${version}`);
