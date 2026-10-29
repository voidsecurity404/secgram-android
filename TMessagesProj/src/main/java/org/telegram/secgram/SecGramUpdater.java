/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.BuildConfig;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.Utilities;
import org.telegram.ui.ActionBar.AlertDialog;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;

// Checks GitHub Releases of SecGram for Android and installs updates.
//
// Only the SecGram repository is contacted, over HTTPS. Before the
// installer is opened the downloaded APK must be signed with the same key
// as the installed app; Android itself enforces this again on install.
public final class SecGramUpdater {

    private static final String REPO = "voidsecurity404/secgram-android";
    private static final String API = "https://api.github.com/repos/" + REPO + "/releases/latest";
    private static final long CHECK_INTERVAL = 12L * 60 * 60 * 1000;

    private static boolean checking;

    private SecGramUpdater() {
    }

    public static final class Release {
        public String version;
        public String notes;
        public String apkUrl;
        public long apkSize;
    }

    public static String currentVersion() {
        return BuildConfig.SECGRAM_VERSION;
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("secgram", Context.MODE_PRIVATE);
    }

    // 1.2.10 > 1.2.9, a missing part counts as 0.
    static int compare(String a, String b) {
        final String[] x = a.replaceFirst("^v", "").split("[.-]");
        final String[] y = b.replaceFirst("^v", "").split("[.-]");
        for (int i = 0; i < Math.max(x.length, y.length); ++i) {
            final int p = i < x.length ? parse(x[i]) : 0;
            final int q = i < y.length ? parse(y[i]) : 0;
            if (p != q) {
                return Integer.compare(p, q);
            }
        }
        return 0;
    }

    private static int parse(String part) {
        try {
            return Integer.parseInt(part.replaceAll("[^0-9]", ""));
        } catch (Exception e) {
            return 0;
        }
    }

    private static Release fetchLatest() throws Exception {
        final HttpURLConnection connection = (HttpURLConnection) new URL(API).openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(20000);
        connection.setRequestProperty("Accept", "application/vnd.github+json");
        connection.setRequestProperty("User-Agent", "SecGram-Android/" + currentVersion());
        try (InputStream in = connection.getInputStream()) {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            final byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0 && out.size() < 1024 * 1024) {
                out.write(buffer, 0, read);
            }
            final JSONObject json = new JSONObject(out.toString("UTF-8"));
            final Release release = new Release();
            release.version = json.optString("tag_name", "").replaceFirst("^v", "");
            release.notes = json.optString("body", "");
            final JSONArray assets = json.optJSONArray("assets");
            if (assets != null) {
                for (int i = 0; i < assets.length(); ++i) {
                    final JSONObject asset = assets.getJSONObject(i);
                    final String url = asset.optString("browser_download_url", "");
                    // Only files of this repository's releases are accepted.
                    if (url.endsWith(".apk") && url.startsWith("https://github.com/" + REPO + "/releases/download/")) {
                        release.apkUrl = url;
                        release.apkSize = asset.optLong("size", 0);
                        break;
                    }
                }
            }
            return release;
        } finally {
            connection.disconnect();
        }
    }

    // Called on start, at most every 12 hours.
    public static void checkAutomatically(Activity activity) {
        final long last = prefs().getLong("update_check_time", 0);
        if (System.currentTimeMillis() - last < CHECK_INTERVAL) {
            return;
        }
        prefs().edit().putLong("update_check_time", System.currentTimeMillis()).apply();
        check(activity, false);
    }

    public static void check(Activity activity, boolean manual) {
        if (checking || activity == null) {
            return;
        }
        checking = true;
        Utilities.globalQueue.postRunnable(() -> {
            Release release = null;
            String error = null;
            try {
                release = fetchLatest();
            } catch (Exception e) {
                error = e.getMessage();
            }
            final Release result = release;
            final String failure = error;
            AndroidUtilities.runOnUIThread(() -> {
                checking = false;
                if (result == null || result.version.isEmpty()) {
                    if (manual) {
                        Toast.makeText(activity, "Не удалось проверить обновления: " + failure, Toast.LENGTH_LONG).show();
                    }
                    return;
                }
                final boolean newer = compare(result.version, currentVersion()) > 0;
                final boolean skipped = result.version.equals(prefs().getString("update_skipped", ""));
                if (!newer || result.apkUrl == null) {
                    if (manual) {
                        Toast.makeText(activity, "У вас последняя версия SecGram " + currentVersion(), Toast.LENGTH_LONG).show();
                    }
                    return;
                } else if (skipped && !manual) {
                    return;
                }
                showUpdate(activity, result);
            });
        });
    }

    private static void showUpdate(Activity activity, Release release) {
        final StringBuilder text = new StringBuilder();
        text.append("Доступна новая версия SecGram ").append(release.version)
            .append(" (у вас ").append(currentVersion()).append(").");
        if (release.apkSize > 0) {
            text.append("\nРазмер: ").append(AndroidUtilities.formatFileSize(release.apkSize)).append('.');
        }
        if (!release.notes.trim().isEmpty()) {
            final String notes = release.notes.trim();
            text.append("\n\nЧто нового:\n").append(notes.length() > 1500 ? notes.substring(0, 1500) + "…" : notes);
        }
        text.append("\n\nВсе чаты и настройки сохранятся.");
        new AlertDialog.Builder(activity)
            .setTitle("Обновление SecGram")
            .setMessage(text)
            .setPositiveButton("Обновить", (d, w) -> download(activity, release))
            .setNegativeButton("Позже", null)
            .setNeutralButton("Пропустить версию", (d, w) -> prefs().edit().putString("update_skipped", release.version).apply())
            .show();
    }

    private static void download(Activity activity, Release release) {
        final AlertDialog progress = new AlertDialog(activity, AlertDialog.ALERT_TYPE_SPINNER);
        progress.setCanCancel(false);
        progress.show();
        Utilities.globalQueue.postRunnable(() -> {
            File file = null;
            String error = null;
            try {
                final File folder = new File(activity.getCacheDir(), "secgram_update");
                folder.mkdirs();
                for (File old : folder.listFiles() == null ? new File[0] : folder.listFiles()) {
                    old.delete();
                }
                file = new File(folder, "SecGram-" + release.version + ".apk");
                HttpURLConnection connection = (HttpURLConnection) new URL(release.apkUrl).openConnection();
                connection.setInstanceFollowRedirects(true);
                connection.setConnectTimeout(15000);
                connection.setReadTimeout(60000);
                connection.setRequestProperty("User-Agent", "SecGram-Android/" + currentVersion());
                try (InputStream in = connection.getInputStream(); OutputStream out = new FileOutputStream(file)) {
                    final byte[] buffer = new byte[65536];
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                } finally {
                    connection.disconnect();
                }
                if (!sameSigner(activity, file)) {
                    file.delete();
                    file = null;
                    error = "файл подписан чужим ключом — установка отменена.";
                }
            } catch (Exception e) {
                FileLog.e(e);
                file = null;
                error = e.getMessage();
            }
            final File apk = file;
            final String failure = error;
            AndroidUtilities.runOnUIThread(() -> {
                try {
                    progress.dismiss();
                } catch (Exception ignore) {
                }
                if (apk == null) {
                    Toast.makeText(activity, "Ошибка обновления: " + failure, Toast.LENGTH_LONG).show();
                    return;
                }
                FileGuard.runTrusted(() -> AndroidUtilities.openForView(apk, apk.getName(), "application/vnd.android.package-archive", activity, null, false));
            });
        });
    }

    @SuppressWarnings("deprecation")
    private static boolean sameSigner(Context context, File apk) {
        try {
            final PackageManager manager = context.getPackageManager();
            final PackageInfo installed = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            final PackageInfo update = manager.getPackageArchiveInfo(apk.getAbsolutePath(), PackageManager.GET_SIGNATURES);
            if (update == null || update.signatures == null || installed.signatures == null) {
                return false;
            }
            if (!context.getPackageName().equals(update.packageName)) {
                return false;
            }
            final Signature[] a = installed.signatures;
            final Signature[] b = update.signatures;
            return Arrays.equals(a, b);
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }
}
