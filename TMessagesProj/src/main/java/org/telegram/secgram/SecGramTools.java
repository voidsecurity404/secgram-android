/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.content.FileProvider;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.SQLite.SQLiteCursor;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.ContactsController;
import org.telegram.messenger.FileLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.MessagesStorage;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.UserObject;
import org.telegram.messenger.Utilities;
import org.telegram.messenger.browser.Browser;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.NativeByteBuffer;
import org.telegram.tgnet.TLRPC;
import org.telegram.tgnet.tl.TL_account;
import org.telegram.ui.ActionBar.AlertDialog;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

// Investigation and account tools of the desktop version, for Android.
public final class SecGramTools {

    private SecGramTools() {
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("secgram", Context.MODE_PRIVATE);
    }

    private static String isoUtc(long millis) {
        final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(millis));
    }

    private static String sha256(byte[] data) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Utilities.bytesToHex(digest.digest(data)).toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    public static String[] fileHashes(File file) {
        try (InputStream in = new FileInputStream(file)) {
            final MessageDigest md5 = MessageDigest.getInstance("MD5");
            final MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            final byte[] buffer = new byte[1 << 20];
            int n;
            while ((n = in.read(buffer)) > 0) {
                md5.update(buffer, 0, n);
                sha1.update(buffer, 0, n);
                sha256.update(buffer, 0, n);
            }
            return new String[] {
                Utilities.bytesToHex(sha256.digest()).toLowerCase(Locale.ROOT),
                Utilities.bytesToHex(sha1.digest()).toLowerCase(Locale.ROOT),
                Utilities.bytesToHex(md5.digest()).toLowerCase(Locale.ROOT),
            };
        } catch (Exception e) {
            return null;
        }
    }

    private static void share(Activity activity, File file, String mime) {
        try {
            final Uri uri = FileProvider.getUriForFile(activity, activity.getPackageName() + ".provider", file);
            final Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType(mime);
            intent.putExtra(Intent.EXTRA_STREAM, uri);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            activity.startActivity(Intent.createChooser(intent, file.getName()));
        } catch (Exception e) {
            FileLog.e(e);
            Toast.makeText(activity, "Сохранено: " + file.getAbsolutePath(), Toast.LENGTH_LONG).show();
        }
    }

    private static void shareText(Activity activity, String title, String text) {
        final Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, title);
        intent.putExtra(Intent.EXTRA_TEXT, text);
        activity.startActivity(Intent.createChooser(intent, title));
    }

    // ---------------------------------------------------------------- Sets

    private static Set<String> set(String key) {
        return new HashSet<>(prefs().getStringSet(key, new HashSet<>()));
    }

    private static void toggle(String key, long dialogId, boolean on) {
        final Set<String> values = set(key);
        if (on) {
            values.add(String.valueOf(dialogId));
        } else {
            values.remove(String.valueOf(dialogId));
        }
        prefs().edit().putStringSet(key, values).apply();
    }

    public static boolean ghostChat(long dialogId) {
        return set("ghost_chats").contains(String.valueOf(dialogId));
    }

    public static void setGhostChat(long dialogId, boolean on) {
        toggle("ghost_chats", dialogId, on);
    }

    public static boolean collectChat(long dialogId) {
        return set("ioc_chats").contains(String.valueOf(dialogId));
    }

    public static void setCollectChat(long dialogId, boolean on) {
        toggle("ioc_chats", dialogId, on);
    }

    public static File iocFeedFile() {
        return new File(ApplicationLoader.applicationContext.getExternalFilesDir(null), "ioc_feed.csv");
    }

    public static void shareIocFeed(Activity activity) {
        final File file = iocFeedFile();
        if (!file.exists()) {
            Toast.makeText(activity, "Пока пусто. Включите «Собирать IOC из этого чата» в «SecGram: анализ» нужного канала.", Toast.LENGTH_LONG).show();
            return;
        }
        share(activity, file, "text/csv");
    }

    public static void collectIocs(long dialogId, String chat, MessageObject object) {
        if (!collectChat(dialogId) || object.messageOwner == null || object.messageOwner.message == null) {
            return;
        }
        final List<IocExtractor.Ioc> iocs = IocExtractor.extract(object.messageOwner.message);
        if (iocs.isEmpty()) {
            return;
        }
        final File file = iocFeedFile();
        final boolean exists = file.exists();
        try (FileWriter writer = new FileWriter(file, true)) {
            if (!exists) {
                writer.write("date_utc,chat,message_id,type,value\n");
            }
            for (IocExtractor.Ioc ioc : iocs) {
                writer.write(isoUtc(object.messageOwner.date * 1000L) + ",\"" + chat.replace("\"", "\"\"") + "\","
                    + object.getId() + "," + ioc.type + ",\"" + ioc.value.replace("\"", "\"\"") + "\"\n");
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    // ------------------------------------------------------- People notes

    private static File peopleFile(int account) {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), "secgram_people_" + account + ".json");
    }

    private static final JSONObject[] people = new JSONObject[UserConfig.MAX_ACCOUNT_COUNT];
    private static final boolean[] saveScheduled = new boolean[UserConfig.MAX_ACCOUNT_COUNT];

    private static synchronized JSONObject people(int account) {
        if (people[account] == null) {
            JSONObject result = new JSONObject();
            final File file = peopleFile(account);
            if (file.exists()) {
                try (InputStream in = new FileInputStream(file)) {
                    final byte[] data = new byte[(int) file.length()];
                    final int read = in.read(data);
                    result = new JSONObject(new String(data, 0, Math.max(read, 0), "UTF-8"));
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            people[account] = result;
        }
        return people[account];
    }

    private static synchronized void savePeopleLater(int account) {
        if (saveScheduled[account]) {
            return;
        }
        saveScheduled[account] = true;
        Utilities.globalQueue.postRunnable(() -> {
            final String text;
            synchronized (SecGramTools.class) {
                saveScheduled[account] = false;
                text = people(account).toString();
            }
            try (FileWriter writer = new FileWriter(peopleFile(account))) {
                writer.write(text);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }, 5000);
    }

    // Called from MessagesController.putUser for every user update.
    public static synchronized void trackName(int account, TLRPC.User user) {
        if (user == null || user.min || !SecGramConfig.get(SecGramConfig.NAME_HISTORY)) {
            return;
        }
        final String name = UserObject.getUserName(user);
        final String username = user.username == null ? "" : user.username;
        if (name == null || name.isEmpty()) {
            return;
        }
        try {
            final JSONObject all = people(account);
            final String key = String.valueOf(user.id);
            final JSONObject entry = all.optJSONObject(key) != null ? all.getJSONObject(key) : new JSONObject();
            final String oldName = entry.optString("name", "");
            final String oldUsername = entry.optString("username", "");
            if (oldName.equals(name) && oldUsername.equals(username)) {
                return;
            }
            if (!oldName.isEmpty()) {
                final JSONArray history = entry.optJSONArray("history") != null ? entry.getJSONArray("history") : new JSONArray();
                history.put(new JSONObject().put("at", System.currentTimeMillis() / 1000).put("name", oldName).put("username", oldUsername));
                while (history.length() > 50) {
                    history.remove(0);
                }
                entry.put("history", history);
            }
            entry.put("name", name).put("username", username);
            all.put(key, entry);
            savePeopleLater(account);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static synchronized String nameHistory(int account, long userId) {
        final JSONObject entry = people(account).optJSONObject(String.valueOf(userId));
        final JSONArray history = entry == null ? null : entry.optJSONArray("history");
        if (history == null || history.length() == 0) {
            return "";
        }
        final StringBuilder result = new StringBuilder();
        final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
        for (int i = history.length() - 1; i >= 0; --i) {
            final JSONObject item = history.optJSONObject(i);
            result.append("до ").append(format.format(new Date(item.optLong("at") * 1000))).append(": ")
                .append(item.optString("name"));
            if (!item.optString("username").isEmpty()) {
                result.append(" (@").append(item.optString("username")).append(')');
            }
            result.append('\n');
        }
        return result.toString();
    }

    public static synchronized String note(int account, long peerId) {
        final JSONObject entry = people(account).optJSONObject(String.valueOf(peerId));
        return entry == null ? "" : entry.optString("note", "");
    }

    public static synchronized void setNote(int account, long peerId, String note) {
        try {
            final JSONObject all = people(account);
            final String key = String.valueOf(peerId);
            final JSONObject entry = all.optJSONObject(key) != null ? all.getJSONObject(key) : new JSONObject();
            if (note.trim().isEmpty()) {
                entry.remove("note");
            } else {
                entry.put("note", note.trim());
            }
            all.put(key, entry);
            savePeopleLater(account);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void showNoteEditor(Activity activity, int account, long peerId, String title) {
        final EditText field = new EditText(activity);
        field.setText(note(account, peerId));
        field.setHint("Например: мошенник, коллега из SOC, инцидент #42");
        field.setMinLines(3);
        final LinearLayout box = new LinearLayout(activity);
        box.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);
        box.addView(field, new LinearLayout.LayoutParams(-1, -2));
        new AlertDialog.Builder(activity)
            .setTitle("Заметка: " + title)
            .setView(box)
            .setPositiveButton("Сохранить", (d, w) -> setNote(account, peerId, field.getText().toString()))
            .setNegativeButton("Отмена", null)
            .show();
    }

    // Another account using the exact name of one of your contacts.
    public static String impersonatedContact(int account, TLRPC.User user) {
        if (user == null || user.contact || user.self || user.bot) {
            return null;
        }
        final String name = UserObject.getUserName(user).trim().toLowerCase(Locale.ROOT);
        if (name.isEmpty()) {
            return null;
        }
        final MessagesController controller = MessagesController.getInstance(account);
        for (TLRPC.TL_contact contact : new ArrayList<>(ContactsController.getInstance(account).contacts)) {
            if (contact.user_id == user.id) {
                continue;
            }
            final TLRPC.User other = controller.getUser(contact.user_id);
            if (other != null && UserObject.getUserName(other).trim().toLowerCase(Locale.ROOT).equals(name)) {
                return UserObject.getUserName(other) + " (ID " + other.id + ")";
            }
        }
        return null;
    }

    // --------------------------------------------------------- Templates

    private static List<String> templates() {
        final String text = prefs().getString("templates", "");
        final List<String> result = new ArrayList<>();
        if (text.trim().isEmpty()) {
            result.add("⚠️ Это фишинговая ссылка. Не открывайте её и не вводите данные. Если уже ввели — срочно смените пароль и сообщите в отдел ИБ.");
            result.add("Никому не сообщайте код из SMS или Telegram. Банк, поддержка и «служба безопасности» никогда его не спрашивают.");
            result.add("Этот файл опасен (вредоносная программа). Не открывайте его, удалите и сообщите в отдел ИБ.");
            result.add("Спасибо за сообщение! Инцидент зарегистрирован под номером #INC-");
            result.add("Включите облачный пароль: Настройки → Конфиденциальность → Облачный пароль. Завершите незнакомые сеансы.");
            return result;
        }
        for (String part : text.split("\n---\n")) {
            if (!part.trim().isEmpty()) {
                result.add(part.trim());
            }
        }
        return result;
    }

    public static void showTemplates(Activity activity) {
        final List<String> list = templates();
        final CharSequence[] items = new CharSequence[list.size() + 1];
        for (int i = 0; i < list.size(); ++i) {
            items[i] = list.get(i).length() > 90 ? list.get(i).substring(0, 90) + "…" : list.get(i);
        }
        items[list.size()] = "✏️ Редактировать шаблоны";
        new AlertDialog.Builder(activity)
            .setTitle("Шаблоны ответов")
            .setItems(items, (d, which) -> {
                if (which < list.size()) {
                    AndroidUtilities.addToClipboard(list.get(which));
                    Toast.makeText(activity, "Скопировано — вставьте в чат", Toast.LENGTH_SHORT).show();
                } else {
                    final EditText field = new EditText(activity);
                    field.setText(Finding.join("\n---\n", list));
                    final ScrollView scroll = new ScrollView(activity);
                    scroll.setPadding(AndroidUtilities.dp(24), 0, AndroidUtilities.dp(24), 0);
                    scroll.addView(field);
                    new AlertDialog.Builder(activity)
                        .setTitle("Шаблоны (разделитель ---)")
                        .setView(scroll)
                        .setPositiveButton("Сохранить", (d2, w2) -> prefs().edit().putString("templates", field.getText().toString()).apply())
                        .setNegativeButton("Отмена", null)
                        .show();
                }
            })
            .setNegativeButton("Закрыть", null)
            .show();
    }

    // -------------------------------------------------------------- Team

    public static void exportTeam(Activity activity) {
        try {
            final JSONObject json = new JSONObject()
                .put("secgram_team", 1)
                .put("watchlist", SecGramWatcher.watchlistText())
                .put("domains", ThreatData.domainListsText())
                .put("templates", new JSONArray(templates()));
            final File file = new File(activity.getExternalFilesDir(null), "secgram-team.json");
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(json.toString(2));
            }
            share(activity, file, "application/json");
        } catch (Exception e) {
            Toast.makeText(activity, "Ошибка: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    public static void importTeamFromClipboard(Activity activity) {
        final ClipboardManager clipboard = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
        final ClipData clip = clipboard == null ? null : clipboard.getPrimaryClip();
        final String text = clip == null || clip.getItemCount() == 0 || clip.getItemAt(0).getText() == null ? "" : clip.getItemAt(0).getText().toString();
        try {
            final JSONObject json = new JSONObject(text);
            if (!json.has("secgram_team")) {
                throw new Exception("не файл настроек SecGram");
            }
            SecGramWatcher.setWatchlistText(merge(SecGramWatcher.watchlistText(), json.optString("watchlist")));
            ThreatData.setDomainListsText(merge(ThreatData.domainListsText(), json.optString("domains")));
            final List<String> list = templates();
            final JSONArray incoming = json.optJSONArray("templates");
            for (int i = 0; incoming != null && i < incoming.length(); ++i) {
                if (!list.contains(incoming.optString(i))) {
                    list.add(incoming.optString(i));
                }
            }
            prefs().edit().putString("templates", Finding.join("\n---\n", list)).apply();
            Toast.makeText(activity, "Настройки команды импортированы", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(activity, "Скопируйте содержимое secgram-team.json в буфер обмена. Ошибка: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private static String merge(String own, String add) {
        final List<String> lines = new ArrayList<>();
        for (String line : own.split("\n")) {
            if (!line.trim().isEmpty()) {
                lines.add(line.trim());
            }
        }
        for (String line : add.split("\n")) {
            if (!line.trim().isEmpty() && !lines.contains(line.trim())) {
                lines.add(line.trim());
            }
        }
        return Finding.join("\n", lines);
    }

    // ------------------------------------------------------------- Audit

    public static void showSecurityAudit(Activity activity, int account) {
        final TextView text = new TextView(activity);
        text.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);
        text.setTextIsSelectable(true);
        final ScrollView scroll = new ScrollView(activity);
        scroll.addView(text);
        final String[] rows = new String[6];
        final Runnable render = () -> {
            final StringBuilder b = new StringBuilder();
            for (String row : rows) {
                b.append(row == null ? "⏳ Проверка…" : row).append("\n\n");
            }
            text.setText(b.toString().trim());
        };
        rows[4] = SharedConfig.passcodeHash.length() > 0
            ? "✅ Код-пароль приложения установлен."
            : "⚠️ Код-пароль приложения не установлен: любой, кто возьмёт телефон, прочитает переписку. Настройки → Конфиденциальность → Код-пароль.";
        final List<String> off = new ArrayList<>();
        final String[][] protections = {
            { SecGramConfig.LINK_GUARD, "проверка ссылок" }, { SecGramConfig.FILE_GUARD, "проверка файлов" },
            { SecGramConfig.LOGIN_CODE_GUARD, "защита кода входа" }, { SecGramConfig.STRIP_METADATA, "удаление метаданных" },
            { SecGramConfig.SCAM_DETECTOR, "детектор мошенничества" },
        };
        for (String[] p : protections) {
            if (!SecGramConfig.get(p[0])) {
                off.add(p[1]);
            }
        }
        rows[5] = off.isEmpty() ? "✅ Все основные защиты SecGram включены." : "⚠️ Выключено в SecGram: " + Finding.join(", ", off) + ".";
        render.run();
        new AlertDialog.Builder(activity)
            .setTitle("Аудит безопасности")
            .setView(scroll)
            .setPositiveButton("Закрыть", null)
            .show();

        final ConnectionsManager connections = ConnectionsManager.getInstance(account);
        connections.sendRequest(new TL_account.getPassword(), (response, error) -> AndroidUtilities.runOnUIThread(() -> {
            if (response instanceof TL_account.Password) {
                final TL_account.Password password = (TL_account.Password) response;
                rows[0] = password.has_password
                    ? "✅ Облачный пароль (2FA) включён." + (password.has_recovery ? " Почта восстановления указана." : " ⚠️ Почта восстановления не указана.")
                    : "❌ Облачный пароль (2FA) выключен! Без него кода из SMS достаточно для угона аккаунта. Настройки → Конфиденциальность → Облачный пароль.";
            } else {
                rows[0] = "2FA: ошибка проверки.";
            }
            render.run();
        }));
        connections.sendRequest(new TL_account.getAuthorizations(), (response, error) -> AndroidUtilities.runOnUIThread(() -> {
            if (response instanceof TL_account.authorizations) {
                final TL_account.authorizations list = (TL_account.authorizations) response;
                final long now = System.currentTimeMillis() / 1000;
                int stale = 0;
                final StringBuilder b = new StringBuilder();
                for (TLRPC.TL_authorization auth : list.authorizations) {
                    if (!auth.current && now - auth.date_active > 30L * 86400) {
                        ++stale;
                    }
                    b.append("• ").append(auth.device_model).append(", ").append(auth.platform)
                        .append(" — ").append(auth.ip).append(" (").append(auth.country).append(")")
                        .append(auth.current ? " — этот" : "").append('\n');
                }
                rows[1] = (stale == 0 ? "✅ " : "⚠️ ") + "Активных сеансов: " + list.authorizations.size()
                    + (stale > 0 ? ". Неактивных больше 30 дней: " + stale + " — завершите их." : ".")
                    + "\n" + b.toString().trim()
                    + "\nАвтозавершение через " + list.authorization_ttl_days + " дн.";
            } else {
                rows[1] = "Сеансы: ошибка проверки.";
            }
            render.run();
        }));
        final TL_account.getPrivacy phone = new TL_account.getPrivacy();
        phone.key = new TLRPC.TL_inputPrivacyKeyPhoneNumber();
        connections.sendRequest(phone, (response, error) -> AndroidUtilities.runOnUIThread(() -> {
            rows[2] = privacyRow(response, "Кто видит номер телефона", true);
            render.run();
        }));
        final TL_account.getPrivacy byPhone = new TL_account.getPrivacy();
        byPhone.key = new TLRPC.TL_inputPrivacyKeyAddedByPhone();
        connections.sendRequest(byPhone, (response, error) -> AndroidUtilities.runOnUIThread(() -> {
            rows[3] = privacyRow(response, "Кто может найти по номеру", false);
            render.run();
        }));
    }

    private static String privacyRow(Object response, String title, boolean strict) {
        if (!(response instanceof TL_account.privacyRules)) {
            return title + ": ошибка проверки.";
        }
        String value = "особые правила";
        boolean ok = false;
        for (TLRPC.PrivacyRule rule : ((TL_account.privacyRules) response).rules) {
            if (rule instanceof TLRPC.TL_privacyValueAllowAll) {
                value = "все";
                ok = false;
            } else if (rule instanceof TLRPC.TL_privacyValueAllowContacts) {
                value = "контакты";
                ok = !strict;
            } else if (rule instanceof TLRPC.TL_privacyValueDisallowAll) {
                value = "никто";
                ok = true;
            }
        }
        return (ok ? "✅ " : "⚠️ ") + title + ": " + value + (ok ? "." : strict ? ". Рекомендуем «Никто»." : ". Рекомендуем «Контакты».");
    }

    // ---------------------------------------------------- Lookup / export

    public static List<String[]> lookupLinks(IocExtractor.Ioc ioc) {
        final List<String[]> result = new ArrayList<>();
        final String v = Uri.encode(ioc.value);
        switch (ioc.type) {
            case "ipv4":
                result.add(new String[] { "VirusTotal", "https://www.virustotal.com/gui/ip-address/" + v });
                result.add(new String[] { "AbuseIPDB", "https://www.abuseipdb.com/check/" + v });
                result.add(new String[] { "Shodan", "https://www.shodan.io/host/" + v });
                result.add(new String[] { "GreyNoise", "https://viz.greynoise.io/ip/" + v });
                break;
            case "domain":
                result.add(new String[] { "VirusTotal", "https://www.virustotal.com/gui/domain/" + v });
                result.add(new String[] { "urlscan", "https://urlscan.io/domain/" + v });
                result.add(new String[] { "crt.sh", "https://crt.sh/?q=" + v });
                break;
            case "url":
                result.add(new String[] { "urlscan", "https://urlscan.io/search/#page.url:%22" + v + "%22" });
                result.add(new String[] { "URLhaus", "https://urlhaus.abuse.ch/browse.php?search=" + v });
                break;
            case "md5":
            case "sha1":
            case "sha256":
                result.add(new String[] { "VirusTotal", "https://www.virustotal.com/gui/file/" + v });
                result.add(new String[] { "MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search=" + Uri.encode((ioc.type.equals("md5") ? "md5:" : ioc.type.equals("sha1") ? "sha1:" : "sha256:") + ioc.value) });
                break;
            case "cve":
                result.add(new String[] { "NVD", "https://nvd.nist.gov/vuln/detail/" + v });
                break;
            case "mitre":
                result.add(new String[] { "MITRE ATT&CK", "https://attack.mitre.org/techniques/" + ioc.value.replace('.', '/') + "/" });
                break;
            case "btc":
                result.add(new String[] { "Blockchair", "https://blockchair.com/bitcoin/address/" + v });
                break;
            case "eth":
                result.add(new String[] { "Etherscan", "https://etherscan.io/address/" + v });
                break;
            case "ton":
                result.add(new String[] { "Tonviewer", "https://tonviewer.com/" + v });
                break;
            case "telegram":
                final String name = ioc.value.replace("@", "");
                result.add(new String[] { "Telegram", "https://t.me/" + name });
                result.add(new String[] { "GitHub", "https://github.com/" + name });
                result.add(new String[] { "Instagram", "https://www.instagram.com/" + name + "/" });
                result.add(new String[] { "X", "https://x.com/" + name });
                break;
            default:
                break;
        }
        return result;
    }

    public static void showLookups(Activity activity, List<IocExtractor.Ioc> iocs) {
        final List<String[]> links = new ArrayList<>();
        for (IocExtractor.Ioc ioc : iocs) {
            for (String[] link : lookupLinks(ioc)) {
                links.add(new String[] { link[0] + ": " + IocExtractor.defang(ioc), link[1] });
            }
        }
        if (links.isEmpty()) {
            Toast.makeText(activity, "Нет индикаторов для проверки", Toast.LENGTH_SHORT).show();
            return;
        }
        final CharSequence[] items = new CharSequence[links.size()];
        for (int i = 0; i < links.size(); ++i) {
            items[i] = links.get(i)[0];
        }
        new AlertDialog.Builder(activity)
            .setTitle("Проверить в сервисах (отправляется только индикатор)")
            .setItems(items, (d, which) -> Browser.openUrl(activity, links.get(which)[1]))
            .setNegativeButton("Закрыть", null)
            .show();
    }

    public static String formatIocs(List<IocExtractor.Ioc> iocs, String format) {
        try {
            final String now = isoUtc(System.currentTimeMillis());
            switch (format) {
                case "stix": {
                    final JSONArray objects = new JSONArray();
                    for (IocExtractor.Ioc ioc : iocs) {
                        final String v = ioc.value.replace("\\", "\\\\").replace("'", "\\'");
                        String pattern = null;
                        switch (ioc.type) {
                            case "url": pattern = "[url:value = '" + v + "']"; break;
                            case "domain": pattern = "[domain-name:value = '" + v + "']"; break;
                            case "ipv4": pattern = "[ipv4-addr:value = '" + v + "']"; break;
                            case "email": pattern = "[email-addr:value = '" + v + "']"; break;
                            case "md5": pattern = "[file:hashes.MD5 = '" + v + "']"; break;
                            case "sha1": pattern = "[file:hashes.'SHA-1' = '" + v + "']"; break;
                            case "sha256": pattern = "[file:hashes.'SHA-256' = '" + v + "']"; break;
                            default: break;
                        }
                        if (pattern == null) {
                            continue;
                        }
                        objects.put(new JSONObject()
                            .put("type", "indicator").put("spec_version", "2.1")
                            .put("id", "indicator--" + UUID.randomUUID())
                            .put("created", now).put("modified", now).put("valid_from", now)
                            .put("name", ioc.type + ": " + ioc.value)
                            .put("pattern", pattern).put("pattern_type", "stix")
                            .put("indicator_types", new JSONArray().put("malicious-activity")));
                    }
                    return new JSONObject().put("type", "bundle").put("id", "bundle--" + UUID.randomUUID()).put("objects", objects).toString(2);
                }
                case "misp": {
                    final JSONArray attributes = new JSONArray();
                    for (IocExtractor.Ioc ioc : iocs) {
                        String type = "text";
                        String category = "Network activity";
                        switch (ioc.type) {
                            case "url": type = "url"; break;
                            case "domain": type = "domain"; break;
                            case "ipv4": type = "ip-dst"; break;
                            case "email": type = "email-src"; break;
                            case "md5": case "sha1": case "sha256": type = ioc.type; category = "Payload delivery"; break;
                            case "cve": type = "vulnerability"; category = "External analysis"; break;
                            case "btc": type = "btc"; category = "Financial fraud"; break;
                            default: category = "Other"; break;
                        }
                        attributes.put(new JSONObject().put("type", type).put("category", category).put("value", ioc.value).put("to_ids", !type.equals("text")));
                    }
                    return new JSONObject().put("Event", new JSONObject()
                        .put("info", "SecGram export").put("threat_level_id", "2").put("analysis", "0").put("distribution", "0")
                        .put("Attribute", attributes)).toString(2);
                }
                case "thehive": {
                    final JSONArray observables = new JSONArray();
                    for (IocExtractor.Ioc ioc : iocs) {
                        final String type = ioc.type.equals("ipv4") ? "ip" : ioc.type.equals("email") ? "mail"
                            : (ioc.type.equals("md5") || ioc.type.startsWith("sha")) ? "hash"
                            : (ioc.type.equals("url") || ioc.type.equals("domain")) ? ioc.type : "other";
                        observables.put(new JSONObject().put("dataType", type).put("data", ioc.value).put("ioc", !type.equals("other")));
                    }
                    return new JSONObject().put("type", "external").put("source", "SecGram")
                        .put("sourceRef", UUID.randomUUID().toString()).put("title", "SecGram: " + iocs.size() + " индикаторов")
                        .put("severity", 2).put("tlp", 2).put("observables", observables).toString(2);
                }
                case "csv": {
                    final StringBuilder b = new StringBuilder("type,value\n");
                    for (IocExtractor.Ioc ioc : iocs) {
                        b.append(ioc.type).append(",\"").append(ioc.value.replace("\"", "\"\"")).append("\"\n");
                    }
                    return b.toString();
                }
                default: {
                    final JSONArray array = new JSONArray();
                    for (IocExtractor.Ioc ioc : iocs) {
                        array.put(new JSONObject().put("type", ioc.type).put("value", ioc.value));
                    }
                    return array.toString(2);
                }
            }
        } catch (Exception e) {
            return "";
        }
    }

    public static void exportIocs(Activity activity, List<IocExtractor.Ioc> iocs) {
        final String[] formats = { "json", "csv", "stix", "misp", "thehive" };
        final CharSequence[] titles = { "JSON", "CSV", "STIX 2.1", "MISP", "TheHive" };
        new AlertDialog.Builder(activity)
            .setTitle("Экспорт IOC")
            .setItems(titles, (d, which) -> shareText(activity, "SecGram IOC (" + titles[which] + ")", formatIocs(iocs, formats[which])))
            .setNegativeButton("Отмена", null)
            .show();
    }

    // ---------------------------------------------------------- Evidence

    public static void exportEvidence(Activity activity, int account, MessageObject object) {
        final MessagesController controller = MessagesController.getInstance(account);
        Utilities.globalQueue.postRunnable(() -> {
            try {
                final String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
                final File folder = new File(activity.getExternalFilesDir(null), "SecGram_evidence_" + stamp);
                if (!folder.mkdirs()) {
                    throw new Exception("не удалось создать папку");
                }
                final TLRPC.Message message = object.messageOwner;
                final long fromId = object.getFromChatId();
                final JSONObject json = new JSONObject()
                    .put("tool", "SecGram Android " + SecGramUpdater.currentVersion())
                    .put("exported_utc", isoUtc(System.currentTimeMillis()))
                    .put("chat_id", object.getDialogId())
                    .put("message_id", message.id)
                    .put("date_utc", isoUtc(message.date * 1000L))
                    .put("sender_id", fromId)
                    .put("text", message.message == null ? "" : message.message);
                if (fromId > 0 && controller.getUser(fromId) != null) {
                    final TLRPC.User user = controller.getUser(fromId);
                    json.put("sender_name", UserObject.getUserName(user)).put("sender_username", user.username == null ? "" : user.username);
                }
                if (message.edit_date != 0) {
                    json.put("edit_date_utc", isoUtc(message.edit_date * 1000L));
                }
                if (message.fwd_from != null) {
                    json.put("forwarded_date_utc", isoUtc(message.fwd_from.date * 1000L));
                    if (message.fwd_from.from_name != null) {
                        json.put("forwarded_from_name", message.fwd_from.from_name);
                    }
                }
                final StringBuilder manifest = new StringBuilder();
                final File media = FileLoader.getInstance(account).getPathToMessage(message);
                if (media != null && media.exists() && media.length() < 200L * 1024 * 1024) {
                    final File copy = new File(folder, "media_" + message.id + "_" + media.getName() + ".bin");
                    try (InputStream in = new FileInputStream(media); FileOutputStream out = new FileOutputStream(copy)) {
                        final byte[] buffer = new byte[1 << 16];
                        int n;
                        while ((n = in.read(buffer)) > 0) {
                            out.write(buffer, 0, n);
                        }
                    }
                    final String[] hashes = fileHashes(copy);
                    json.put("media", new JSONObject().put("file", copy.getName()).put("sha256", hashes == null ? "" : hashes[0]));
                    manifest.append(hashes == null ? "" : hashes[0]).append("  ").append(copy.getName()).append('\n');
                }
                final byte[] jsonBytes = json.toString(2).getBytes("UTF-8");
                try (FileOutputStream out = new FileOutputStream(new File(folder, "message.json"))) {
                    out.write(jsonBytes);
                }
                manifest.append(sha256(jsonBytes)).append("  message.json\n");
                final String html = "<!doctype html><meta charset=\"utf-8\"><h1>Доказательства SecGram</h1><pre>"
                    + android.text.TextUtils.htmlEncode(json.toString(2)) + "</pre>";
                final byte[] htmlBytes = html.getBytes("UTF-8");
                try (FileOutputStream out = new FileOutputStream(new File(folder, "report.html"))) {
                    out.write(htmlBytes);
                }
                manifest.append(sha256(htmlBytes)).append("  report.html\n");
                final byte[] manifestBytes = manifest.toString().getBytes("UTF-8");
                try (FileOutputStream out = new FileOutputStream(new File(folder, "manifest.txt"))) {
                    out.write(manifestBytes);
                }
                final String manifestHash = sha256(manifestBytes);
                try (FileOutputStream out = new FileOutputStream(new File(folder, "manifest.sha256"))) {
                    out.write((manifestHash + "  manifest.txt\n").getBytes("UTF-8"));
                }
                try (FileWriter custody = new FileWriter(new File(activity.getExternalFilesDir(null), "custody.log"), true)) {
                    custody.write(isoUtc(System.currentTimeMillis()) + "\t" + Build.MODEL + "\t" + folder.getName() + "\tmanifest_sha256=" + manifestHash + "\n");
                }
                final File zip = new File(activity.getExternalFilesDir(null), folder.getName() + ".zip");
                try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zip))) {
                    for (File file : folder.listFiles()) {
                        out.putNextEntry(new ZipEntry(folder.getName() + "/" + file.getName()));
                        try (InputStream in = new FileInputStream(file)) {
                            final byte[] buffer = new byte[1 << 16];
                            int n;
                            while ((n = in.read(buffer)) > 0) {
                                out.write(buffer, 0, n);
                            }
                        }
                        out.closeEntry();
                    }
                }
                AndroidUtilities.runOnUIThread(() -> share(activity, zip, "application/zip"));
            } catch (Exception e) {
                FileLog.e(e);
                AndroidUtilities.runOnUIThread(() -> Toast.makeText(activity, "Ошибка экспорта: " + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        });
    }

    // ------------------------------------------------------ Regex search

    public static void showRegexSearch(Activity activity, int account, long dialogId) {
        final EditText field = new EditText(activity);
        field.setHint("Например: \\b\\d{16}\\b  или  (?i)парол|parol");
        final LinearLayout box = new LinearLayout(activity);
        box.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);
        box.addView(field, new LinearLayout.LayoutParams(-1, -2));
        new AlertDialog.Builder(activity)
            .setTitle("Поиск regex в этом чате")
            .setView(box)
            .setPositiveButton("Искать", (d, w) -> runRegexSearch(activity, account, dialogId, field.getText().toString()))
            .setNegativeButton("Отмена", null)
            .show();
    }

    private static void runRegexSearch(Activity activity, int account, long dialogId, String expression) {
        final Pattern pattern;
        try {
            pattern = Pattern.compile(expression);
        } catch (Exception e) {
            Toast.makeText(activity, "Некорректное выражение: " + e.getMessage(), Toast.LENGTH_LONG).show();
            return;
        }
        final MessagesStorage storage = MessagesStorage.getInstance(account);
        storage.getStorageQueue().postRunnable(() -> {
            final List<String> results = new ArrayList<>();
            SQLiteCursor cursor = null;
            try {
                cursor = storage.getDatabase().queryFinalized("SELECT data FROM messages_v2 WHERE uid = " + dialogId + " ORDER BY mid DESC LIMIT 20000");
                final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
                while (cursor.next() && results.size() < 200) {
                    final NativeByteBuffer data = cursor.byteBufferValue(0);
                    if (data == null) {
                        continue;
                    }
                    final TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                    if (message == null || message.message == null) {
                        continue;
                    }
                    final Matcher m = pattern.matcher(message.message);
                    if (m.find()) {
                        final int from = Math.max(0, m.start() - 30);
                        results.add(format.format(new Date(message.date * 1000L)) + "  #" + message.id + "\n" + message.message.substring(from, Math.min(message.message.length(), from + 140)).replace('\n', ' '));
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            } finally {
                if (cursor != null) {
                    cursor.dispose();
                }
            }
            AndroidUtilities.runOnUIThread(() -> {
                if (results.isEmpty()) {
                    Toast.makeText(activity, "Ничего не найдено", Toast.LENGTH_LONG).show();
                    return;
                }
                final CharSequence[] items = results.toArray(new CharSequence[0]);
                new AlertDialog.Builder(activity)
                    .setTitle("Найдено: " + results.size())
                    .setItems(items, (d, which) -> AndroidUtilities.addToClipboard(results.get(which)))
                    .setNegativeButton("Закрыть", null)
                    .show();
            });
        });
    }

    // ---------------------------------------------------- Clipboard guard

    private static boolean clipboardWatching;

    public static void startClipboardGuard() {
        if (clipboardWatching) {
            return;
        }
        clipboardWatching = true;
        final ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            return;
        }
        clipboard.addPrimaryClipChangedListener(() -> {
            if (!SecGramConfig.get(SecGramConfig.CLIPBOARD_GUARD)) {
                return;
            }
            final ClipData clip = clipboard.getPrimaryClip();
            if (clip == null || clip.getItemCount() == 0 || clip.getItemAt(0).getText() == null) {
                return;
            }
            final String text = clip.getItemAt(0).getText().toString();
            Utilities.globalQueue.postRunnable(() -> {
                if (!LoginCodeGuard.containsRecentCode(UserConfig.selectedAccount, text)) {
                    return;
                }
                AndroidUtilities.runOnUIThread(() -> {
                    final ClipData now = clipboard.getPrimaryClip();
                    if (now != null && now.getItemCount() > 0 && now.getItemAt(0).getText() != null && text.equals(now.getItemAt(0).getText().toString())) {
                        if (Build.VERSION.SDK_INT >= 28) {
                            clipboard.clearPrimaryClip();
                        } else {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""));
                        }
                    }
                }, 30000);
            });
        });
    }

    // --------------------------------------------------- Link context

    private static MessageObject lastLinkMessage;
    private static int lastLinkAccount;
    private static long lastLinkTime;

    public static void rememberLinkMessage(int account, MessageObject object) {
        lastLinkAccount = account;
        lastLinkMessage = object;
        lastLinkTime = System.currentTimeMillis();
    }

    // True if the link being opened was just pressed in a message of a
    // stranger (private chat with someone not in contacts).
    public static boolean linkFromStranger() {
        final MessageObject object = lastLinkMessage;
        if (object == null || System.currentTimeMillis() - lastLinkTime > 5000 || object.isOut()) {
            return false;
        }
        final long dialogId = object.getDialogId();
        if (dialogId <= 0) {
            return false;
        }
        final TLRPC.User user = MessagesController.getInstance(lastLinkAccount).getUser(dialogId);
        return user != null && !user.contact && !user.bot && !user.self && !user.verified;
    }
}
