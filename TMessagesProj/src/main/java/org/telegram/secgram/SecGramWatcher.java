/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.content.Context;
import android.content.SharedPreferences;
import android.widget.Toast;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.UserConfig;
import org.telegram.tgnet.TLRPC;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

// Watches incoming messages: scam warnings for strangers and the watchlist.
public final class SecGramWatcher implements NotificationCenter.NotificationCenterDelegate {

    private static final int MAX_HITS = 100;
    private static boolean started;
    private static List<Object> terms;

    private final int account;

    private SecGramWatcher(int account) {
        this.account = account;
    }

    public static void start() {
        if (started) {
            return;
        }
        started = true;
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; ++a) {
            NotificationCenter.getInstance(a).addObserver(new SecGramWatcher(a), NotificationCenter.didReceiveNewMessages);
        }
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("secgram", Context.MODE_PRIVATE);
    }

    public static String watchlistText() {
        return prefs().getString("watchlist", "");
    }

    public static void setWatchlistText(String text) {
        prefs().edit().putString("watchlist", text).apply();
        terms = null;
    }

    public static String hitsText() {
        return prefs().getString("watch_hits", "");
    }

    private static List<Object> terms() {
        if (terms != null) {
            return terms;
        }
        final List<Object> result = new ArrayList<>();
        for (String line : watchlistText().split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("re:")) {
                try {
                    result.add(Pattern.compile(line.substring(3).trim(), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE));
                } catch (Exception ignore) {
                }
            } else {
                result.add(IocExtractor.refang(line).toLowerCase(Locale.ROOT));
            }
        }
        return terms = result;
    }

    private static String match(String text) {
        final String refanged = IocExtractor.refang(text);
        final String lowered = refanged.toLowerCase(Locale.ROOT);
        for (Object term : terms()) {
            if (term instanceof Pattern) {
                if (((Pattern) term).matcher(refanged).find()) {
                    return ((Pattern) term).pattern();
                }
            } else if (lowered.contains((String) term)) {
                return (String) term;
            }
        }
        return null;
    }

    private void recordHit(String term, String chat, String text) {
        final String time = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date());
        final String line = time + "  «" + term + "»  " + chat + ": " + text.replace('\n', ' ');
        final String[] old = hitsText().split("\n");
        final StringBuilder b = new StringBuilder(line.length() > 200 ? line.substring(0, 200) : line);
        for (int i = 0; i < old.length && i < MAX_HITS - 1; ++i) {
            if (!old[i].isEmpty()) {
                b.append('\n').append(old[i]);
            }
        }
        prefs().edit().putString("watch_hits", b.toString()).apply();
    }

    @Override
    @SuppressWarnings("unchecked")
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id != NotificationCenter.didReceiveNewMessages || args.length < 3 || (boolean) args[2]) {
            return;
        }
        final long dialogId = (long) args[0];
        final ArrayList<MessageObject> messages = (ArrayList<MessageObject>) args[1];
        final MessagesController controller = MessagesController.getInstance(this.account);
        for (MessageObject object : messages) {
            if (object == null || object.isOut() || object.messageOwner == null) {
                continue;
            }
            final String text = object.messageOwner.message == null ? "" : object.messageOwner.message;
            if (text.isEmpty()) {
                continue;
            }
            final String chat = dialogId > 0
                ? userName(controller.getUser(dialogId))
                : (controller.getChat(-dialogId) != null ? controller.getChat(-dialogId).title : String.valueOf(dialogId));
            if (SecGramConfig.get(SecGramConfig.SCAM_DETECTOR) && dialogId > 0) {
                final TLRPC.User user = controller.getUser(dialogId);
                final boolean stranger = user != null && !user.contact && !user.bot && !user.self && !user.verified;
                if (stranger) {
                    final Finding.Report report = ScamDetector.analyze(text, true);
                    if (report.atLeast(Finding.Severity.WARNING)) {
                        toast("⚠️ Возможное мошенничество от " + chat + "\n" + report.findings.get(0).text);
                    }
                }
            }
            if (SecGramConfig.get(SecGramConfig.WATCHLIST)) {
                final String term = match(text);
                if (term != null) {
                    recordHit(term, chat, text);
                    toast("🔔 Наблюдение: «" + term + "»\n" + chat + ": " + (text.length() > 80 ? text.substring(0, 80) : text));
                }
            }
        }
    }

    private static String userName(TLRPC.User user) {
        if (user == null) {
            return "?";
        }
        final String name = ((user.first_name == null ? "" : user.first_name) + " " + (user.last_name == null ? "" : user.last_name)).trim();
        return name.isEmpty() ? String.valueOf(user.id) : name;
    }

    private static void toast(String text) {
        AndroidUtilities.runOnUIThread(() -> Toast.makeText(ApplicationLoader.applicationContext, text, Toast.LENGTH_LONG).show());
    }
}
