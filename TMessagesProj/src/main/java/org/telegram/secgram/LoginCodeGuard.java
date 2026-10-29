/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import org.telegram.SQLite.SQLiteCursor;
import org.telegram.messenger.MessagesStorage;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.NativeByteBuffer;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.LaunchActivity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Stops sending a Telegram login code to anyone — the most common way
// accounts are stolen.
public final class LoginCodeGuard {

    private static final long SERVICE_ID = 777000;
    private static final int CODE_LIFETIME = 24 * 3600;
    private static final Pattern CODE = Pattern.compile("(?<!\\d)(\\d{5,6})(?!\\d)");
    private static final Pattern CODE_MESSAGE = Pattern.compile("(?i)code|код|kod|login|вход");

    private static boolean bypass;

    private LoginCodeGuard() {
    }

    private static List<String> recentCodes(int account) {
        final List<String> result = new ArrayList<>();
        final MessagesStorage storage = MessagesStorage.getInstance(account);
        final int now = ConnectionsManager.getInstance(account).getCurrentTime();
        final CountDownLatch latch = new CountDownLatch(1);
        storage.getStorageQueue().postRunnable(() -> {
            SQLiteCursor cursor = null;
            try {
                cursor = storage.getDatabase().queryFinalized("SELECT data FROM messages_v2 WHERE uid = " + SERVICE_ID + " ORDER BY mid DESC LIMIT 10");
                while (cursor.next()) {
                    final NativeByteBuffer data = cursor.byteBufferValue(0);
                    if (data == null) {
                        continue;
                    }
                    final TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                    if (message == null || message.message == null || now - message.date > CODE_LIFETIME) {
                        continue;
                    }
                    if (CODE_MESSAGE.matcher(message.message).find()) {
                        final Matcher m = CODE.matcher(message.message);
                        while (m.find()) {
                            result.add(m.group(1));
                        }
                    }
                }
            } catch (Exception ignore) {
            } finally {
                if (cursor != null) {
                    cursor.dispose();
                }
                latch.countDown();
            }
        });
        try {
            latch.await(2, TimeUnit.SECONDS);
        } catch (InterruptedException ignore) {
        }
        return result;
    }

    // Returns true if sending was stopped by a warning; `send` is called
    // again if the user insists.
    public static boolean check(int account, long dialogId, String text, Runnable send) {
        if (bypass || text == null || text.isEmpty() || dialogId == SERVICE_ID || !SecGramConfig.get(SecGramConfig.LOGIN_CODE_GUARD)) {
            return false;
        }
        final StringBuilder digits = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isDigit(c)) {
                digits.append(c);
            }
        }
        if (digits.length() < 5) {
            return false;
        }
        boolean found = false;
        for (String code : recentCodes(account)) {
            if (text.contains(code) || digits.indexOf(code) >= 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
        final BaseFragment fragment = LaunchActivity.getLastFragment();
        if (fragment == null || fragment.getParentActivity() == null) {
            return true; // Better not to send at all.
        }
        final AlertDialog dialog = new AlertDialog.Builder(fragment.getParentActivity())
            .setTitle("Это код входа в Telegram!")
            .setMessage("Ваше сообщение содержит код входа в ваш аккаунт. С этим кодом любой человек получит полный доступ к вашей переписке.\n\nTelegram, поддержка, банки и «служба безопасности» НИКОГДА не просят этот код. Если его кто-то просит — это мошенник.")
            .setPositiveButton("Отмена", null)
            .setNegativeButton("Всё равно отправить", (d, w) -> {
                bypass = true;
                try {
                    send.run();
                } finally {
                    bypass = false;
                }
            })
            .show();
        dialog.redPositive();
        return true;
    }
}
