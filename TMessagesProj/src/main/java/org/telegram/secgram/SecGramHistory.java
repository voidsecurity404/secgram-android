/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.widget.Toast;

import org.telegram.SQLite.SQLiteCursor;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.MessagesStorage;
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.Utilities;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.NativeByteBuffer;
import org.telegram.tgnet.TLRPC;
import org.telegram.tgnet.tl.TL_update;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

// Messages deleted or edited by others stay visible in the chat.
//
// A deleted message is not removed from the local database: it is turned
// into a local edit with a "🗑 Удалено <time>" header, so it survives
// restarts. Edits get the previous version appended below the new text.
public final class SecGramHistory {

    public static final String DELETED_MARKER = "🗑 Удалено ";
    public static final String EDIT_MARKER = "\n\n✏️ Изменено ";

    private SecGramHistory() {
    }

    private static String time(int unixtime) {
        return new SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.US)
            .format(new Date(unixtime * 1000L));
    }

    // Called while collecting update deletions. Returns true if the ids
    // are kept (they must not be deleted then).
    // channelDialogId is 0 for private chats and basic groups.
    public static boolean keepDeleted(int account, long channelDialogId, ArrayList<Integer> ids) {
        if (!SecGramConfig.keepDeleted() || ids == null || ids.isEmpty()) {
            return false;
        }
        final ArrayList<Integer> copy = new ArrayList<>(ids);
        final MessagesStorage storage = MessagesStorage.getInstance(account);
        storage.getStorageQueue().postRunnable(() -> {
            final ArrayList<TLRPC.Message> marked = new ArrayList<>();
            final long selfId = UserConfig.getInstance(account).getClientUserId();
            final int now = ConnectionsManager.getInstance(account).getCurrentTime();
            for (int id : copy) {
                SQLiteCursor cursor = null;
                try {
                    cursor = storage.getDatabase().queryFinalized(channelDialogId != 0
                        ? "SELECT data FROM messages_v2 WHERE uid = " + channelDialogId + " AND mid = " + id
                        : "SELECT data FROM messages_v2 WHERE mid = " + id);
                    while (cursor.next()) {
                        final NativeByteBuffer data = cursor.byteBufferValue(0);
                        if (data == null) {
                            continue;
                        }
                        final TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                        data.reuse();
                        if (message == null
                            || message.action != null
                            || (channelDialogId == 0 && message.peer_id instanceof TLRPC.TL_peerChannel)
                            || (message.message != null && message.message.startsWith(DELETED_MARKER))) {
                            continue;
                        }
                        markDeleted(message, now);
                        marked.add(message);
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                } finally {
                    if (cursor != null) {
                        cursor.dispose();
                    }
                }
            }
            if (marked.isEmpty()) {
                return;
            }
            Utilities.stageQueue.postRunnable(() -> {
                final ArrayList<TLRPC.Update> updates = new ArrayList<>();
                for (TLRPC.Message message : marked) {
                    if (message.peer_id instanceof TLRPC.TL_peerChannel) {
                        final TL_update.TL_updateEditChannelMessage update = new TL_update.TL_updateEditChannelMessage();
                        update.message = message;
                        updates.add(update);
                    } else {
                        final TL_update.TL_updateEditMessage update = new TL_update.TL_updateEditMessage();
                        update.message = message;
                        updates.add(update);
                    }
                }
                MessagesController.getInstance(account).processUpdateArray(updates, new ArrayList<>(), new ArrayList<>(), false, 0);
            });
            final int count = marked.size();
            AndroidUtilities.runOnUIThread(() -> Toast.makeText(
                ApplicationLoader.applicationContext,
                "🗑 Удалено сообщений: " + count + " — сохранены в чате",
                Toast.LENGTH_SHORT).show());
        });
        return true;
    }

    private static void markDeleted(TLRPC.Message message, int now) {
        final String header = DELETED_MARKER + time(now) + "\n";
        final String text = message.message == null ? "" : message.message;
        message.message = header + text;
        final int shift = header.length();
        for (TLRPC.MessageEntity entity : message.entities) {
            entity.offset += shift;
        }
        final TLRPC.TL_messageEntityBold bold = new TLRPC.TL_messageEntityBold();
        bold.offset = 0;
        bold.length = shift - 1;
        message.entities.add(0, bold);
        if (!message.entities.isEmpty()) {
            message.flags |= 128;
        }
        message.edit_date = now;
        message.edit_hide = true;
    }

    // Edited message from the server: appends the previous version taken
    // from the local database.
    public static void applyEdit(int account, TLRPC.Message message) {
        if (!SecGramConfig.keepEdits()
            || message == null
            || message.out
            || message.message == null
            || message.message.startsWith(DELETED_MARKER)) {
            return;
        }
        if (Thread.currentThread() == MessagesStorage.getInstance(account).getStorageQueue()) {
            return; // Reading the database from its own queue would deadlock.
        }
        final TLRPC.Message old;
        try {
            old = MessagesStorage.getInstance(account).getMessage(MessageObject.getDialogId(message), message.id);
        } catch (Exception e) {
            FileLog.e(e);
            return;
        }
        if (old == null || old.message == null) {
            return;
        }
        final int split = old.message.indexOf(EDIT_MARKER);
        final String base = split < 0 ? old.message : old.message.substring(0, split);
        final String history = split < 0 ? "" : old.message.substring(split);
        if (base.equals(message.message) || base.isEmpty()) {
            if (!history.isEmpty() && !message.message.contains(EDIT_MARKER)) {
                message.message = message.message + history;
            }
            return;
        }
        final int editDate = message.edit_date != 0 ? message.edit_date : ConnectionsManager.getInstance(account).getCurrentTime();
        final String header = EDIT_MARKER + time(editDate) + " · было:\n";
        final int headerStart = message.message.length();
        message.message = message.message + header + base + history;

        final TLRPC.TL_messageEntityItalic italic = new TLRPC.TL_messageEntityItalic();
        italic.offset = headerStart + 2; // Skip the two line breaks.
        italic.length = header.length() - 3;
        message.entities.add(italic);
        final TLRPC.TL_messageEntityBlockquote quote = new TLRPC.TL_messageEntityBlockquote();
        quote.offset = headerStart + header.length();
        quote.length = base.length();
        message.entities.add(quote);
        message.flags |= 128;
    }
}
