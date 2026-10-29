/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.app.Activity;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.DialogObject;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.UserObject;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.ActionBar.AlertDialog;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

// "SecGram: анализ" in the message menu: ids, dates, sender red flags,
// scam patterns, links and indicators of compromise.
public final class MessageAnalysis {

    private MessageAnalysis() {
    }

    private static String date(int unixtime) {
        if (unixtime == 0) {
            return "";
        }
        final SimpleDateFormat local = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
        final SimpleDateFormat utc = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
        utc.setTimeZone(TimeZone.getTimeZone("UTC"));
        final Date value = new Date(unixtime * 1000L);
        return local.format(value) + " (UTC " + utc.format(value) + ")";
    }

    private static String peerLine(MessagesController controller, long id) {
        if (id > 0) {
            final TLRPC.User user = controller.getUser(id);
            if (user == null) {
                return "id " + id;
            }
            final StringBuilder b = new StringBuilder(UserObject.getUserName(user)).append("  [id ").append(id).append("]");
            if (user.username != null) {
                b.append("  @").append(user.username);
            }
            if (user.scam) {
                b.append("  ⚠ SCAM");
            } else if (user.fake) {
                b.append("  ⚠ FAKE");
            } else if (user.verified) {
                b.append("  ✔ верифицирован");
            }
            if (user.bot) {
                b.append("  (бот)");
            }
            return b.toString();
        }
        final TLRPC.Chat chat = controller.getChat(-id);
        if (chat == null) {
            return "id " + id;
        }
        final StringBuilder b = new StringBuilder(chat.title).append("  [id ").append(id).append("]");
        if (chat.username != null) {
            b.append("  @").append(chat.username);
        }
        if (chat.scam) {
            b.append("  ⚠ SCAM");
        } else if (chat.fake) {
            b.append("  ⚠ FAKE");
        }
        return b.toString();
    }

    private static Finding.Report senderRisk(TLRPC.User user, long userId) {
        final Finding.Report result = new Finding.Report();
        if (user == null) {
            return result;
        }
        if (user.scam) {
            result.add(Finding.Severity.CRITICAL, "Telegram пометил аккаунт как SCAM.");
        }
        if (user.fake) {
            result.add(Finding.Severity.CRITICAL, "Telegram пометил аккаунт как FAKE (выдаёт себя за другого).");
        }
        if (user.verified) {
            return result;
        }
        final String name = (UserObject.getUserName(user) + " " + (user.username == null ? "" : user.username)).toLowerCase(Locale.ROOT);
        final String[] authority = { "telegram", "support", "admin", "official", "security", "notification", "moderator", "durov", "service", "verify", "bank" };
        final StringBuilder matched = new StringBuilder();
        for (String word : authority) {
            if (name.contains(word)) {
                if (matched.length() > 0) {
                    matched.append(", ");
                }
                matched.append(word);
            }
        }
        if (matched.length() > 0 && userId != 777000) {
            result.add(user.contact ? Finding.Severity.NOTICE : Finding.Severity.HIGH, "Имя претендует на официальность (" + matched + "), но аккаунт не верифицирован. Уведомления Telegram приходят только от верифицированного «Telegram» (ID 777000).");
        }
        return result;
    }

    public static void show(Activity activity, int account, MessageObject object) {
        if (activity == null || object == null || object.messageOwner == null) {
            return;
        }
        final MessagesController controller = MessagesController.getInstance(account);
        final TLRPC.Message message = object.messageOwner;
        final long dialogId = object.getDialogId();
        final long fromId = object.getFromChatId();
        final StringBuilder text = new StringBuilder();
        text.append("Чат: ").append(peerLine(controller, dialogId)).append('\n');
        text.append("ID сообщения: ").append(message.id).append('\n');
        if (fromId != 0 && fromId != dialogId) {
            text.append("Отправитель: ").append(peerLine(controller, fromId)).append('\n');
        }
        text.append("Дата: ").append(date(message.date)).append('\n');
        if (message.edit_date != 0 && !message.edit_hide) {
            text.append("Изменено: ").append(date(message.edit_date)).append('\n');
        }
        if (message.fwd_from != null) {
            final TLRPC.MessageFwdHeader fwd = message.fwd_from;
            if (fwd.from_id != null) {
                text.append("Переслано от: ").append(peerLine(controller, DialogObject.getPeerDialogId(fwd.from_id))).append('\n');
            } else if (fwd.from_name != null) {
                text.append("Переслано от: ").append(fwd.from_name).append(" (скрытый аккаунт)").append('\n');
            }
            if (fwd.channel_post != 0) {
                text.append("ID исходного сообщения: ").append(fwd.channel_post).append('\n');
            }
            text.append("Дата оригинала: ").append(date(fwd.date)).append('\n');
        }
        if (message.via_bot_id != 0) {
            text.append("Через бота: ").append(peerLine(controller, message.via_bot_id)).append('\n');
        }
        if (object.getDocument() != null) {
            text.append("Файл: ").append(object.getDocumentName()).append(" (").append(AndroidUtilities.formatFileSize(object.getDocument().size)).append(")\n");
            for (Finding f : FileGuard.analyzeName(object.getDocumentName()).findings) {
                text.append(f.severity.mark).append(' ').append(f.text).append('\n');
            }
        }

        final TLRPC.User sender = fromId > 0 ? controller.getUser(fromId) : null;
        final boolean stranger = sender != null && !sender.contact && !sender.self && !sender.bot && dialogId > 0;
        final Finding.Report risk = senderRisk(sender, fromId);
        if (!risk.findings.isEmpty()) {
            text.append("\nОтправитель: ").append(risk.verdict()).append('\n');
            for (Finding f : risk.findings) {
                text.append(f.severity.mark).append(' ').append(f.text).append('\n');
            }
        }

        final String body = message.message == null ? "" : message.message;
        final Finding.Report scam = ScamDetector.analyze(body, stranger);
        if (!scam.findings.isEmpty()) {
            text.append("\nТекст: ").append(scam.verdict()).append('\n');
            for (Finding f : scam.findings) {
                text.append(f.severity.mark).append(' ').append(f.text).append('\n');
            }
        }

        final List<IocExtractor.Ioc> iocs = IocExtractor.extract(body);
        final StringBuilder iocText = new StringBuilder();
        for (IocExtractor.Ioc ioc : iocs) {
            iocText.append(ioc.type).append(": ").append(IocExtractor.defang(ioc)).append('\n');
            if (ioc.type.equals("url")) {
                final UrlAnalyzer.UrlReport report = UrlAnalyzer.analyze(ioc.value);
                if (report.atLeast(Finding.Severity.NOTICE)) {
                    iocText.append("   ").append(report.verdict()).append('\n');
                }
            }
        }
        if (iocText.length() > 0) {
            text.append("\nИндикаторы (обезврежены):\n").append(iocText);
        }

        final StringBuilder decoded = new StringBuilder();
        for (String token : body.split("\\s+")) {
            if (token.length() < 12) {
                continue;
            }
            for (String line : Decoder.decode(token)) {
                decoded.append(token.length() > 24 ? token.substring(0, 24) + "…" : token).append(" → ").append(line).append('\n');
            }
        }
        if (decoded.length() > 0) {
            text.append("\nДекодирование:\n").append(decoded);
        }

        final String all = text.toString();
        final String iocsOnly = iocText.toString();
        final AlertDialog.Builder builder = new AlertDialog.Builder(activity)
            .setTitle("SecGram: анализ")
            .setMessage(all)
            .setPositiveButton("Закрыть", null)
            .setNeutralButton("Копировать", (d, w) -> AndroidUtilities.addToClipboard(all));
        if (!iocsOnly.isEmpty()) {
            builder.setNegativeButton("Копировать IOC", (d, w) -> AndroidUtilities.addToClipboard(iocsOnly));
        }
        builder.show();
    }
}
