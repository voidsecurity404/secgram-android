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

        // Inline bot buttons hide where they lead: show it.
        if (message.reply_markup instanceof TLRPC.TL_replyInlineMarkup) {
            int index = 0;
            for (org.telegram.tgnet.tl.TL_keyboard.KeyboardInlineButtonRow row : ((TLRPC.TL_replyInlineMarkup) message.reply_markup).rows) {
                for (org.telegram.tgnet.tl.TL_keyboard.KeyboardInlineButton button : row.buttons) {
                    ++index;
                    final org.telegram.tgnet.tl.TL_keyboard.InlineButtonType type = button.type;
                    String kind = null;
                    String target = null;
                    if (type instanceof org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeUrl) {
                        kind = "ссылка";
                        target = ((org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeUrl) type).url;
                    } else if (type instanceof org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeUrlAuth) {
                        kind = "вход через Telegram";
                        target = ((org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeUrlAuth) type).url;
                    } else if (type instanceof org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeWebView) {
                        kind = "мини-приложение";
                        target = ((org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeWebView) type).url;
                    } else if (type instanceof org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeCallback) {
                        final byte[] data = ((org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeCallback) type).data;
                        kind = "callback";
                        target = data == null ? "" : new String(data, java.nio.charset.StandardCharsets.UTF_8);
                    } else if (type instanceof org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeCopy) {
                        kind = "копирует текст";
                        target = ((org.telegram.tgnet.tl.TL_keyboard.TL_inlineButtonTypeCopy) type).copy_text;
                    }
                    if (kind == null) {
                        continue;
                    }
                    text.append("Кнопка ").append(index).append(": «").append(button.text).append("» — ").append(kind);
                    if (target != null && !target.isEmpty()) {
                        text.append(": ").append(target.length() > 300 ? target.substring(0, 300) : target);
                        if (target.contains("://")) {
                            text.append("  ").append(UrlAnalyzer.analyze(target).verdict());
                        }
                    }
                    text.append('\n');
                }
            }
        }
        if (object.getDocument() != null) {
            for (TLRPC.DocumentAttribute attribute : object.getDocument().attributes) {
                // Since 2021 a sticker set id keeps its creator id in the high bits.
                if (attribute instanceof TLRPC.TL_documentAttributeSticker
                    && attribute.stickerset instanceof TLRPC.TL_inputStickerSetID
                    && (attribute.stickerset.id >>> 32) != 0) {
                    text.append("Создатель набора стикеров: вероятно, пользователь ID ").append(attribute.stickerset.id >>> 32).append('\n');
                }
            }
        }

        final TLRPC.User sender = fromId > 0 ? controller.getUser(fromId) : null;
        final boolean stranger = sender != null && !sender.contact && !sender.self && !sender.bot && dialogId > 0;
        final Finding.Report risk = senderRisk(sender, fromId);
        final String impersonated = SecGramTools.impersonatedContact(account, sender);
        if (impersonated != null) {
            risk.add(Finding.Severity.HIGH, "Имя совпадает с вашим контактом «" + impersonated + "», но это ДРУГОЙ аккаунт (ID " + fromId + "). Классическая подмена знакомого.");
        }
        if (fromId != 0) {
            final String history = SecGramTools.nameHistory(account, fromId);
            if (!history.isEmpty()) {
                text.append("\nИстория имён отправителя:\n").append(history);
            }
            final String note = SecGramTools.note(account, fromId);
            if (!note.isEmpty()) {
                text.append("\n📝 Ваша заметка: ").append(note).append('\n');
            }
        }
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

        final java.io.File local = org.telegram.messenger.FileLoader.getInstance(account).getPathToMessage(message);
        // Only containers, and not huge ones: this runs on the UI thread.
        if (object.getDocument() != null && local != null && local.exists() && local.length() <= 16L * 1024 * 1024
            && FileGuard.isContainer(FileGuard.readHead(local))) {
            try (java.io.InputStream in = new java.io.FileInputStream(local)) {
                final byte[] data = new byte[(int) local.length()];
                int read = 0;
                while (read < data.length) {
                    final int n = in.read(data, read, data.length - read);
                    if (n <= 0) {
                        break;
                    }
                    read += n;
                }
                final ContainerAnalyzer.Result container = ContainerAnalyzer.analyze(data);
                if (!container.findings.isEmpty() || !container.summary.isEmpty()) {
                    text.append("\nСодержимое файла: ").append(container.verdict()).append('\n');
                    for (Finding f : container.findings) {
                        text.append(f.severity.mark).append(' ').append(f.text).append('\n');
                    }
                    if (!container.summary.isEmpty()) {
                        text.append(container.summary.length() > 1200 ? container.summary.substring(0, 1200) + "…" : container.summary).append('\n');
                    }
                }
            } catch (Throwable ignore) {
            }
        }

        final String all = text.toString();
        new AlertDialog.Builder(activity)
            .setTitle("SecGram: анализ")
            .setMessage(all)
            .setPositiveButton("Закрыть", null)
            .setNegativeButton("Копировать", (d, w) -> AndroidUtilities.addToClipboard(all))
            .setNeutralButton("Ещё…", (d, w) -> showActions(activity, account, object, iocs, iocText.toString(), local))
            .show();
    }

    private static void showActions(Activity activity, int account, MessageObject object, List<IocExtractor.Ioc> iocs, String iocsText, java.io.File local) {
        final long dialogId = object.getDialogId();
        final long fromId = object.getFromChatId();
        final boolean ghost = SecGramTools.ghostChat(dialogId);
        final boolean collect = SecGramTools.collectChat(dialogId);
        final boolean hasFile = local != null && local.exists();
        final java.util.ArrayList<CharSequence> items = new java.util.ArrayList<>();
        final java.util.ArrayList<Runnable> actions = new java.util.ArrayList<>();
        if (!iocs.isEmpty()) {
            items.add("Копировать IOC (обезвреженные)");
            actions.add(() -> AndroidUtilities.addToClipboard(iocsText));
            items.add("Проверить IOC: VirusTotal, AbuseIPDB, Shodan…");
            actions.add(() -> SecGramTools.showLookups(activity, iocs));
            items.add("Экспорт IOC: JSON / CSV / STIX / MISP / TheHive");
            actions.add(() -> SecGramTools.exportIocs(activity, iocs));
        }
        if (hasFile) {
            items.add("Хеши файла и VirusTotal");
            actions.add(() -> org.telegram.messenger.Utilities.globalQueue.postRunnable(() -> {
                final String[] hashes = SecGramTools.fileHashes(local);
                AndroidUtilities.runOnUIThread(() -> {
                    if (hashes == null) {
                        return;
                    }
                    final String value = "SHA-256: " + hashes[0] + "\nSHA-1: " + hashes[1] + "\nMD5: " + hashes[2];
                    new AlertDialog.Builder(activity)
                        .setTitle("Хеши файла")
                        .setMessage(value + "\n\nVirusTotal ищет по хешу — сам файл никуда не отправляется.")
                        .setPositiveButton("VirusTotal", (d, w) -> org.telegram.messenger.browser.Browser.openUrl(activity, "https://www.virustotal.com/gui/file/" + hashes[0]))
                        .setNegativeButton("Копировать", (d, w) -> AndroidUtilities.addToClipboard(value))
                        .show();
                });
            }));
        }
        items.add("Экспорт доказательств (ZIP с SHA-256)");
        actions.add(() -> SecGramTools.exportEvidence(activity, account, object));
        if (fromId != 0) {
            items.add("Заметка об отправителе");
            actions.add(() -> SecGramTools.showNoteEditor(activity, account, fromId, String.valueOf(fromId)));
        }
        items.add(ghost ? "Выключить ghost-режим в этом чате" : "Ghost-режим в этом чате (не отмечать прочитанным)");
        actions.add(() -> {
            SecGramTools.setGhostChat(dialogId, !ghost);
            android.widget.Toast.makeText(activity, ghost ? "Ghost-режим в чате выключен" : "Собеседник не увидит прочтения в этом чате", android.widget.Toast.LENGTH_SHORT).show();
        });
        items.add(collect ? "Не собирать IOC из этого чата" : "Собирать IOC из этого чата в CSV");
        actions.add(() -> {
            SecGramTools.setCollectChat(dialogId, !collect);
            android.widget.Toast.makeText(activity, collect ? "Сбор IOC остановлен" : "Новые индикаторы пишутся в " + SecGramTools.iocFeedFile().getAbsolutePath(), android.widget.Toast.LENGTH_LONG).show();
        });
        items.add("Поиск regex в этом чате");
        actions.add(() -> SecGramTools.showRegexSearch(activity, account, dialogId));
        items.add("Шаблоны ответов");
        actions.add(() -> SecGramTools.showTemplates(activity));
        new AlertDialog.Builder(activity)
            .setTitle("SecGram")
            .setItems(items.toArray(new CharSequence[0]), (d, which) -> actions.get(which).run())
            .setNegativeButton("Отмена", null)
            .show();
    }
}
