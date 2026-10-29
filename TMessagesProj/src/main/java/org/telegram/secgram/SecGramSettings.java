/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.content.Context;
import android.widget.LinearLayout;
import android.widget.ScrollView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextCheckCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;

// "Безопасность SecGram": all switches in one dialog.
public final class SecGramSettings {

    private SecGramSettings() {
    }

    private static final String[][] ROWS = {
        { "#", "Защита аккаунта" },
        { SecGramConfig.LOGIN_CODE_GUARD, "Защита кода входа", "Предупреждать при попытке отправить код входа от Telegram — главный способ угона аккаунтов." },
        { "#", "Защита" },
        { SecGramConfig.LINK_GUARD, "Проверка ссылок", "Анализ каждой ссылки: поддельные буквы, имитация брендов и банков, IP-адреса, сокращатели, перенаправления, скачивание APK." },
        { SecGramConfig.CONFIRM_ALL_LINKS, "Подтверждать каждую ссылку", "Показывать анализ даже для безопасных на вид ссылок." },
        { SecGramConfig.FILE_GUARD, "Проверка файлов", "Перед открытием: RTLO, двойные расширения, замаскированные APK и программы, анализ разрешений APK (банковские трояны)." },
        { SecGramConfig.WATCHLIST, "Список наблюдения", "Уведомлять, когда во входящих появляется слово, домен, IP или кошелёк из списка (редактируется ниже)." },
        { SecGramConfig.SCAM_DETECTOR, "Детектор мошенничества", "Предупреждать о сообщениях с признаками мошенничества (призы, «бесплатный Premium», блокировка карты, просьба кода)." },
        { "#", "Удалённые и изменённые" },
        { SecGramConfig.KEEP_DELETED, "Оставлять удалённые в чате", "Удалённые собеседником сообщения остаются с пометкой «Удалено» и временем. Видно только вам." },
        { SecGramConfig.KEEP_EDITS, "Показывать прежние версии", "У изменённых сообщений видно, что было до правки." },
        { "#", "Конфиденциальность" },
        { SecGramConfig.STRIP_METADATA, "Удалять метаданные фото и видео", "GPS-координаты, модель камеры и серийные номера удаляются из JPEG, PNG и MP4, отправленных файлом." },
        { SecGramConfig.STRIP_TRACKING, "Удалять трекеры из ссылок", "utm_*, fbclid, gclid и другие параметры слежки." },
        { SecGramConfig.GHOST_READ, "Не отправлять отметку о прочтении", "Отправитель не увидит двойную галочку." },
        { SecGramConfig.GHOST_TYPING, "Скрывать «печатает…»", "Не отправлять статусы набора, записи и загрузки." },
        { SecGramConfig.GHOST_ONLINE, "Всегда оффлайн", "Не сообщать статус «в сети»." },
        { SecGramConfig.GHOST_STORIES, "Незаметный просмотр историй", "Автор истории не узнает о просмотре." },
    };

    private static void showWatchlist(Context context) {
        final android.widget.EditText field = new android.widget.EditText(context);
        field.setText(SecGramWatcher.watchlistText());
        field.setHint("mycompany.uz\n10.20.30.40\nre:пароль|parol");
        field.setMinLines(5);
        field.setGravity(android.view.Gravity.TOP);
        final LinearLayout box = new LinearLayout(context);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(AndroidUtilities.dp(24), AndroidUtilities.dp(8), AndroidUtilities.dp(24), 0);
        box.addView(field);
        final android.widget.TextView hits = new android.widget.TextView(context);
        final String text = SecGramWatcher.hitsText();
        hits.setText(text.isEmpty() ? "Совпадений пока нет." : "Последние совпадения:\n" + text);
        hits.setTextIsSelectable(true);
        hits.setPadding(0, AndroidUtilities.dp(12), 0, 0);
        box.addView(hits);
        final ScrollView scroll = new ScrollView(context);
        scroll.addView(box);
        new AlertDialog.Builder(context)
            .setTitle("Список наблюдения")
            .setView(scroll)
            .setPositiveButton("Сохранить", (d, w) -> SecGramWatcher.setWatchlistText(field.getText().toString()))
            .setNegativeButton("Отмена", null)
            .show();
    }

    public static void show(Context context) {
        if (context == null) {
            return;
        }
        final LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        for (String[] row : ROWS) {
            if (row[0].equals("#")) {
                final HeaderCell header = new HeaderCell(context);
                header.setText(row[1]);
                layout.addView(header);
                continue;
            }
            final String key = row[0];
            final TextCheckCell cell = new TextCheckCell(context);
            cell.setTextAndValueAndCheck(row[1], row[2], SecGramConfig.get(key), true, true);
            cell.setOnClickListener(v -> {
                final boolean value = !SecGramConfig.get(key);
                SecGramConfig.set(key, value);
                cell.setChecked(value);
            });
            layout.addView(cell);
        }
        final org.telegram.ui.Cells.TextSettingsCell watch = new org.telegram.ui.Cells.TextSettingsCell(context);
        watch.setText("Редактировать список наблюдения", true);
        watch.setOnClickListener(v -> showWatchlist(context));
        layout.addView(watch);

        final TextInfoPrivacyCell info = new TextInfoPrivacyCell(context);
        info.setText("SecGram для Android — неофициальный клиент Telegram. Остальные функции настольной версии переносятся постепенно.");
        layout.addView(info);

        final ScrollView scroll = new ScrollView(context);
        scroll.addView(layout);
        new AlertDialog.Builder(context)
            .setTitle("Безопасность SecGram")
            .setView(scroll)
            .setPositiveButton("Готово", null)
            .show();
    }
}
