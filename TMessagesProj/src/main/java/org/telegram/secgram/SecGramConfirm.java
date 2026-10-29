/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.LaunchActivity;

// Small confirmations and masks used from Telegram code.
public final class SecGramConfirm {

    private static boolean confirmed;

    private SecGramConfirm() {
    }

    public static boolean needsRevokeConfirmation() {
        return !confirmed && SecGramConfig.get(SecGramConfig.CONFIRM_REVOKE);
    }

    // "Delete for everyone" can't be undone and may destroy evidence.
    public static void confirmRevoke(int count, Runnable delete) {
        final BaseFragment fragment = LaunchActivity.getLastFragment();
        if (fragment == null || fragment.getParentActivity() == null) {
            run(delete);
            return;
        }
        final AlertDialog dialog = new AlertDialog.Builder(fragment.getParentActivity())
            .setTitle("Удалить у всех?")
            .setMessage("Сообщения (" + count + ") будут удалены и у собеседника. Это нельзя отменить, а удалённое может понадобиться как доказательство.")
            .setPositiveButton("Удалить у всех", (d, w) -> run(delete))
            .setNegativeButton("Отмена", null)
            .show();
        dialog.redPositive();
    }

    private static void run(Runnable action) {
        confirmed = true;
        try {
            action.run();
        } finally {
            confirmed = false;
        }
    }

    // "+998 90 123 45 67" -> "+998 •• ••• •• 67"
    public static String maskPhone(String formatted) {
        if (formatted == null || !SecGramConfig.get(SecGramConfig.HIDE_PHONE)) {
            return formatted;
        }
        final char[] chars = formatted.toCharArray();
        int digits = 0;
        for (int i = chars.length - 1; i >= 0; --i) {
            if (Character.isDigit(chars[i]) && ++digits > 2) {
                chars[i] = '•';
            }
        }
        // Keep the country code readable.
        for (int i = 1; i < chars.length && chars[i] != ' '; ++i) {
            if (chars[i] == '•') {
                chars[i] = formatted.charAt(i);
            }
        }
        return new String(chars);
    }
}
