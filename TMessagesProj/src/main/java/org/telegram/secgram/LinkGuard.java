/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.content.Context;
import android.net.Uri;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.Utilities;
import org.telegram.ui.ActionBar.AlertDialog;

// Shows the link analysis before an external link is opened.
public final class LinkGuard {

    private static boolean bypass;

    private LinkGuard() {
    }

    // Returns true if opening was taken over by a warning dialog.
    // `open` receives the url to open (possibly without trackers).
    public static boolean intercept(Context context, Uri uri, Utilities.Callback<Uri> open) {
        if (bypass || context == null || uri == null) {
            return false;
        }
        final String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!scheme.equals("http") && !scheme.equals("https") && !scheme.equals("javascript") && !scheme.equals("data")) {
            return false;
        }
        final String url = uri.toString();
        final UrlAnalyzer.UrlReport report = UrlAnalyzer.analyze(url);
        final boolean strip = SecGramConfig.get(SecGramConfig.STRIP_TRACKING);
        final Uri target = strip && !report.cleanUrl.equals(url) ? Uri.parse(report.cleanUrl) : uri;
        if (!SecGramConfig.linkGuard()
            || (!SecGramConfig.get(SecGramConfig.CONFIRM_ALL_LINKS)
                && !report.atLeast(Finding.Severity.WARNING))) {
            if (target != uri) {
                openBypassed(open, target);
                return true;
            }
            return false;
        }
        show(context, report, url, open, target);
        return true;
    }

    private static void openBypassed(Utilities.Callback<Uri> open, Uri target) {
        bypass = true;
        try {
            open.run(target);
        } finally {
            bypass = false;
        }
    }

    public static void show(Context context, UrlAnalyzer.UrlReport report, String url, Utilities.Callback<Uri> open, Uri target) {
        final SpannableStringBuilder text = new SpannableStringBuilder();
        text.append(AndroidUtilities.replaceTags("**" + report.verdict() + "**")).append("\n\n");
        text.append(url).append("\n");
        if (!TextUtils.isEmpty(report.asciiHost)) {
            text.append("\nХост: ").append(report.asciiHost);
            if (!report.host.equals(report.asciiHost)) {
                text.append(" (отображается как ").append(report.host).append(")");
            }
            if (!TextUtils.isEmpty(report.registrableDomain)) {
                text.append("\nДомен: ").append(report.registrableDomain);
            }
            text.append("\n");
        }
        for (Finding finding : report.findings) {
            text.append("\n").append(finding.severity.mark).append(" ")
                .append(finding.severity.title).append(": ").append(finding.text);
        }
        final boolean dangerous = report.atLeast(Finding.Severity.HIGH);
        final AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle("Проверка ссылки");
        builder.setMessage(text);
        if (open != null) {
            builder.setPositiveButton(dangerous ? "Всё равно открыть" : "Открыть", (dialog, which) -> openBypassed(open, target));
        }
        builder.setNegativeButton("Отмена", null);
        builder.setNeutralButton("Копировать обезвреженной", (dialog, which) ->
            AndroidUtilities.addToClipboard(defang(url)));
        final AlertDialog dialog = builder.show();
        if (dangerous && open != null) {
            dialog.redPositive();
        }
    }

    public static String defang(String url) {
        String result = url.replaceFirst("(?i)^http", "hxxp");
        final int start = result.indexOf("://");
        if (start < 0) {
            return result.replace(".", "[.]");
        }
        int end = result.indexOf('/', start + 3);
        if (end < 0) {
            end = result.length();
        }
        return result.substring(0, start) + "[://]"
            + result.substring(start + 3, end).replace(".", "[.]").replace("@", "[@]")
            + result.substring(end);
    }
}
