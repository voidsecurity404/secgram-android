/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import java.util.ArrayList;
import java.util.List;

public final class Finding {

    public enum Severity {
        INFO("Инфо", "⚪"),
        NOTICE("Низкий", "🔵"),
        WARNING("Средний", "🟡"),
        HIGH("Высокий", "🟠"),
        CRITICAL("Критический", "🔴");

        public final String title;
        public final String mark;

        Severity(String title, String mark) {
            this.title = title;
            this.mark = mark;
        }
    }

    public final Severity severity;
    public final String text;

    public Finding(Severity severity, String text) {
        this.severity = severity;
        this.text = text;
    }

    // String.join needs API 26, SecGram supports API 23.
    public static String join(String separator, Iterable<String> parts) {
        final StringBuilder result = new StringBuilder();
        for (String part : parts) {
            if (result.length() > 0) {
                result.append(separator);
            }
            result.append(part);
        }
        return result.toString();
    }

    public static class Report {
        public final List<Finding> findings = new ArrayList<>();

        public void add(Severity severity, String text) {
            findings.add(new Finding(severity, text));
        }

        public Severity max() {
            Severity result = Severity.INFO;
            for (Finding finding : findings) {
                if (finding.severity.ordinal() > result.ordinal()) {
                    result = finding.severity;
                }
            }
            return result;
        }

        public boolean atLeast(Severity severity) {
            return !findings.isEmpty() && max().ordinal() >= severity.ordinal();
        }

        public String verdict() {
            if (!atLeast(Severity.NOTICE)) {
                return "Известных угроз не найдено";
            }
            final Severity max = max();
            return max.mark + " Риск: " + max.title;
        }
    }
}
