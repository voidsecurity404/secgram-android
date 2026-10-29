/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Port of ExtractIocs from the desktop version (main indicator types).
public final class IocExtractor {

    public static final class Ioc {
        public final String type;
        public final String value;

        Ioc(String type, String value) {
            this.type = type;
            this.value = value;
        }
    }

    private static final Object[][] RULES = {
        { "url", Pattern.compile("(?i)\\b(?:https?|ftp)://[^\\s<>\"'`]+") },
        { "email", Pattern.compile("(?i)(?<![\\w.+-])[\\w.+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}\\b") },
        { "cve", Pattern.compile("(?i)\\bCVE-\\d{4}-\\d{4,7}\\b") },
        { "mitre", Pattern.compile("\\b(?:T[1-9]\\d{3}(?:\\.\\d{3})?|TA00\\d\\d)\\b") },
        { "sha256", Pattern.compile("(?<![0-9a-fA-Fx])[0-9a-fA-F]{64}(?![0-9a-fA-F])") },
        { "eth", Pattern.compile("\\b0x[0-9a-fA-F]{40}(?![0-9a-fA-F])") },
        { "sha1", Pattern.compile("(?<![0-9a-fA-Fx])[0-9a-fA-F]{40}(?![0-9a-fA-F])") },
        { "md5", Pattern.compile("(?<![0-9a-fA-Fx])[0-9a-fA-F]{32}(?![0-9a-fA-F])") },
        { "ton", Pattern.compile("(?<![\\w-])(?:EQ|UQ|kQ|0Q)[A-Za-z0-9_-]{46}(?![\\w-])") },
        { "btc", Pattern.compile("(?<![\\w])(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![\\w])") },
        { "ipv4", Pattern.compile("(?<![\\d.])(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?!\\.?\\d)") },
        { "telegram", Pattern.compile("(?<![\\w@./])@[A-Za-z][A-Za-z0-9_]{3,31}(?![\\w@])") },
        { "domain", Pattern.compile("(?i)(?<![\\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}(?![\\w-]|\\.\\w)") },
    };

    private static final String NOT_TLDS = " py sh md rs cc so cs pl ps rb ts js h c cpp txt log exe dll bin dat json xml yml yaml ini cfg conf pdf doc docx xls xlsx png jpg jpeg gif mp4 mp3 html htm php css java jar apk zip rar ";

    private IocExtractor() {
    }

    public static String refang(String text) {
        return text
            .replaceAll("(?i)\\bh(?:xx|XX)p(s?)", "http$1")
            .replace("[://]", "://").replace("[:]", ":")
            .replaceAll("(?i)\\s?[\\[({](?:\\.|dot)[\\])}]\\s?", ".")
            .replaceAll("(?i)\\s?[\\[({](?:@|at)[\\])}]\\s?", "@");
    }

    public static List<Ioc> extract(String original) {
        final String text = refang(original == null ? "" : original);
        final List<int[]> taken = new ArrayList<>();
        final Map<String, Ioc> result = new LinkedHashMap<>();
        for (Object[] rule : RULES) {
            final String type = (String) rule[0];
            final Matcher m = ((Pattern) rule[1]).matcher(text);
            while (m.find()) {
                String value = m.group();
                if (type.equals("url")) {
                    value = value.replaceAll("[.,;:!?'\")\\]>}]+$", "");
                }
                final int from = m.start();
                final int till = from + value.length();
                boolean overlaps = false;
                for (int[] range : taken) {
                    if (from < range[1] && range[0] < till) {
                        overlaps = true;
                        break;
                    }
                }
                if (overlaps || value.isEmpty()) {
                    continue;
                }
                if (type.equals("domain")) {
                    final String[] labels = value.split("\\.");
                    final String tld = labels[labels.length - 1].toLowerCase(Locale.ROOT);
                    if (labels.length == 2 && NOT_TLDS.contains(" " + tld + " ")) {
                        continue;
                    }
                }
                taken.add(new int[] { from, till });
                final String normalized = type.equals("cve") ? value.toUpperCase(Locale.ROOT)
                    : (type.equals("domain") || type.startsWith("sha") || type.equals("md5")) ? value.toLowerCase(Locale.ROOT)
                    : value;
                result.put(type + ":" + normalized, new Ioc(type, normalized));
                if (type.equals("url")) {
                    final String host = value.replaceFirst("(?i)^[a-z]+://", "").replaceFirst("[/?#:].*$", "").toLowerCase(Locale.ROOT);
                    if (host.contains(".")) {
                        result.put("domain:" + host, new Ioc("domain", host));
                    }
                }
            }
        }
        return new ArrayList<>(result.values());
    }

    public static String defang(Ioc ioc) {
        switch (ioc.type) {
            case "url":
                return LinkGuard.defang(ioc.value);
            case "domain":
            case "ipv4":
            case "email":
                return ioc.value.replace(".", "[.]").replace("@", "[@]");
            default:
                return ioc.value;
        }
    }
}
