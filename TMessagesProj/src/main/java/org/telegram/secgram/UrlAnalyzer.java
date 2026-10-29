/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import java.net.IDN;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Port of the SecGram desktop link analysis (secgram_analyzer.cpp).
// Pure Java, no Android classes, so it can be tested with plain javac.
public final class UrlAnalyzer {

    public static final class UrlReport extends Finding.Report {
        public String scheme = "";
        public String host = ""; // Unicode, as displayed.
        public String asciiHost = ""; // Punycode, really resolved.
        public String registrableDomain = "";
        public String cleanUrl = "";
        public final List<String> trackingParams = new ArrayList<>();
    }

    private static Set<String> set(String list) {
        return new HashSet<>(Arrays.asList(list.split(" ")));
    }

    private static final Set<String> EXECUTABLE = set(
        "exe com scr pif bat cmd msi msp cpl dll hta js jse vbs vbe wsf wsh "
        + "ps1 reg lnk url scf inf chm jar jnlp appx msix iso img vhd "
        + "app pkg dmg command sh run bin deb rpm appimage apk apks xapk "
        + "aab ipa docm xlsm pptm");

    private static final Set<String> SHORTENERS = set(
        "bit.ly bitly.com tinyurl.com t.co goo.gl is.gd v.gd cutt.ly rb.gy "
        + "ow.ly buff.ly shorturl.at tiny.cc rebrand.ly s.id clck.ru qps.ru "
        + "u.to bit.do t.ly tiny.one shorte.st adf.ly lnkd.in clk.sh ouo.io");

    private static final Set<String> SUSPICIOUS_TLDS = set(
        "zip mov xyz top tk ml ga cf gq click country work support rest cam "
        + "icu buzz lol sbs cfd bond quest monster cyou beauty hair loan win "
        + "bid review men date racing download stream gdn kim");

    private static final Set<String> COMPOUND_SUFFIXES = set(
        "co.uk org.uk ac.uk gov.uk com.au net.au co.jp com.br com.tr co.in "
        + "com.cn com.ua co.za com.uz org.uz net.uz gov.uz edu.uz co.uz "
        + "com.kz gov.kz org.kz com.ru msk.ru spb.ru com.tj com.kg "
        + "github.io pages.dev workers.dev vercel.app netlify.app "
        + "herokuapp.com firebaseapp.com web.app appspot.com glitch.me "
        + "repl.co replit.dev ngrok.io ngrok-free.app ngrok.app "
        + "trycloudflare.com azurewebsites.net cloudfront.net blogspot.com "
        + "wixsite.com weebly.com 000webhostapp.com duckdns.org ddns.net "
        + "no-ip.org loca.lt serveo.net r2.dev onrender.com fly.dev "
        + "railway.app");

    private static final Set<String> FREE_HOSTING = set(
        "github.io pages.dev workers.dev vercel.app netlify.app herokuapp.com "
        + "firebaseapp.com web.app appspot.com glitch.me repl.co replit.dev "
        + "ngrok.io ngrok-free.app ngrok.app trycloudflare.com "
        + "azurewebsites.net blogspot.com wixsite.com weebly.com "
        + "000webhostapp.com duckdns.org ddns.net no-ip.org loca.lt "
        + "serveo.net r2.dev onrender.com fly.dev railway.app");

    private static final Set<String> TRACKING = set(
        "fbclid gclid dclid gbraid wbraid msclkid yclid ysclid igshid igsh "
        + "mc_cid mc_eid _hsenc _hsmi mkt_tok ref_src ref_url oly_anon_id "
        + "oly_enc_id vero_id rb_clickid __s wickedid twclid ttclid "
        + "li_fat_id epik _ga _gl spm scm srsltid");

    private static final String[] PHISHING_WORDS = {
        "login", "signin", "sign-in", "verify", "verification", "secure",
        "account", "update", "wallet", "recover", "unlock", "airdrop",
        "claim", "giveaway", "bonus", "premium", "gift", "auth", "password",
        "confirm", "support", "security", "kyc", "suspend", "blocked",
        "reward", "prize", "free",
    };

    private static final String[][] BRANDS = {
        { "telegram", "telegram.org t.me telegram.me telegram.dog telesco.pe telegra.ph fragment.com" },
        { "paypal", "paypal.com paypal.me" },
        { "google", "google.com goo.gl youtube.com gmail.com" },
        { "microsoft", "microsoft.com live.com office.com microsoftonline.com outlook.com azure.com windows.com" },
        { "apple", "apple.com icloud.com" },
        { "amazon", "amazon.com amazonaws.com" },
        { "facebook", "facebook.com fb.com fb.me meta.com" },
        { "instagram", "instagram.com" },
        { "whatsapp", "whatsapp.com whatsapp.net wa.me" },
        { "binance", "binance.com" },
        { "coinbase", "coinbase.com" },
        { "metamask", "metamask.io" },
        { "tonkeeper", "tonkeeper.com" },
        { "trustwallet", "trustwallet.com" },
        { "steamcommunity", "steamcommunity.com" },
        { "discord", "discord.com discord.gg discordapp.com" },
        { "netflix", "netflix.com" },
        { "github", "github.com github.io githubusercontent.com" },
        { "payme", "payme.uz paycom.uz" },
        { "uzcard", "uzcard.uz" },
        { "humocard", "humocard.uz" },
        { "kapitalbank", "kapitalbank.uz" },
        { "hamkorbank", "hamkorbank.uz" },
        { "agrobank", "agrobank.uz" },
        { "uzum", "uzum.uz uzumbank.uz" },
        { "gosuslugi", "gosuslugi.ru" },
        { "sberbank", "sberbank.ru sber.ru" },
        { "tinkoff", "tinkoff.ru tbank.ru" },
    };

    private static final String LOOKALIKE_CYRILLIC = "аеорсухіјѕԁһӏвкмнт";
    private static final String LOOKALIKE_LATIN = "aeopcyxijsdhlbkmht";

    private static final Pattern IPV4 = Pattern.compile(
        "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern NUMERIC_HOST = Pattern.compile(
        "^(0x[0-9a-f]+|\\d+)(\\.(0x[0-9a-f]+|\\d+))*$");
    private static final Pattern RAW_HOST = Pattern.compile(
        "^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/?#@]*@)?([^/?#:]+)");

    private UrlAnalyzer() {
    }

    public static String registrableDomain(String host) {
        final String[] labels = host.toLowerCase(Locale.ROOT).split("\\.");
        if (labels.length <= 2) {
            return host.toLowerCase(Locale.ROOT);
        }
        final String lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1];
        final int take = COMPOUND_SUFFIXES.contains(lastTwo) ? 3 : 2;
        final StringBuilder result = new StringBuilder();
        for (int i = labels.length - take; i < labels.length; ++i) {
            if (result.length() > 0) {
                result.append('.');
            }
            result.append(labels[i]);
        }
        return result.toString();
    }

    private static int editDistance(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] curr = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); ++j) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); ++i) {
            curr[0] = i;
            for (int j = 1; j <= b.length(); ++j) {
                final int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                curr[j] = Math.min(Math.min(prev[j] + 1, curr[j - 1] + 1), prev[j - 1] + cost);
            }
            final int[] t = prev;
            prev = curr;
            curr = t;
        }
        return prev[b.length()];
    }

    private static String normalizeLookalike(String label) {
        final StringBuilder b = new StringBuilder();
        for (int i = 0; i < label.length(); ++i) {
            final char c = label.charAt(i);
            final int index = LOOKALIKE_CYRILLIC.indexOf(c);
            b.append(index >= 0 ? LOOKALIKE_LATIN.charAt(index) : c);
        }
        return b.toString()
            .replace("rn", "m").replace("vv", "w").replace("cl", "d")
            .replace('0', 'o').replace('1', 'l').replace('3', 'e')
            .replace('4', 'a').replace('5', 's').replace('7', 't')
            .replace('8', 'b').replace('i', 'l');
    }

    private static String rawHost(String url) {
        final Matcher m = RAW_HOST.matcher(url.trim());
        return m.find() ? m.group(1).toLowerCase(Locale.ROOT) : "";
    }

    private static int[] parseIpv4(String host) {
        final Matcher m = IPV4.matcher(host);
        if (!m.matches()) {
            return null;
        }
        final int[] result = new int[4];
        for (int i = 0; i < 4; ++i) {
            result[i] = Integer.parseInt(m.group(i + 1));
            if (result[i] > 255) {
                return null;
            }
        }
        return result;
    }

    private static String privateRange(int[] ip) {
        if (ip[0] == 127) {
            return "этот компьютер (loopback)";
        } else if (ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)) {
            return "адрес локальной сети";
        } else if (ip[0] == 169 && ip[1] == 254) {
            return "link-local адрес";
        }
        return null;
    }

    public static String stripTracking(String url, List<String> removed) {
        final int q = url.indexOf('?');
        if (q < 0) {
            return url;
        }
        final int hash = url.indexOf('#', q);
        final String query = hash < 0 ? url.substring(q + 1) : url.substring(q + 1, hash);
        final String fragment = hash < 0 ? "" : url.substring(hash);
        final String host = rawHost(url);
        final boolean shareSi = host.endsWith("youtube.com") || host.equals("youtu.be") || host.endsWith("spotify.com");
        final StringBuilder kept = new StringBuilder();
        boolean changed = false;
        for (String part : query.split("&")) {
            if (part.isEmpty()) {
                continue;
            }
            final int eq = part.indexOf('=');
            final String key = (eq < 0 ? part : part.substring(0, eq)).toLowerCase(Locale.ROOT);
            if (key.startsWith("utm_") || TRACKING.contains(key) || (shareSi && key.equals("si"))) {
                changed = true;
                if (removed != null) {
                    removed.add(key);
                }
                continue;
            }
            if (kept.length() > 0) {
                kept.append('&');
            }
            kept.append(part);
        }
        if (!changed) {
            return url;
        }
        return url.substring(0, q) + (kept.length() > 0 ? "?" + kept : "") + fragment;
    }

    private static boolean mixedScripts(String label) {
        boolean latin = false, cyrillic = false, greek = false, other = false;
        for (int i = 0; i < label.length(); ) {
            final int cp = label.codePointAt(i);
            i += Character.charCount(cp);
            if (!Character.isLetter(cp)) {
                continue;
            }
            final Character.UnicodeScript script = Character.UnicodeScript.of(cp);
            if (script == Character.UnicodeScript.LATIN) {
                latin = true;
            } else if (script == Character.UnicodeScript.CYRILLIC) {
                cyrillic = true;
            } else if (script == Character.UnicodeScript.GREEK) {
                greek = true;
            } else {
                other = true;
            }
        }
        return (latin ? 1 : 0) + (cyrillic ? 1 : 0) + (greek ? 1 : 0) + (other ? 1 : 0) > 1;
    }

    private static boolean onlyLookalikes(String label) {
        boolean any = false;
        for (int i = 0; i < label.length(); ++i) {
            final char c = label.charAt(i);
            if (c < 0x80) {
                continue;
            }
            any = true;
            if (LOOKALIKE_CYRILLIC.indexOf(c) < 0) {
                return false;
            }
        }
        return any;
    }

    public static UrlReport analyze(String url) {
        final UrlReport result = new UrlReport();
        final String trimmed = url.trim();
        URI parsed;
        try {
            parsed = new URI(trimmed.contains("://") || trimmed.startsWith("javascript:") || trimmed.startsWith("data:") ? trimmed : ("https://" + trimmed));
        } catch (Exception e) {
            result.add(Finding.Severity.WARNING, "Ссылка повреждена или некорректна.");
            result.cleanUrl = trimmed;
            return result;
        }
        result.scheme = parsed.getScheme() == null ? "" : parsed.getScheme().toLowerCase(Locale.ROOT);
        result.cleanUrl = stripTracking(trimmed, result.trackingParams);

        switch (result.scheme) {
            case "javascript":
            case "vbscript":
            case "data":
                result.add(Finding.Severity.CRITICAL, "Ссылки «" + result.scheme + ":» выполняют код или встраивают содержимое — никогда их не открывайте.");
                return result;
            case "file":
            case "smb":
            case "intent":
                result.add(Finding.Severity.CRITICAL, "Ссылки «" + result.scheme + ":» открывают локальные файлы или приложения напрямую.");
                return result;
            case "http":
                result.add(Finding.Severity.NOTICE, "Соединение не зашифровано (http).");
                break;
            default:
                break;
        }

        if (parsed.getRawUserInfo() != null) {
            result.add(Finding.Severity.CRITICAL, "Всё до «@» («" + parsed.getRawUserInfo() + "») браузер игнорирует. Настоящий сайт — " + parsed.getHost() + ".");
        }

        String host = parsed.getHost();
        if (host == null) {
            host = rawHost(trimmed);
        }
        host = host == null ? "" : host.toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        String ascii;
        try {
            ascii = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            ascii = host;
        }
        result.asciiHost = ascii;
        try {
            result.host = IDN.toUnicode(ascii, IDN.ALLOW_UNASSIGNED);
        } catch (Exception e) {
            result.host = ascii;
        }
        if (!ascii.isEmpty()) {
            analyzeHost(result, trimmed);
        }

        final int port = parsed.getPort();
        if (port > 0 && port != 80 && port != 443) {
            result.add(Finding.Severity.WARNING, "Нестандартный порт " + port + ".");
        }

        final String path = parsed.getRawPath() == null ? "" : parsed.getRawPath();
        final String file = path.substring(path.lastIndexOf('/') + 1);
        final int dot = file.lastIndexOf('.');
        if (dot >= 0 && EXECUTABLE.contains(file.substring(dot + 1).toLowerCase(Locale.ROOT))) {
            result.add(Finding.Severity.HIGH, "Ссылка напрямую скачивает исполняемый или опасный файл (." + file.substring(dot + 1).toLowerCase(Locale.ROOT) + ").");
        }

        final String query = parsed.getRawQuery();
        if (query != null) {
            for (String part : query.split("&")) {
                final int eq = part.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                String value;
                try {
                    value = URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8.name());
                } catch (Exception e) {
                    continue;
                }
                if (value.startsWith("http://") || value.startsWith("https://") || value.startsWith("//")) {
                    final String target = rawHost(value.startsWith("//") ? "https:" + value : value);
                    if (!target.isEmpty() && !registrableDomain(target).equals(result.registrableDomain)) {
                        result.add(Finding.Severity.WARNING, "Параметр «" + part.substring(0, eq) + "» перенаправляет на другой сайт: " + target);
                        for (Finding f : analyze(value).findings) {
                            if (f.severity.ordinal() >= Finding.Severity.WARNING.ordinal()) {
                                result.add(f.severity, "Цель перенаправления: " + f.text);
                            }
                        }
                        break;
                    }
                }
            }
        }

        final String lowered = (ascii + path).toLowerCase(Locale.ROOT);
        final List<String> words = new ArrayList<>();
        for (String word : PHISHING_WORDS) {
            if (lowered.contains(word)) {
                words.add(word);
            }
        }
        if (!words.isEmpty()) {
            result.add(words.size() >= 2 ? Finding.Severity.WARNING : Finding.Severity.NOTICE, "Фишинговые слова в адресе: " + Finding.join(", ", words));
        }
        if (!result.trackingParams.isEmpty()) {
            result.add(Finding.Severity.INFO, "Параметры слежки: " + Finding.join(", ", result.trackingParams));
        }
        return result;
    }

    private static void analyzeHost(UrlReport result, String original) {
        final String host = result.asciiHost;
        final String raw = rawHost(original);
        if (!raw.isEmpty() && !raw.equals(host) && NUMERIC_HOST.matcher(raw).matches() && parseIpv4(raw) == null) {
            result.add(Finding.Severity.CRITICAL, "Хост «" + raw + "» — это замаскированная (десятичная, восьмеричная или шестнадцатеричная) запись IP-адреса.");
            return;
        }
        if (host.startsWith("[")) {
            result.add(Finding.Severity.HIGH, "Ссылка использует IPv6-адрес вместо доменного имени.");
            return;
        }
        final int[] ip = parseIpv4(host);
        if (ip != null) {
            result.add(Finding.Severity.HIGH, "Ссылка использует IP-адрес (" + host + ") вместо доменного имени.");
            final String range = privateRange(ip);
            if (range != null) {
                result.add(Finding.Severity.WARNING, "Адрес указывает на " + range + ". Вредоносные ссылки так атакуют роутер или локальные сервисы.");
            }
            return;
        }
        if (NUMERIC_HOST.matcher(host).matches()) {
            result.add(Finding.Severity.CRITICAL, "Хост «" + host + "» — замаскированный IP-адрес.");
            return;
        }
        result.registrableDomain = registrableDomain(host);
        final String[] labels = host.split("\\.");
        final String[] unicodeLabels = result.host.split("\\.");
        final String tld = labels[labels.length - 1];

        if (host.contains("xn--")) {
            boolean mixed = false, confusable = false;
            for (String label : unicodeLabels) {
                if (mixedScripts(label)) {
                    mixed = true;
                } else if (onlyLookalikes(label)) {
                    confusable = true;
                }
            }
            if (mixed) {
                result.add(Finding.Severity.CRITICAL, "Домен смешивает буквы разных алфавитов (атака гомоглифами). Настоящий адрес: " + host);
            } else if (confusable) {
                result.add(Finding.Severity.CRITICAL, "Домен написан нелатинскими буквами, которые выглядят как латинские. Настоящий адрес: " + host);
            } else {
                result.add(Finding.Severity.NOTICE, "Интернационализированный домен, настоящий адрес: " + host);
            }
        }

        brands:
        for (String[] brand : BRANDS) {
            final String name = brand[0];
            for (String legit : brand[1].split(" ")) {
                if (host.equals(legit) || host.endsWith("." + legit)) {
                    continue brands;
                }
            }
            for (int i = 0; i < labels.length - 1; ++i) {
                final String label = unicodeLabels.length == labels.length ? unicodeLabels[i] : labels[i];
                if (label.contains(name)) {
                    result.add(Finding.Severity.HIGH, "Адрес упоминает «" + name + "», но настоящий сайт — " + result.registrableDomain + ", это не официальный домен " + name + ".");
                    break brands;
                }
                if (name.length() < 5) {
                    continue;
                }
                final int limit = name.length() >= 7 ? 2 : 1;
                for (String piece : normalizeLookalike(label).split("-")) {
                    if (piece.length() < 4) {
                        continue;
                    }
                    if (piece.equals(name) && !label.equals(name)) {
                        result.add(Finding.Severity.HIGH, "«" + label + "» имитирует «" + name + "», заменяя буквы похожими символами.");
                        break brands;
                    }
                    final int distance = editDistance(piece, name);
                    if (distance > 0 && distance <= limit) {
                        result.add(Finding.Severity.HIGH, "«" + label + "» похоже на искажённое «" + name + "» (тайпсквоттинг).");
                        break brands;
                    }
                }
            }
        }

        if (tld.equals("onion") || tld.equals("i2p")) {
            result.add(Finding.Severity.WARNING, "Адрес сети " + (tld.equals("onion") ? "Tor (.onion)" : "I2P") + ": открывается только через Tor/I2P, часто ведёт в даркнет.");
        }
        if (SHORTENERS.contains(host)) {
            result.add(Finding.Severity.WARNING, "Это сокращатель ссылок: настоящий адрес скрыт до открытия.");
        }
        for (String suffix : FREE_HOSTING) {
            if (host.endsWith("." + suffix)) {
                result.add(Finding.Severity.WARNING, "Размещено на бесплатном хостинге или туннеле (" + suffix + "), их часто используют для фишинга.");
                break;
            }
        }
        if (SUSPICIOUS_TLDS.contains(tld)) {
            result.add(Finding.Severity.WARNING, "Доменная зона «." + tld + "» массово используется для спама и фишинга.");
        }
        if (labels.length >= 5) {
            result.add(Finding.Severity.NOTICE, "Необычно глубокая цепочка поддоменов (" + labels.length + " уровней).");
        }
        int hyphens = 0;
        for (char c : result.host.toCharArray()) {
            if (c == '-') {
                ++hyphens;
            }
        }
        if (hyphens >= 3) {
            result.add(Finding.Severity.NOTICE, "Много дефисов в имени домена — типично для фишинговых доменов.");
        }
    }
}
