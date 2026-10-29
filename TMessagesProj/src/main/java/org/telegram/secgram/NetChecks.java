/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.Utilities;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

// Explicit, user-requested network checks (port of secgram_net.cpp).
// They contact third parties from this phone, so they never run
// automatically.
public final class NetChecks {

    private NetChecks() {
    }

    private static String read(InputStream in) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) > 0 && out.size() < 512 * 1024) {
            out.write(buffer, 0, n);
        }
        return out.toString("UTF-8");
    }

    private static String day(Date date) {
        return new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(date);
    }

    // RDAP registration date + TLS certificate of host:443.
    public static void checkServer(String host, Utilities.Callback<String> done) {
        Utilities.globalQueue.postRunnable(() -> {
            final StringBuilder text = new StringBuilder();
            final Finding.Report report = new Finding.Report();
            try {
                final HttpURLConnection c = (HttpURLConnection) new URL("https://rdap.org/domain/" + UrlAnalyzer.registrableDomain(host)).openConnection();
                c.setConnectTimeout(12000);
                c.setReadTimeout(12000);
                c.setInstanceFollowRedirects(true);
                c.setRequestProperty("Accept", "application/rdap+json");
                final JSONObject json = new JSONObject(read(c.getInputStream()));
                c.disconnect();
                final JSONArray events = json.optJSONArray("events");
                if (events != null) {
                    for (int i = 0; i < events.length(); ++i) {
                        final JSONObject event = events.getJSONObject(i);
                        final String date = event.optString("eventDate", "");
                        if (date.length() < 10) {
                            continue;
                        }
                        if ("registration".equals(event.optString("eventAction"))) {
                            final Date registered = new SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(date.substring(0, 10));
                            final long days = (System.currentTimeMillis() - registered.getTime()) / 86400000L;
                            text.append("Домен зарегистрирован: ").append(date, 0, 10).append(" (").append(days).append(" дн. назад)\n");
                            if (days < 30) {
                                report.add(Finding.Severity.HIGH, "Домен создан всего " + days + " дн. назад — фишинговые сайты почти всегда совсем новые.");
                            } else if (days < 180) {
                                report.add(Finding.Severity.NOTICE, "Домену меньше полугода.");
                            }
                        } else if ("expiration".equals(event.optString("eventAction"))) {
                            text.append("Истекает: ").append(date, 0, 10).append('\n');
                        }
                    }
                }
            } catch (Exception e) {
                text.append("RDAP: нет данных (").append(e.getMessage()).append(")\n");
            }
            try {
                final HttpsURLConnection c = (HttpsURLConnection) new URL("https://" + host + "/").openConnection();
                c.setConnectTimeout(12000);
                c.setReadTimeout(12000);
                c.setRequestMethod("HEAD");
                c.connect();
                final Certificate[] chain = c.getServerCertificates();
                c.disconnect();
                if (chain.length > 0 && chain[0] instanceof X509Certificate) {
                    final X509Certificate cert = (X509Certificate) chain[0];
                    final long days = (System.currentTimeMillis() - cert.getNotBefore().getTime()) / 86400000L;
                    text.append("Сертификат выдан: ").append(cert.getIssuerX500Principal().getName())
                        .append(", ").append(day(cert.getNotBefore())).append(" (").append(days).append(" дн. назад), до ")
                        .append(day(cert.getNotAfter())).append('\n');
                    final Collection<List<?>> names = cert.getSubjectAlternativeNames();
                    if (names != null) {
                        final List<String> list = new ArrayList<>();
                        for (List<?> name : names) {
                            if (name.size() > 1 && list.size() < 8) {
                                list.add(String.valueOf(name.get(1)));
                            }
                        }
                        text.append("Домены в сертификате: ").append(Finding.join(", ", list)).append('\n');
                    }
                    if (days < 3) {
                        report.add(Finding.Severity.NOTICE, "Сертификат выпущен меньше 3 дней назад.");
                    }
                }
            } catch (javax.net.ssl.SSLException e) {
                report.add(Finding.Severity.HIGH, "Ошибка сертификата: " + e.getMessage());
            } catch (Exception e) {
                text.append("TLS: ").append(e.getMessage()).append('\n');
            }
            final StringBuilder result = new StringBuilder(report.verdict()).append('\n').append(text);
            for (Finding finding : report.findings) {
                result.append(finding.severity.mark).append(' ').append(finding.text).append('\n');
            }
            final String value = result.toString();
            AndroidUtilities.runOnUIThread(() -> done.run(value));
        });
    }

    // HEAD requests following Location headers.
    public static void expandRedirects(String url, Utilities.Callback<String> done) {
        Utilities.globalQueue.postRunnable(() -> {
            final StringBuilder text = new StringBuilder("Цепочка перенаправлений:\n");
            String current = url;
            try {
                for (int hop = 1; hop <= 10; ++hop) {
                    final UrlAnalyzer.UrlReport report = UrlAnalyzer.analyze(current);
                    text.append(hop).append(". ").append(report.max().mark).append(' ').append(LinkGuard.defang(current)).append('\n');
                    final HttpURLConnection c = (HttpURLConnection) new URL(current).openConnection();
                    c.setInstanceFollowRedirects(false);
                    c.setRequestMethod("HEAD");
                    c.setConnectTimeout(10000);
                    c.setReadTimeout(10000);
                    c.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36");
                    final int code = c.getResponseCode();
                    final String location = c.getHeaderField("Location");
                    c.disconnect();
                    if (code < 300 || code >= 400 || location == null) {
                        break;
                    }
                    current = new URL(new URL(current), location).toString();
                }
            } catch (Exception e) {
                text.append("Ошибка: ").append(e.getMessage());
            }
            final String value = text.toString();
            AndroidUtilities.runOnUIThread(() -> done.run(value));
        });
    }
}
