/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.content.Context;
import android.content.SharedPreferences;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.Utilities;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

// Own allow / block domain lists and public phishing feeds
// (OpenPhish, Phishing Army) checked locally by the link guard.
public final class ThreatData {

    public enum Listed { NONE, ALLOWED, BLOCKED }

    private static Map<String, String> feedHosts;

    private ThreatData() {
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences("secgram", Context.MODE_PRIVATE);
    }

    public static String domainListsText() {
        return prefs().getString("domains", "");
    }

    public static void setDomainListsText(String text) {
        prefs().edit().putString("domains", text).apply();
    }

    private static boolean hostMatches(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }

    public static Listed listed(String host) {
        if (host == null || host.isEmpty()) {
            return Listed.NONE;
        }
        final String lower = host.toLowerCase(Locale.ROOT);
        Listed result = Listed.NONE;
        for (String line : domainListsText().split("\n")) {
            line = IocExtractor.refang(line.trim()).toLowerCase(Locale.ROOT);
            if (line.length() < 2) {
                continue;
            }
            final String domain = line.substring(1).trim();
            if (line.charAt(0) == '-' && hostMatches(lower, domain)) {
                return Listed.BLOCKED;
            } else if (line.charAt(0) == '+' && hostMatches(lower, domain)) {
                result = Listed.ALLOWED;
            }
        }
        return result;
    }

    private static File feedFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), "secgram_feeds.txt");
    }

    private static synchronized Map<String, String> feeds() {
        if (feedHosts != null) {
            return feedHosts;
        }
        final Map<String, String> result = new HashMap<>();
        final File file = feedFile();
        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    final int tab = line.indexOf('\t');
                    if (tab > 0) {
                        result.put(line.substring(tab + 1), line.substring(0, tab));
                    }
                }
            } catch (Exception ignore) {
            }
        }
        return feedHosts = result;
    }

    // Name of the feed listing this host or one of its parents.
    public static String feedMatch(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }
        final Map<String, String> feeds = feeds();
        String current = host.toLowerCase(Locale.ROOT);
        while (!current.isEmpty()) {
            final String source = feeds.get(current);
            if (source != null) {
                return source;
            }
            final int dot = current.indexOf('.');
            if (dot < 0) {
                break;
            }
            current = current.substring(dot + 1);
        }
        return null;
    }

    public static String feedsInfo() {
        final File file = feedFile();
        if (!file.exists()) {
            return "база не загружена";
        }
        return feeds().size() + " доменов, обновлено "
            + new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date(file.lastModified()));
    }

    // Downloads the feeds, done(count, error) on the UI thread.
    public static void updateFeeds(Utilities.Callback2<Integer, String> done) {
        Utilities.globalQueue.postRunnable(() -> {
            final String[][] sources = {
                { "OpenPhish", "https://openphish.com/feed.txt" },
                { "Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt" },
            };
            final StringBuilder out = new StringBuilder();
            final StringBuilder errors = new StringBuilder();
            int count = 0;
            for (String[] source : sources) {
                HttpURLConnection connection = null;
                try {
                    connection = (HttpURLConnection) new URL(source[1]).openConnection();
                    connection.setConnectTimeout(15000);
                    connection.setReadTimeout(30000);
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            line = line.trim();
                            if (line.isEmpty() || line.startsWith("#")) {
                                continue;
                            }
                            String host = line;
                            if (line.contains("://")) {
                                host = line.replaceFirst("(?i)^[a-z]+://", "").replaceFirst("[/?#:].*$", "");
                                // Shared services list one bad path, not the whole host.
                                final String reg = UrlAnalyzer.registrableDomain(host);
                                if (!reg.equals(host.toLowerCase(Locale.ROOT)) && (reg.equals("google.com") || reg.equals("github.com") || reg.equals("dropbox.com") || reg.equals("microsoft.com") || reg.equals("sharepoint.com"))) {
                                    continue;
                                }
                            }
                            out.append(source[0]).append('\t').append(host.toLowerCase(Locale.ROOT)).append('\n');
                            ++count;
                        }
                    }
                } catch (Exception e) {
                    errors.append(source[0]).append(": ").append(e.getMessage()).append("; ");
                } finally {
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
            if (count > 0) {
                try (FileWriter writer = new FileWriter(feedFile())) {
                    writer.write(out.toString());
                } catch (Exception e) {
                    errors.append(e.getMessage());
                }
                synchronized (ThreatData.class) {
                    feedHosts = null;
                }
            }
            final int total = count;
            final String error = errors.toString();
            AndroidUtilities.runOnUIThread(() -> done.run(total, error));
        });
    }
}
