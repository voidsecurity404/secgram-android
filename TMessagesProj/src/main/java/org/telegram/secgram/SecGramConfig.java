/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.content.Context;
import android.content.SharedPreferences;

import org.telegram.messenger.ApplicationLoader;

// SecGram switches, stored apart from the Telegram settings.
public final class SecGramConfig {

    public static final String LINK_GUARD = "link_guard";
    public static final String CONFIRM_ALL_LINKS = "confirm_all_links";
    public static final String STRIP_TRACKING = "strip_tracking";
    public static final String SCAM_DETECTOR = "scam_detector";
    public static final String GHOST_READ = "ghost_read";
    public static final String GHOST_TYPING = "ghost_typing";
    public static final String GHOST_ONLINE = "ghost_online";
    public static final String GHOST_STORIES = "ghost_stories";
    public static final String KEEP_DELETED = "keep_deleted";
    public static final String KEEP_EDITS = "keep_edits";
    public static final String FILE_GUARD = "file_guard";
    public static final String STRIP_METADATA = "strip_metadata";

    private SecGramConfig() {
    }

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences(
            "secgram",
            Context.MODE_PRIVATE);
    }

    private static boolean defaultValue(String key) {
        switch (key) {
            case LINK_GUARD:
            case STRIP_TRACKING:
            case SCAM_DETECTOR:
            case KEEP_DELETED:
            case KEEP_EDITS:
            case FILE_GUARD:
            case STRIP_METADATA:
                return true;
            default:
                return false;
        }
    }

    public static boolean get(String key) {
        if (ApplicationLoader.applicationContext == null) {
            return defaultValue(key);
        }
        return prefs().getBoolean(key, defaultValue(key));
    }

    public static void set(String key, boolean value) {
        prefs().edit().putBoolean(key, value).apply();
    }

    public static boolean linkGuard() {
        return get(LINK_GUARD);
    }

    public static boolean ghostRead() {
        return get(GHOST_READ);
    }

    public static boolean ghostTyping() {
        return get(GHOST_TYPING);
    }

    public static boolean ghostOnline() {
        return get(GHOST_ONLINE);
    }

    public static boolean ghostStories() {
        return get(GHOST_STORIES);
    }

    public static boolean keepDeleted() {
        return get(KEEP_DELETED);
    }

    public static boolean keepEdits() {
        return get(KEEP_EDITS);
    }
}
