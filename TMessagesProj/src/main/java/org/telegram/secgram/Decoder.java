/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.util.Base64;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

// Port of DecodeText: Base64, Hex, URL encoding, JWT and hash types.
public final class Decoder {

    private static final Pattern BASE64 = Pattern.compile("^[A-Za-z0-9+/_-]{12,}={0,2}$");
    private static final Pattern HEX = Pattern.compile("^(?:0x)?(?:[0-9a-fA-F]{2}[\\s:]?){6,}$");
    private static final Pattern HEX_ONLY = Pattern.compile("^[0-9a-fA-F]+$");

    private Decoder() {
    }

    private static boolean printable(String s) {
        if (s.isEmpty() || s.indexOf('�') >= 0) {
            return false;
        }
        int good = 0;
        for (char c : s.toCharArray()) {
            if (c >= 0x20 || c == '\n' || c == '\r' || c == '\t') {
                ++good;
            }
        }
        return good * 100 >= s.length() * 95;
    }

    private static String hashKind(String v) {
        if (v.startsWith("$2a$") || v.startsWith("$2b$") || v.startsWith("$2y$")) {
            return "bcrypt";
        } else if (v.startsWith("$argon2")) {
            return "Argon2";
        } else if (v.startsWith("$6$")) {
            return "SHA-512 crypt";
        } else if (v.startsWith("$1$")) {
            return "MD5 crypt";
        } else if (!HEX_ONLY.matcher(v).matches()) {
            return null;
        }
        switch (v.length()) {
            case 32: return "MD5, NTLM, MD4 или LM";
            case 40: return "SHA-1 или RIPEMD-160";
            case 64: return "SHA-256 / SHA3-256";
            case 128: return "SHA-512 / SHA3-512";
            default: return null;
        }
    }

    private static byte[] base64(String v) {
        try {
            return (v.contains("-") || v.contains("_"))
                ? Base64.decode(v, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING)
                : Base64.decode(v, Base64.DEFAULT);
        } catch (Exception e) {
            return null;
        }
    }

    // Each entry is "Kind: value".
    public static List<String> decode(String token) {
        final List<String> result = new ArrayList<>();
        final String v = token.trim();
        if (v.isEmpty()) {
            return result;
        }
        final String hash = hashKind(v);
        if (hash != null) {
            result.add("Тип хеша: " + hash);
            return result;
        }
        final String[] parts = v.split("\\.");
        if (parts.length == 3 && v.startsWith("eyJ")) {
            final byte[] header = base64(parts[0]);
            final byte[] payload = base64(parts[1]);
            if (header != null) {
                result.add("JWT заголовок: " + new String(header, StandardCharsets.UTF_8));
            }
            if (payload != null) {
                result.add("JWT данные: " + new String(payload, StandardCharsets.UTF_8));
            }
            result.add("JWT подпись: " + (parts[2].isEmpty() ? "ОТСУТСТВУЕТ (alg none?)" : "есть, не проверялась"));
            return result;
        }
        if (BASE64.matcher(v).matches() && v.length() % 4 != 1) {
            final byte[] bytes = base64(v);
            if (bytes != null && bytes.length > 0) {
                final String text = new String(bytes, StandardCharsets.UTF_8);
                if (printable(text)) {
                    result.add("Base64: " + text);
                } else if (bytes.length > 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
                    result.add("Base64: исполняемый файл Windows (PE) — ИСПОЛНЯЕМЫЙ КОД!");
                } else if (bytes.length > 4 && bytes[0] == 'P' && bytes[1] == 'K') {
                    result.add("Base64: ZIP / APK / Office архив");
                }
            }
        }
        if (HEX.matcher(v).matches()) {
            final String clean = v.replace("0x", "").replaceAll("[\\s:]", "");
            if (clean.length() % 2 == 0) {
                final byte[] bytes = new byte[clean.length() / 2];
                for (int i = 0; i < bytes.length; ++i) {
                    bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
                }
                final String text = new String(bytes, StandardCharsets.UTF_8);
                if (printable(text)) {
                    result.add("Hex: " + text);
                }
            }
        }
        if (v.contains("%")) {
            try {
                final String decoded = URLDecoder.decode(v, "UTF-8");
                if (!decoded.equals(v)) {
                    result.add("URL-кодирование: " + decoded);
                }
            } catch (Exception ignore) {
            }
        }
        return result;
    }
}
