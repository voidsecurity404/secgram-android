/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import android.app.Activity;

import org.telegram.ui.ActionBar.AlertDialog;

import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

// Checks a downloaded file before it is opened (port of the desktop
// AnalyzeFileName and AnalyzeApk).
public final class FileGuard {

    private static final Set<String> EXECUTABLE = new HashSet<>(Arrays.asList((
        "exe com scr pif bat cmd msi msp cpl dll hta js jse vbs vbe wsf wsh ps1 "
        + "reg lnk url scf inf chm jar jnlp appx msix app pkg dmg command sh run "
        + "bin deb rpm appimage apk apks xapk apkm aab ipa").split(" ")));
    private static final Set<String> MACRO = new HashSet<>(Arrays.asList(
        "docm dotm xlsm xltm xlam xlsb pptm potm ppam ppsm sldm".split(" ")));
    private static final Set<String> LURE = new HashSet<>(Arrays.asList((
        "pdf doc docx xls xlsx ppt pptx txt rtf jpg jpeg png gif bmp webp mp4 "
        + "mov avi mkv mp3 wav ogg csv").split(" ")));

    private static final String[][] PERMISSIONS = {
        { "RECEIVE_SMS", "HIGH", "получать SMS — перехват банковских кодов" },
        { "READ_SMS", "HIGH", "читать SMS — кража кодов подтверждения" },
        { "SEND_SMS", "HIGH", "отправлять SMS — платные подписки, распространение" },
        { "BIND_ACCESSIBILITY_SERVICE", "HIGH", "спец. возможности — полный контроль экрана" },
        { "BIND_DEVICE_ADMIN", "HIGH", "права администратора — защита от удаления" },
        { "SYSTEM_ALERT_WINDOW", "WARNING", "окна поверх других — поддельные формы банков" },
        { "BIND_NOTIFICATION_LISTENER_SERVICE", "WARNING", "читать все уведомления, включая коды" },
        { "REQUEST_INSTALL_PACKAGES", "WARNING", "устанавливать другие приложения — дроппер" },
        { "READ_CALL_LOG", "NOTICE", "журнал звонков" },
        { "READ_CONTACTS", "NOTICE", "контакты" },
        { "RECORD_AUDIO", "NOTICE", "запись звука" },
        { "CAMERA", "NOTICE", "камера" },
        { "ACCESS_FINE_LOCATION", "NOTICE", "точное местоположение" },
        { "QUERY_ALL_PACKAGES", "NOTICE", "видеть все приложения (поиск банков)" },
    };

    private static boolean bypass;

    private FileGuard() {
    }

    private static boolean isBidi(int c) {
        return (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F || c == 0x061C;
    }

    public static Finding.Report analyzeName(String name) {
        final Finding.Report result = new Finding.Report();
        if (name == null) {
            return result;
        }
        final StringBuilder clean = new StringBuilder();
        boolean bidi = false;
        for (int i = 0; i < name.length(); ++i) {
            final char c = name.charAt(i);
            if (isBidi(c)) {
                bidi = true;
            } else if (c != 0x200B && c != 0x200C && c != 0x200D && c != 0xFEFF) {
                clean.append(c);
            }
        }
        final String file = clean.toString();
        final int dot = file.lastIndexOf('.');
        final String ext = dot < 0 ? "" : file.substring(dot + 1).trim().toLowerCase(Locale.ROOT);
        if (bidi) {
            result.add(Finding.Severity.CRITICAL, "Имя содержит символы смены направления текста (RTLO), маскирующие расширение. Настоящее расширение — «." + ext + "».");
        }
        if (EXECUTABLE.contains(ext)) {
            result.add(Finding.Severity.HIGH, "«." + ext + "» — программа или скрипт. Она может получить полный контроль над телефоном или компьютером.");
        } else if (MACRO.contains(ext)) {
            result.add(Finding.Severity.HIGH, "«." + ext + "» — документ Office с макросами. Никогда не включайте макросы.");
        }
        final String[] parts = file.split("\\.");
        if (parts.length >= 3 && LURE.contains(parts[parts.length - 2].trim().toLowerCase(Locale.ROOT))
            && (EXECUTABLE.contains(ext) || MACRO.contains(ext))) {
            result.add(Finding.Severity.CRITICAL, "Двойное расширение «." + parts[parts.length - 2] + "." + ext + "»: файл притворяется документом.");
        }
        if (file.matches("(?s).*(\\s{4,}|_{6,})\\.?[A-Za-z0-9]{1,8}$")) {
            result.add(Finding.Severity.CRITICAL, "Длинный отступ перед расширением скрывает «." + ext + "».");
        }
        return result;
    }

    // String pool of Android binary XML, enough to read permissions.
    static List<String> axmlStrings(byte[] xml) {
        final List<String> result = new ArrayList<>();
        if (xml == null || xml.length < 36) {
            return result;
        }
        final ByteBuffer b = ByteBuffer.wrap(xml).order(ByteOrder.LITTLE_ENDIAN);
        if ((b.getShort(0) & 0xFFFF) != 0x0003) {
            return result;
        }
        final int pool = b.getShort(2) & 0xFFFF;
        if ((b.getShort(pool) & 0xFFFF) != 0x0001) {
            return result;
        }
        final int count = b.getInt(pool + 8);
        final int flags = b.getInt(pool + 16);
        final int stringsStart = pool + b.getInt(pool + 20);
        final boolean utf8 = (flags & 0x100) != 0;
        final int offsets = pool + (b.getShort(pool + 2) & 0xFFFF);
        for (int i = 0; i < count && i < 100000; ++i) {
            if (offsets + i * 4 + 4 > xml.length) {
                break;
            }
            int at = stringsStart + b.getInt(offsets + i * 4);
            if (at < 0 || at >= xml.length) {
                break;
            }
            try {
                if (utf8) {
                    at += ((xml[at] & 0x80) != 0) ? 2 : 1;
                    int length = xml[at] & 0xFF;
                    if ((length & 0x80) != 0) {
                        length = ((length & 0x7F) << 8) | (xml[at + 1] & 0xFF);
                        at += 2;
                    } else {
                        at += 1;
                    }
                    result.add(new String(xml, at, Math.min(length, xml.length - at), "UTF-8"));
                } else {
                    int length = b.getShort(at) & 0xFFFF;
                    if ((length & 0x8000) != 0) {
                        length = ((length & 0x7FFF) << 16) | (b.getShort(at + 2) & 0xFFFF);
                        at += 4;
                    } else {
                        at += 2;
                    }
                    if (at + length * 2 > xml.length) {
                        break;
                    }
                    result.add(new String(xml, at, length * 2, "UTF-16LE"));
                }
            } catch (Exception e) {
                break;
            }
        }
        return result;
    }

    public static Finding.Report analyzeApk(File file, StringBuilder summary) {
        final Finding.Report result = new Finding.Report();
        try (ZipFile zip = new ZipFile(file)) {
            final ZipEntry manifest = zip.getEntry("AndroidManifest.xml");
            if (manifest == null) {
                return result;
            }
            final byte[] xml;
            try (InputStream in = zip.getInputStream(manifest)) {
                final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                final byte[] buffer = new byte[16384];
                int read;
                while ((read = in.read(buffer)) > 0 && out.size() < 8 * 1024 * 1024) {
                    out.write(buffer, 0, read);
                }
                xml = out.toByteArray();
            }
            final List<String> strings = axmlStrings(xml);
            final Set<String> found = new LinkedHashSet<>();
            for (String s : strings) {
                if (s.startsWith("android.permission.")) {
                    found.add(s.substring(19));
                }
            }
            for (String[] permission : PERMISSIONS) {
                if (found.contains(permission[0])) {
                    result.add(Finding.Severity.valueOf(permission[1]), permission[0] + ": " + permission[2]);
                }
            }
            final boolean sms = found.contains("RECEIVE_SMS") || found.contains("READ_SMS");
            final boolean control = found.contains("BIND_ACCESSIBILITY_SERVICE") || found.contains("SYSTEM_ALERT_WINDOW") || found.contains("BIND_NOTIFICATION_LISTENER_SERVICE");
            if (sms && control) {
                result.add(Finding.Severity.CRITICAL, "Сочетание доступа к SMS и управления экраном / уведомлениями — типичный банковский троян. НЕ устанавливайте.");
            }
            final java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            final List<String> hidden = new ArrayList<>();
            while (entries.hasMoreElements()) {
                final String name = entries.nextElement().getName().toLowerCase(Locale.ROOT);
                if ((name.startsWith("assets/") || name.startsWith("res/raw/"))
                    && (name.endsWith(".dex") || name.endsWith(".jar") || name.endsWith(".apk"))) {
                    hidden.add(name);
                } else if (name.startsWith("lib/") && (name.contains("libjiagu") || name.contains("libsecexe") || name.contains("libdexhelper") || name.contains("libprotectclass"))) {
                    result.add(Finding.Severity.WARNING, "Упакован протектором (" + name.substring(name.lastIndexOf('/') + 1) + ") — код скрыт от анализа.");
                }
            }
            if (!hidden.isEmpty()) {
                result.add(Finding.Severity.HIGH, "Скрытый код в ресурсах: " + Finding.join(", ", hidden.subList(0, Math.min(5, hidden.size()))));
            }
            summary.append("Разрешения (").append(found.size()).append("): ").append(Finding.join(", ", found));
        } catch (Exception e) {
            result.add(Finding.Severity.NOTICE, "Не удалось прочитать APK.");
        }
        return result;
    }

    // Returns true if the opening was taken over by a warning.
    public static boolean intercept(Activity activity, File file, String fileName, Runnable open) {
        if (bypass || activity == null || file == null || !SecGramConfig.get(SecGramConfig.FILE_GUARD)) {
            return false;
        }
        final String name = fileName != null ? fileName : file.getName();
        final Finding.Report report = analyzeName(name);
        final StringBuilder summary = new StringBuilder();
        boolean isApk = name.toLowerCase(Locale.ROOT).endsWith(".apk");
        try (InputStream in = new java.io.FileInputStream(file)) {
            final byte[] head = new byte[4];
            if (in.read(head) == 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4) {
                try (ZipFile zip = new ZipFile(file)) {
                    if (zip.getEntry("AndroidManifest.xml") != null) {
                        if (!isApk) {
                            report.add(Finding.Severity.CRITICAL, "Это на самом деле приложение Android (APK), хотя имя «" + name + "».");
                        }
                        isApk = true;
                    }
                }
            } else if (head[0] == 'M' && head[1] == 'Z' && !name.toLowerCase(Locale.ROOT).matches(".*\\.(exe|dll|scr|com|sys)$")) {
                report.add(Finding.Severity.CRITICAL, "Содержимое — программа Windows (PE), а имя «" + name + "». Файл замаскирован.");
            }
        } catch (Exception ignore) {
        }
        if (isApk) {
            final Finding.Report apk = analyzeApk(file, summary);
            report.findings.addAll(apk.findings);
        }
        if (!report.atLeast(Finding.Severity.HIGH)) {
            return false;
        }
        final StringBuilder text = new StringBuilder();
        text.append(report.verdict()).append("\n\nФайл: ").append(name).append("\n");
        for (Finding finding : report.findings) {
            text.append("\n").append(finding.severity.mark).append(" ").append(finding.text);
        }
        if (summary.length() > 0) {
            text.append("\n\n").append(summary);
        }
        text.append("\n\nОткрывайте, только если доверяете отправителю и ждали именно этот файл.");
        final AlertDialog dialog = new AlertDialog.Builder(activity)
            .setTitle("Опасный файл")
            .setMessage(text)
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Всё равно открыть", (d, w) -> {
                bypass = true;
                try {
                    open.run();
                } finally {
                    bypass = false;
                }
            })
            .show();
        dialog.redPositive();
        return true;
    }
}
