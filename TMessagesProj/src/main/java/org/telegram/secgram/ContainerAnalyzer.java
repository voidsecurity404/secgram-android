/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;

// Port of secgram_files.cpp: ZIP (and OOXML), PDF, PE and VBA macros.
// Pure Java, testable with plain javac.
public final class ContainerAnalyzer {

    public static final class Result extends Finding.Report {
        public String summary = "";
    }

    static final class ZipEntry {
        String name;
        long size;
        long compressedSize;
        long offset;
        int method;
        boolean encrypted;
    }

    private ContainerAnalyzer() {
    }

    private static int u16(byte[] b, long at) {
        if (at < 0 || at + 2 > b.length) {
            return 0;
        }
        return (b[(int) at] & 0xFF) | ((b[(int) at + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] b, long at) {
        if (at < 0 || at + 4 > b.length) {
            return 0;
        }
        return (u16(b, at) & 0xFFFFL) | ((long) u16(b, at + 2) << 16);
    }

    private static String latin1(byte[] b) {
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    static List<ZipEntry> listZip(byte[] b) {
        final List<ZipEntry> result = new ArrayList<>();
        long eocd = -1;
        for (long i = b.length - 22; i >= Math.max(0, b.length - 65557); --i) {
            if (u32(b, i) == 0x06054b50L) {
                eocd = i;
                break;
            }
        }
        if (eocd < 0) {
            return null;
        }
        final int count = u16(b, eocd + 10);
        long at = u32(b, eocd + 16);
        for (int i = 0; i < count; ++i) {
            if (u32(b, at) != 0x02014b50L) {
                break;
            }
            final int nameLength = u16(b, at + 28);
            final int extra = u16(b, at + 30);
            final int comment = u16(b, at + 32);
            final ZipEntry entry = new ZipEntry();
            final int nameStart = (int) Math.min(b.length, at + 46);
            entry.name = new String(b, nameStart, Math.min(nameLength, b.length - nameStart), StandardCharsets.UTF_8);
            entry.encrypted = (u16(b, at + 8) & 1) != 0;
            entry.method = u16(b, at + 10);
            entry.compressedSize = u32(b, at + 20);
            entry.size = u32(b, at + 24);
            entry.offset = u32(b, at + 42);
            result.add(entry);
            at += 46 + nameLength + extra + comment;
        }
        return result;
    }

    static byte[] readZipEntry(byte[] b, ZipEntry entry) {
        if (entry.encrypted || entry.size > 64L * 1024 * 1024 || u32(b, entry.offset) != 0x04034b50L) {
            return null;
        }
        final long start = entry.offset + 30 + u16(b, entry.offset + 26) + u16(b, entry.offset + 28);
        if (start + entry.compressedSize > b.length) {
            return null;
        }
        if (entry.method == 0) {
            final byte[] out = new byte[(int) entry.compressedSize];
            System.arraycopy(b, (int) start, out, 0, out.length);
            return out;
        } else if (entry.method != 8) {
            return null;
        }
        final Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(b, (int) start, (int) entry.compressedSize);
            final ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.max(16, entry.size));
            final byte[] buffer = new byte[65536];
            while (!inflater.finished()) {
                final int n = inflater.inflate(buffer);
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    break;
                }
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        } finally {
            inflater.end();
        }
    }

    private static boolean officeInternal(String name) {
        return name.endsWith(".bin") && (name.startsWith("word/") || name.startsWith("xl/") || name.startsWith("ppt/"));
    }

    public static Result analyzeZip(byte[] b) {
        final Result result = new Result();
        final List<ZipEntry> entries = listZip(b);
        if (entries == null) {
            result.add(Finding.Severity.NOTICE, "Не удалось прочитать оглавление архива.");
            return result;
        }
        final List<String> executables = new ArrayList<>();
        final List<String> disguised = new ArrayList<>();
        final List<String> traversal = new ArrayList<>();
        final StringBuilder lines = new StringBuilder();
        int encrypted = 0;
        long total = 0;
        int shown = 0;
        for (ZipEntry entry : entries) {
            total += entry.size;
            if (entry.encrypted) {
                ++encrypted;
            }
            if (entry.name.startsWith("/") || entry.name.contains("../") || entry.name.contains("..\\")) {
                traversal.add(entry.name);
            }
            if (entry.name.endsWith("/")) {
                continue;
            }
            final Finding.Report name = FileGuard.analyzeName(entry.name);
            if (name.atLeast(Finding.Severity.CRITICAL)) {
                disguised.add(entry.name);
            } else if (name.atLeast(Finding.Severity.HIGH) && !officeInternal(entry.name)) {
                executables.add(entry.name);
            }
            if (entry.name.endsWith("vbaProject.bin")) {
                final Result macros = analyzeMacros(readZipEntry(b, entry));
                result.findings.addAll(macros.findings);
                if (!macros.summary.isEmpty()) {
                    lines.insert(0, macros.summary + "\n\n");
                }
            }
            if (shown++ < 30) {
                lines.append(entry.name).append(entry.encrypted ? " 🔒" : "").append('\n');
            }
        }
        if (!disguised.isEmpty()) {
            result.add(Finding.Severity.CRITICAL, "Замаскированные файлы внутри: " + Finding.join(", ", disguised));
        }
        if (!executables.isEmpty()) {
            result.add(Finding.Severity.HIGH, "Исполняемые файлы внутри: " + Finding.join(", ", executables.subList(0, Math.min(10, executables.size()))));
        }
        if (encrypted > 0) {
            result.add(Finding.Severity.WARNING, "Файлов под паролем: " + encrypted + ". Антивирус не может проверить зашифрованное содержимое.");
        }
        if (!traversal.isEmpty()) {
            result.add(Finding.Severity.HIGH, "Пути с выходом из папки (Zip Slip): " + Finding.join(", ", traversal));
        }
        if (total > 512L * 1024 * 1024 && total / Math.max(1, b.length) > 100) {
            result.add(Finding.Severity.WARNING, "Возможная ZIP-бомба: распакованный размер в сотни раз больше архива.");
        }
        result.summary = "Файлов: " + entries.size() + "\n" + lines;
        return result;
    }

    public static Result analyzePdf(byte[] b) {
        final Result result = new Result();
        final String s = latin1(b);
        final int js = count(s, "/JavaScript") + count(s, "/JS");
        final int launch = count(s, "/Launch");
        final int embedded = count(s, "/EmbeddedFile");
        final int open = count(s, "/OpenAction") + count(s, "/AA");
        if (js > 0) {
            result.add(Finding.Severity.HIGH, "Содержит JavaScript (" + js + ") — может выполнять код при открытии.");
        }
        if (launch > 0) {
            result.add(Finding.Severity.CRITICAL, "Действие /Launch — попытка запустить программу.");
        }
        if (embedded > 0) {
            result.add(Finding.Severity.HIGH, "Вложенные файлы (" + embedded + ").");
        }
        if (open > 0) {
            result.add(js > 0 || launch > 0 ? Finding.Severity.HIGH : Finding.Severity.NOTICE, "Автоматические действия при открытии (" + open + ").");
        }
        if (count(s, "/XFA") + count(s, "/RichMedia") > 0) {
            result.add(Finding.Severity.WARNING, "XFA-формы / RichMedia — частый вектор эксплойтов.");
        }
        if (count(s, "/SubmitForm") > 0) {
            result.add(Finding.Severity.WARNING, "Форма отправляет данные на сервер (/SubmitForm).");
        }
        if (Pattern.compile("/[A-Za-z]*#[0-9A-Fa-f]{2}").matcher(s).find()) {
            result.add(Finding.Severity.HIGH, "Имена объектов закодированы (#xx) — обфускация.");
        }
        final Matcher uri = Pattern.compile("/URI\\s*\\(([^)]{4,500})\\)").matcher(s);
        final List<String> links = new ArrayList<>();
        int risky = 0;
        while (uri.find() && links.size() < 30) {
            final String link = uri.group(1);
            if (!links.contains(link)) {
                links.add(link);
                if (UrlAnalyzer.analyze(link).atLeast(Finding.Severity.HIGH)) {
                    ++risky;
                }
            }
        }
        if (risky > 0) {
            result.add(Finding.Severity.HIGH, "Опасных ссылок в документе: " + risky + ".");
        }
        result.summary = links.isEmpty() ? "" : "Ссылки:\n" + Finding.join("\n", links);
        return result;
    }

    private static int count(String s, String key) {
        int result = 0;
        for (int i = s.indexOf(key); i >= 0; i = s.indexOf(key, i + key.length())) {
            ++result;
        }
        return result;
    }

    private static double entropy(byte[] b, long offset, long size) {
        if (size <= 0 || offset < 0 || offset + size > b.length) {
            return 0;
        }
        final long[] counts = new long[256];
        for (long i = offset; i < offset + size; ++i) {
            ++counts[b[(int) i] & 0xFF];
        }
        double result = 0;
        for (long c : counts) {
            if (c > 0) {
                final double p = (double) c / size;
                result -= p * Math.log(p) / Math.log(2);
            }
        }
        return result;
    }

    public static Result analyzePe(byte[] b) {
        final Result result = new Result();
        final long pe = u32(b, 0x3C);
        if (u32(b, pe) != 0x00004550L) {
            result.add(Finding.Severity.NOTICE, "Повреждённый PE.");
            return result;
        }
        final int machine = u16(b, pe + 4);
        final int sections = u16(b, pe + 6);
        final long timestamp = u32(b, pe + 8);
        final int optionalSize = u16(b, pe + 20);
        final int characteristics = u16(b, pe + 22);
        final long optional = pe + 24;
        final boolean plus = u16(b, optional) == 0x20b;
        final long directories = optional + (plus ? 112 : 96);
        final long signature = u32(b, directories + 4 * 8 + 4);
        final long clr = u32(b, directories + 14 * 8 + 4);
        final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        final StringBuilder details = new StringBuilder();
        details.append("Тип: ").append((characteristics & 0x2000) != 0 ? "DLL" : "EXE").append(", ")
            .append(machine == 0x8664 ? "x64" : machine == 0x14c ? "x86" : machine == 0xaa64 ? "ARM64" : "?")
            .append(clr != 0 ? ", .NET" : "").append('\n');
        details.append("Дата компиляции: ").append(format.format(new Date(timestamp * 1000))).append(" UTC");
        if (timestamp * 1000 > System.currentTimeMillis() + 86400000L) {
            result.add(Finding.Severity.WARNING, "Дата компиляции в будущем — подделана.");
        }
        if (signature == 0) {
            result.add(Finding.Severity.WARNING, "Нет цифровой подписи (Authenticode).");
        }
        final String[] packers = { "UPX", ".aspack", ".adata", "Themida", ".vmp", "MPRESS", ".petite", ".nsp", "PEC2", ".enigma" };
        long table = optional + optionalSize;
        final List<String> packed = new ArrayList<>();
        final List<String> high = new ArrayList<>();
        for (int i = 0; i < sections && i < 96; ++i, table += 40) {
            if (table + 40 > b.length) {
                break;
            }
            final String name = new String(b, (int) table, 8, StandardCharsets.ISO_8859_1).replace("\0", "");
            final long rawSize = u32(b, table + 16);
            final long rawOffset = u32(b, table + 20);
            final double e = entropy(b, rawOffset, rawSize);
            if (e > 7.2 && rawSize > 1024) {
                high.add(name + String.format(Locale.US, " (%.2f)", e));
            }
            for (String packer : packers) {
                if (name.toLowerCase(Locale.ROOT).contains(packer.toLowerCase(Locale.ROOT))) {
                    packed.add(name);
                }
            }
        }
        if (!packed.isEmpty()) {
            result.add(Finding.Severity.HIGH, "Упакован/защищён: " + Finding.join(", ", packed) + " — код скрыт.");
        }
        if (!high.isEmpty()) {
            result.add(Finding.Severity.WARNING, "Секции с высокой энтропией: " + Finding.join(", ", high));
        }
        final String[][] apis = {
            { "CreateRemoteThread", "внедрение в процессы" }, { "WriteProcessMemory", "внедрение в процессы" },
            { "VirtualAllocEx", "внедрение в процессы" }, { "NtUnmapViewOfSection", "process hollowing" },
            { "SetWindowsHookEx", "перехват клавиатуры" }, { "GetAsyncKeyState", "кейлоггер" },
            { "URLDownloadToFile", "скачивание файлов" }, { "CryptEncrypt", "шифрование" },
            { "IsDebuggerPresent", "антиотладка" }, { "RegSetValueEx", "автозапуск в реестре" },
            { "CryptUnprotectData", "кража паролей браузеров" }, { "vssadmin", "удаление теневых копий" },
        };
        final String text = latin1(b);
        final List<String> found = new ArrayList<>();
        for (String[] api : apis) {
            if (text.contains(api[0])) {
                found.add(api[0] + " (" + api[1] + ")");
            }
        }
        if (found.size() >= 3) {
            result.add(Finding.Severity.HIGH, "Подозрительные функции: " + Finding.join(", ", found));
        } else if (!found.isEmpty()) {
            result.add(Finding.Severity.NOTICE, "Функции: " + Finding.join(", ", found));
        }
        result.summary = details.toString();
        return result;
    }

    // MS-OVBA decompression ([MS-OVBA] 2.4.1).
    static byte[] decompressOvba(byte[] data, int start, int limit) {
        byte[] out = new byte[4096];
        int size = 0;
        if (start >= data.length || data[start] != 0x01) {
            return new byte[0];
        }
        int pos = start + 1;
        while (pos + 2 <= data.length && size < limit) {
            final int header = u16(data, pos);
            if (((header >> 12) & 7) != 3) {
                break;
            }
            final int chunkEnd = Math.min(data.length, pos + (header & 0x0FFF) + 3);
            pos += 2;
            final int chunkStart = size;
            if ((header & 0x8000) == 0) {
                final int n = Math.min(4096, data.length - pos);
                if (size + n > out.length) {
                    out = java.util.Arrays.copyOf(out, Math.max(out.length * 2, size + n));
                }
                System.arraycopy(data, pos, out, size, n);
                size += n;
                pos += 4096;
                continue;
            }
            while (pos < chunkEnd) {
                final int flags = data[pos++] & 0xFF;
                for (int bit = 0; bit < 8 && pos < chunkEnd; ++bit) {
                    if (((flags >> bit) & 1) == 0) {
                        if (size + 1 > out.length) {
                            out = java.util.Arrays.copyOf(out, out.length * 2);
                        }
                        out[size++] = data[pos++];
                        continue;
                    }
                    if (pos + 2 > chunkEnd) {
                        return java.util.Arrays.copyOf(out, size);
                    }
                    final int token = u16(data, pos);
                    pos += 2;
                    final int difference = size - chunkStart;
                    int bitCount = 4;
                    while ((1 << bitCount) < difference && bitCount < 12) {
                        ++bitCount;
                    }
                    final int lengthMask = 0xFFFF >> bitCount;
                    final int length = (token & lengthMask) + 3;
                    final int offset = ((token & ~lengthMask & 0xFFFF) >> (16 - bitCount)) + 1;
                    final int source = size - offset;
                    if (source < 0) {
                        return java.util.Arrays.copyOf(out, size);
                    }
                    if (size + length > out.length) {
                        out = java.util.Arrays.copyOf(out, Math.max(out.length * 2, size + length));
                    }
                    for (int i = 0; i < length; ++i) {
                        out[size] = out[source + i];
                        ++size;
                    }
                }
            }
        }
        return java.util.Arrays.copyOf(out, size);
    }

    public static Result analyzeMacros(byte[] data) {
        final Result result = new Result();
        if (data == null) {
            return result;
        }
        final List<String> sources = new ArrayList<>();
        int attempts = 0;
        for (int i = 0; i + 3 < data.length; ++i) {
            if (data[i] != 0x01 || ((u16(data, i + 1) >> 12) & 7) != 3) {
                continue;
            } else if (++attempts > 5000) {
                break;
            }
            final String code = latin1(decompressOvba(data, i, 1024 * 1024));
            if (code.contains("Attribute VB_")) {
                sources.add(code);
                i += 16;
            }
        }
        if (sources.isEmpty()) {
            if (latin1(data).contains("VBA")) {
                result.add(Finding.Severity.HIGH, "Есть проект VBA (макросы), код извлечь не удалось.");
            }
            return result;
        }
        final String[][] keywords = {
            { "AutoOpen", "HIGH" }, { "Auto_Open", "HIGH" }, { "Document_Open", "HIGH" }, { "Workbook_Open", "HIGH" },
            { "Shell", "HIGH" }, { "WScript.Shell", "CRITICAL" }, { "powershell", "CRITICAL" }, { "cmd.exe", "CRITICAL" },
            { "URLDownloadToFile", "CRITICAL" }, { "XMLHTTP", "HIGH" }, { "ADODB.Stream", "HIGH" }, { "CreateObject", "WARNING" },
            { "VirtualAlloc", "CRITICAL" }, { "RtlMoveMemory", "CRITICAL" }, { "mshta", "CRITICAL" }, { "certutil", "CRITICAL" },
            { "regsvr32", "CRITICAL" }, { "StrReverse", "WARNING" }, { "Environ", "NOTICE" },
        };
        final String code = Finding.join("\n", sources);
        final String lower = code.toLowerCase(Locale.ROOT);
        final List<String> found = new ArrayList<>();
        Finding.Severity severity = Finding.Severity.HIGH;
        for (String[] k : keywords) {
            if (lower.contains(k[0].toLowerCase(Locale.ROOT))) {
                found.add(k[0]);
                final Finding.Severity s = Finding.Severity.valueOf(k[1]);
                if (s.ordinal() > severity.ordinal()) {
                    severity = s;
                }
            }
        }
        result.add(severity, "Макросы VBA: " + sources.size() + " модул(ей). Подозрительное: " + (found.isEmpty() ? "—" : Finding.join(", ", found)));
        final List<IocExtractor.Ioc> iocs = IocExtractor.extract(code);
        if (!iocs.isEmpty()) {
            result.add(Finding.Severity.HIGH, "Адреса в коде макроса: " + IocExtractor.defang(iocs.get(0)) + (iocs.size() > 1 ? " (+" + (iocs.size() - 1) + ")" : ""));
        }
        final StringBuilder lines = new StringBuilder("Начало кода макроса:\n");
        int shown = 0;
        for (String line : code.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("Attribute ")) {
                continue;
            }
            lines.append(line.length() > 120 ? line.substring(0, 120) : line).append('\n');
            if (++shown >= 20) {
                break;
            }
        }
        result.summary = lines.toString();
        return result;
    }

    public static Result analyze(byte[] b) {
        if (b == null || b.length < 4) {
            return new Result();
        }
        if (b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4) {
            return analyzeZip(b);
        } else if (b[0] == '%' && b[1] == 'P' && b[2] == 'D' && b[3] == 'F') {
            return analyzePdf(b);
        } else if (b[0] == 'M' && b[1] == 'Z') {
            return analyzePe(b);
        } else if ((b[0] & 0xFF) == 0xD0 && (b[1] & 0xFF) == 0xCF && b[2] == 0x11 && (b[3] & 0xFF) == 0xE0) {
            return analyzeMacros(b);
        }
        return new Result();
    }
}
