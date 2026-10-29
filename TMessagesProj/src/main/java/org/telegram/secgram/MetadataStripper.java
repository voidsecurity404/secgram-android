/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

// Removes EXIF (GPS, camera, serial numbers), XMP, IPTC and comments from
// JPEG, text chunks from PNG and udta/meta boxes from MP4 / MOV.
// Port of StripImageMetadata / StripVideoMetadata from the desktop version.
public final class MetadataStripper {

    private static final long MAX_IMAGE = 64L * 1024 * 1024;
    private static final long MAX_VIDEO = 400L * 1024 * 1024;

    private MetadataStripper() {
    }

    // Returns the path of a cleaned copy, or the original path.
    public static String stripIfNeeded(String path, File cacheDir) {
        if (path == null || !SecGramConfig.get(SecGramConfig.STRIP_METADATA)) {
            return path;
        }
        final File file = new File(path);
        final long size = file.length();
        if (size <= 12 || size > MAX_VIDEO) {
            return path;
        }
        try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
            final byte[] head = new byte[12];
            in.readFully(head);
            final boolean jpeg = (head[0] & 0xFF) == 0xFF && (head[1] & 0xFF) == 0xD8;
            final boolean png = (head[0] & 0xFF) == 0x89 && head[1] == 'P' && head[2] == 'N' && head[3] == 'G';
            final boolean mp4 = head[4] == 'f' && head[5] == 't' && head[6] == 'y' && head[7] == 'p';
            if ((!jpeg && !png && !mp4) || ((jpeg || png) && size > MAX_IMAGE)) {
                return path;
            }
            final byte[] bytes = new byte[(int) size];
            in.seek(0);
            in.readFully(bytes);
            final byte[] cleaned = jpeg ? stripJpeg(bytes) : png ? stripPng(bytes) : stripMp4(bytes);
            if (cleaned == null) {
                return path;
            }
            final File folder = new File(cacheDir, "secgram_clean/" + System.nanoTime());
            if (!folder.mkdirs()) {
                return path;
            }
            final File out = new File(folder, file.getName());
            try (FileOutputStream stream = new FileOutputStream(out)) {
                stream.write(cleaned);
            }
            return out.getAbsolutePath();
        } catch (Throwable e) {
            return path;
        }
    }

    private static int u16be(byte[] b, int at) {
        return ((b[at] & 0xFF) << 8) | (b[at + 1] & 0xFF);
    }

    private static int exifOrientation(byte[] b, int start, int length) {
        // start points at "Exif\0\0".
        final int tiff = start + 6;
        if (length < 14) {
            return 0;
        }
        final boolean big = b[tiff] == 'M';
        final int end = start + length;
        final java.util.function.IntUnaryOperator u16 = at -> at + 2 > end ? -1
            : big ? (((b[at] & 0xFF) << 8) | (b[at + 1] & 0xFF))
            : (((b[at + 1] & 0xFF) << 8) | (b[at] & 0xFF));
        final int ifd = (u16.applyAsInt(tiff + (big ? 4 : 6)) << 16) | u16.applyAsInt(tiff + (big ? 6 : 4));
        if (ifd < 8 || tiff + ifd + 2 > end) {
            return 0;
        }
        final int count = u16.applyAsInt(tiff + ifd);
        for (int i = 0; i < count; ++i) {
            final int entry = tiff + ifd + 2 + i * 12;
            if (u16.applyAsInt(entry) == 0x0112) {
                final int value = u16.applyAsInt(entry + 8);
                return value >= 1 && value <= 8 ? value : 0;
            }
        }
        return 0;
    }

    static byte[] stripJpeg(byte[] b) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(b.length);
        out.write(0xFF);
        out.write(0xD8);
        int at = 2;
        int orientation = 0;
        boolean removed = false;
        while (at + 4 <= b.length) {
            if ((b[at] & 0xFF) != 0xFF) {
                return null;
            }
            final int marker = b[at + 1] & 0xFF;
            if (marker == 0xFF) {
                ++at;
                continue;
            }
            if (marker == 0xDA || marker == 0xD9) {
                if (!removed) {
                    return null;
                }
                final byte[] body = Arrays.copyOfRange(b, at, b.length);
                final byte[] start = out.toByteArray();
                final ByteArrayOutputStream result = new ByteArrayOutputStream(b.length);
                result.write(start, 0, 2);
                if (orientation > 1) {
                    final byte[] exif = {
                        'E', 'x', 'i', 'f', 0, 0, 'M', 'M', 0, 0x2A, 0, 0, 0, 8,
                        0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, (byte) orientation, 0, 0,
                        0, 0, 0, 0,
                    };
                    final int length = exif.length + 2;
                    result.write(0xFF);
                    result.write(0xE1);
                    result.write(length >> 8);
                    result.write(length & 0xFF);
                    result.write(exif, 0, exif.length);
                }
                result.write(start, 2, start.length - 2);
                result.write(body, 0, body.length);
                return result.toByteArray();
            }
            final int length = u16be(b, at + 2);
            if (length < 2 || at + 2 + length > b.length) {
                return null;
            }
            final boolean exif = marker == 0xE1
                && length >= 8
                && b[at + 4] == 'E' && b[at + 5] == 'x' && b[at + 6] == 'i' && b[at + 7] == 'f';
            if (exif) {
                orientation = exifOrientation(b, at + 4, length - 2);
            }
            if (marker == 0xE1 || marker == 0xED || marker == 0xFE) {
                removed = true;
            } else {
                out.write(b, at, 2 + length);
            }
            at += 2 + length;
        }
        return null;
    }

    static byte[] stripPng(byte[] b) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(b.length);
        out.write(b, 0, 8);
        int at = 8;
        boolean removed = false;
        while (at + 12 <= b.length) {
            final long length = ((long) (b[at] & 0xFF) << 24) | ((b[at + 1] & 0xFF) << 16) | ((b[at + 2] & 0xFF) << 8) | (b[at + 3] & 0xFF);
            if (at + 12 + length > b.length) {
                return null;
            }
            final String type = new String(b, at + 4, 4, java.nio.charset.StandardCharsets.US_ASCII);
            if (type.equals("eXIf") || type.equals("tEXt") || type.equals("zTXt") || type.equals("iTXt") || type.equals("tIME")) {
                removed = true;
            } else {
                out.write(b, at, (int) (12 + length));
            }
            at += 12 + (int) length;
            if (type.equals("IEND")) {
                break;
            }
        }
        return removed ? out.toByteArray() : null;
    }

    private static final Set<String> CONTAINERS = new HashSet<>(Arrays.asList(
        "moov", "trak", "mdia", "minf", "stbl", "edts", "dinf"));

    private static boolean freeBoxes(byte[] b, long from, long till, int depth) {
        boolean changed = false;
        long at = from;
        while (at + 8 <= till && depth < 8) {
            long size = ((long) (b[(int) at] & 0xFF) << 24) | ((b[(int) at + 1] & 0xFF) << 16) | ((b[(int) at + 2] & 0xFF) << 8) | (b[(int) at + 3] & 0xFF);
            int header = 8;
            if (size == 1 && at + 16 <= till) {
                size = 0;
                for (int i = 0; i < 8; ++i) {
                    size = (size << 8) | (b[(int) at + 8 + i] & 0xFF);
                }
                header = 16;
            } else if (size == 0) {
                size = till - at;
            }
            if (size < header || at + size > till) {
                break;
            }
            final String type = new String(b, (int) at + 4, 4, java.nio.charset.StandardCharsets.US_ASCII);
            if (type.equals("udta") || type.equals("meta") || type.equals("uuid")) {
                b[(int) at + 4] = 'f';
                b[(int) at + 5] = 'r';
                b[(int) at + 6] = 'e';
                b[(int) at + 7] = 'e';
                Arrays.fill(b, (int) at + header, (int) (at + size), (byte) 0);
                changed = true;
            } else if (CONTAINERS.contains(type)) {
                changed |= freeBoxes(b, at + header, at + size, depth + 1);
            }
            at += size;
        }
        return changed;
    }

    static byte[] stripMp4(byte[] b) {
        return freeBoxes(b, 0, b.length, 0) ? b : null;
    }
}
