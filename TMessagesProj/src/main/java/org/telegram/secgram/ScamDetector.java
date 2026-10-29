/*
 * This file is part of SecGram for Android.
 * It is licensed under GNU GPL v. 2 or later.
 */
package org.telegram.secgram;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Port of AnalyzeMessageText from the desktop version.
public final class ScamDetector {

    private static final String[][] GROUPS = {
        { "обещание приза", "вы выиграли", "поздравляем", "розыгрыш", "ваш приз", "победител", "yutdingiz", "yutib oldingiz", "g'olib", "sovrin", "you won", "you have won", "giveaway", "winner", "ютдингиз", "совға", "ғолиб" },
        { "бесплатный Premium / подарок", "premium бесплатно", "бесплатный premium", "telegram premium", "tekin premium", "bepul premium", "free premium", "подарок от telegram", "sovg'a", "stars бесплатно", "бесплатные звёзды", "free stars", "nft подарок" },
        { "данные карты / банка", "карта заблокирована", "номер карты", "данные карты", "cvv", "срок действия карты", "karta bloklandi", "karta raqam", "kartangiz", "card number", "card details", "код из смс", "sms kod", "sms-kod", "смс код", "plastik karta" },
        { "лёгкий заработок / инвестиции", "пассивный доход", "доход от", "гарантированн", "инвестиц", "арбитраж", "заработок без", "daromad", "investitsiya", "pul ishlash", "kuniga", "trading", "usdt", "x2 ", "x10", "guaranteed profit", "passive income", "kunlik foyda" },
        { "срочность / угроза", "срочно", "немедленно", "в течение 24", "последний шанс", "будет заблокирован", "заблокирован", "будет удал", "tezda", "shoshiling", "bloklandi", "zudlik bilan", "o'chiriladi", "bloklanadi", "urgent", "immediately", "will be suspended", "will be deleted" },
        { "просьба подтвердить данные", "подтвердите", "верификац", "пройдите проверку", "tasdiqlang", "tasdiqlash", "verify your", "confirm your", "введите код", "kodni yuboring", "send the code", "отправьте код", "скажите код" },
        { "фейковая работа", "удалённая работа", "удаленная работа", "работа на дому", "оплата за отзывы", "ставить лайки", "uyda ishlash", "masofaviy ish", "onlayn ish", "work from home", "оплата каждый день" },
        { "голосование / помощь", "проголосуйте", "проголосуй", "ovoz bering", "ovoz berib", "vote for", "помогите проголосовать" },
        { "криптовалютная афера", "airdrop", "connect wallet", "подключите кошелёк", "подключите кошелек", "seed", "мнемоническ", "seed-фраз", "claim your", "claim now", "drainer" },
    };

    private static final Pattern URL = Pattern.compile(
        "(?i)\\b(?:https?://|www\\.)[^\\s<>\"']+");

    private ScamDetector() {
    }

    public static Finding.Report analyze(String text, boolean fromStranger) {
        final Finding.Report result = new Finding.Report();
        if (text == null || text.isEmpty()) {
            return result;
        }
        final String lowered = text.toLowerCase(Locale.ROOT);
        final List<String> reasons = new ArrayList<>();
        for (String[] group : GROUPS) {
            for (int i = 1; i < group.length; ++i) {
                if (lowered.contains(group[i])) {
                    reasons.add(group[0]);
                    break;
                }
            }
        }
        boolean hasLink = false;
        boolean riskyLink = false;
        final Matcher matcher = URL.matcher(text);
        while (matcher.find()) {
            hasLink = true;
            if (UrlAnalyzer.analyze(matcher.group()).atLeast(Finding.Severity.HIGH)) {
                riskyLink = true;
            }
        }
        if (reasons.isEmpty() && !riskyLink) {
            return result;
        }
        final int score = reasons.size() + (hasLink ? 1 : 0) + (riskyLink ? 2 : 0) + (fromStranger ? 1 : 0);
        if (riskyLink) {
            reasons.add("опасная ссылка");
        } else if (hasLink) {
            reasons.add("ссылка");
        }
        if (fromStranger) {
            reasons.add("от незнакомца");
        }
        final Finding.Severity severity = score >= 5 ? Finding.Severity.CRITICAL
            : score >= 4 ? Finding.Severity.HIGH
            : score >= 3 ? Finding.Severity.WARNING
            : Finding.Severity.NOTICE;
        result.add(severity, "Признаки мошенничества: " + Finding.join(", ", reasons) + ".");
        return result;
    }
}
