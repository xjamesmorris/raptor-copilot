// Synthetic fixture — every regex below is a textbook catastrophic-
// backtracking shape synthesized for this test; none is taken from a
// real-world codebase or undisclosed finding.
// Each line tagged `redos-tp` must be flagged by
// raptor.injection.regex-dos.literal.java (and nothing else in the file).
import java.util.regex.Pattern;

public class RedosLiteralPositives {

    void nestedQuantifiers(String userInput) {
        Pattern.compile("(a+)+").matcher(userInput).matches(); // redos-tp
        boolean ok = userInput.matches("^(a+)+$"); // redos-tp
        Pattern.compile("(\\d+)*"); // redos-tp
        boolean id = userInput.matches("([a-z]+)*$"); // redos-tp
        Pattern.compile("(\\w+\\s?)*"); // redos-tp
        String[] parts = userInput.split("(a{2,})+"); // redos-tp
        String out = userInput.replaceAll("(x+){3,}", ""); // redos-tp
        Pattern.compile("(?:\\d+)+", Pattern.CASE_INSENSITIVE); // redos-tp
        boolean lazy = userInput.matches("(a+?)+"); // redos-tp
        Pattern.compile("(\\s*\\w+)*$"); // redos-tp
        Pattern.compile("(a+b?)+"); // redos-tp
    }

    void overlappingAlternation(String userInput) {
        Pattern.compile("(a|aa)+"); // redos-tp
        boolean hit = Pattern.matches("(ab|abab)*", userInput); // redos-tp
        String first = userInput.replaceFirst("(a|a)*", ""); // redos-tp
    }

    void wildcardRuns(String userInput) {
        String[] cells = userInput.split("(.*,)+"); // redos-tp
        Pattern.compile("(a.+b)*"); // redos-tp
    }

    void groupSpellings(String userInput) {
        // Same blowup shapes behind other group spellings — named,
        // flag-carrying, inline-flag, COMMENTS-mode (whitespace
        // insignificant), and backslash-prefixed forms.
        Pattern.compile("(?<g>a+)+"); // redos-tp
        Pattern.compile("(?i:a+)+"); // redos-tp
        Pattern.compile("((?i)a+)+"); // redos-tp
        Pattern.compile("(?x)( a+ )+"); // redos-tp
        Pattern.compile("( a+ )+", Pattern.COMMENTS); // redos-tp
        Pattern.compile("( a+ )+", Pattern.COMMENTS | Pattern.CASE_INSENSITIVE); // redos-tp
        Pattern.compile("\\\\(a+)+"); // redos-tp
        Pattern.compile("(\\.+)+"); // redos-tp
    }
}
