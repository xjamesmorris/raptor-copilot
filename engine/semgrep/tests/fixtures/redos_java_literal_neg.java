// Synthetic fixture — linear / defused regexes that superficially
// resemble catastrophic-backtracking shapes. All synthesized for this
// test. raptor.injection.regex-dos.literal.java must stay SILENT on
// every line in this file.
import java.util.regex.Pattern;

public class RedosLiteralNegatives {

    void commonIdioms(String userInput) {
        // Scary-looking but linear everyday patterns.
        boolean mail = userInput.matches("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$");
        boolean date = userInput.matches("^\\d{4}-\\d{2}-\\d{2}$");
        Pattern.compile("^\\w+(\\.\\w+)*$");            // dotted name: required "." delimiter
        Pattern.compile("^[+-]?(\\d+\\.?\\d*|\\.\\d+)$"); // number literal
        Pattern.compile("(19|20)\\d{2}");                // year
        boolean kv = userInput.matches("^(\\w+)=(\\S+)$");
        Pattern.compile("(?i)^(rc4.*|des.*|.*-ecb)$");   // anchored cipher matcher
        String[] rows = userInput.split("([^,]*,)+");    // class excludes the delimiter
        Pattern.compile("([A-Z][a-z]+ )+[A-Z][a-z]+");   // required space delimiter
        Pattern.compile("(0x[0-9a-f]+,)*0x[0-9a-f]+");   // delimited list
        Pattern.compile("(;[^;]+)*$");                   // required ";" delimiter
    }

    void defusedQuantifiers(String userInput) {
        // Possessive quantifiers and atomic groups do not backtrack.
        Pattern.compile("(a++)+");
        Pattern.compile("(a+)++");
        Pattern.compile("(a+)*+");
        Pattern.compile("(?>a+)+");
        // Bounded repetition caps the search space.
        Pattern.compile("(a+){1,4}");
        Pattern.compile("(a{1,5})+");
        boolean tag = userInput.matches("(foo|bar){1,3}");
    }

    void nonOverlapping(String userInput) {
        // Disjoint alternation branches — a unique parse per input.
        Pattern.compile("(a|b)+");
        boolean pet = userInput.matches("(cat|dog)*");
        Pattern.compile("(https?|ftp)://");
    }

    void groupSpellingsStillLinear(String userInput) {
        // The widened group-prefix admission must not turn benign
        // named/flag groups or delimiter shapes into findings.
        Pattern.compile("(a?b)+");                     // required "b" delimiter
        Pattern.compile("(\\d+,\\d+)+");               // required "," delimiter
        Pattern.compile("(https?://[a-z0-9.-]+/?)+");  // URL list, required prefix
        Pattern.compile("(foo|foobar)+");              // prefix overlap, not unit repetition
        Pattern.compile("(a+){2,4}");                  // bounded outer
        Pattern.compile("(?<name>\\d+)");              // named group, no nesting
        Pattern.compile("(?i:[a-z]+)");                // flag group, no outer quantifier
        Pattern.compile("((?m)^\\w+$)");               // inline flags, no nesting
        Pattern.compile("(?<g>\\.\\w+)*");             // named + required delimiter
        Pattern.compile("( a+ b )+", Pattern.COMMENTS); // == (a+b)+, "b" delimits
    }

    void notNested(String userInput) {
        Pattern.compile("(\\d+)");         // single quantifier, no outer
        boolean n = userInput.matches("^(\\d+)$");
        Pattern.compile("(a+b)+");         // required "b" delimiter
        Pattern.compile("(\\d+\\.\\d+)?"); // bounded outer
        Pattern.compile("\\(x+\\)+");      // escaped parens, no group
        Pattern.compile("[.*]+");          // "." and "*" inside a class are literals
    }
}
