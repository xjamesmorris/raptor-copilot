// Synthetic fixture — the safe shapes around the taint rule: constant
// linear pattern applied TO request data (the normal case), and
// Pattern.quote() sanitisation. Synthesized for this test.
// raptor.injection.regex-dos.taint.java must stay SILENT here.
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

public class RedosTaintNegatives {

    private static final Pattern TOKEN = Pattern.compile("^[a-z0-9-]{1,64}$");

    void constantPatternTaintedSubject(HttpServletRequest request) {
        // Tainted data in the SUBJECT position is fine — the pattern
        // is a constant, linear regex.
        String name = request.getParameter("name");
        boolean ok = TOKEN.matcher(name).matches();
        boolean mail = name.matches("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$");
        String[] parts = name.split(",");
        String cleaned = name.replaceAll("^\\s+", "");
    }

    void quotedUserToken(HttpServletRequest request, String haystack) {
        // Pattern.quote() turns the value into a literal — no regex
        // metacharacters survive.
        String token = request.getParameter("token");
        Pattern.compile(Pattern.quote(token));
        boolean hit = haystack.matches(Pattern.quote(token));
    }

    void localConstantPattern(String haystack) {
        // No request data involved at all.
        String sep = ";";
        String[] parts = haystack.split(sep);
    }
}
