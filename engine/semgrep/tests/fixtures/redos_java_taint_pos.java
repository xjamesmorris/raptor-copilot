// Synthetic fixture — attacker-controlled data reaching the regex
// PATTERN position. Synthesized for this test; no real-world code.
// Each line tagged `redos-tp` must be flagged by
// raptor.injection.regex-dos.taint.java.
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

public class RedosTaintPositives {

    void compileFromParam(HttpServletRequest request, String haystack) {
        String userPattern = request.getParameter("q");
        Pattern.compile(userPattern); // redos-tp
    }

    void matchesFromHeader(HttpServletRequest request, String haystack) {
        String filter = request.getHeader("X-Filter");
        boolean hit = haystack.matches(filter); // redos-tp
    }

    void splitFromQueryString(HttpServletRequest request, String haystack) {
        String sep = request.getQueryString();
        String[] parts = haystack.split(sep); // redos-tp
    }

    void replaceAllFromParam(HttpServletRequest request, String haystack) {
        String needle = request.getParameter("strip");
        String out = haystack.replaceAll(needle, ""); // redos-tp
    }

    void staticMatchesFromParam(HttpServletRequest request, String haystack) {
        String p = request.getParameter("re");
        boolean ok = Pattern.matches(p, haystack); // redos-tp
    }
}
