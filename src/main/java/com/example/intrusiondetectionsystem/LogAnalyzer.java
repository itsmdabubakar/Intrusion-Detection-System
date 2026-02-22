package com.example.intrusiondetectionsystem;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogAnalyzer {

    // 1. DEFINE THREAT PATTERNS (Signatures)
    // SQL Injection (e.g., ' OR 1=1, UNION SELECT)
    private static final Pattern SQL_INJECTION = Pattern.compile("(?i)(.*)(\\bUNION\\b|\\bSELECT\\b|\\bOR\\s+1=1\\b|--|\\bINSERT\\b|\\bDROP\\b)(.*)");

    // Cross-Site Scripting (XSS) (e.g., <script>, alert())
    private static final Pattern XSS = Pattern.compile("(?i)(.*)(<script>|javascript:|alert\\()(.*)");

    // Path Traversal (e.g., ../../etc/passwd)
    private static final Pattern PATH_TRAVERSAL = Pattern.compile("(?i)(.*)(\\.\\./|\\.\\.\\\\)(.*)");

    public static List<String> analyzeLog(File logFile) {
        List<String> threats = new ArrayList<>();
        int lineNumber = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;

                // Check the line against our signatures
                if (checkLine(line, SQL_INJECTION)) {
                    threats.add("🚨 Line " + lineNumber + " [SQL Injection]: " + line);
                }
                else if (checkLine(line, XSS)) {
                    threats.add("☣️ Line " + lineNumber + " [XSS Attack]: " + line);
                }
                else if (checkLine(line, PATH_TRAVERSAL)) {
                    threats.add("📂 Line " + lineNumber + " [Path Traversal]: " + line);
                }
            }
        } catch (Exception e) {
            threats.add("Error reading file: " + e.getMessage());
        }

        if (threats.isEmpty()) {
            threats.add("✅ No threats found. System appears clean.");
        }

        return threats;
    }

    // Helper method to check if a line matches a pattern
    private static boolean checkLine(String line, Pattern pattern) {
        Matcher matcher = pattern.matcher(line);
        return matcher.find();
    }
}