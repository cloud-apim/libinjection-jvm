package com.cloud.apim.libinjection.test;

import com.cloud.apim.libinjection.impl.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class SQLiFoldingTests {

    private final String testName;
    private final String input;
    private final String expected;

    public SQLiFoldingTests(String testName, String input, String expected) {
        this.testName = testName;
        this.input = input;
        this.expected = expected;
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws IOException {
        List<Object[]> testCases = new ArrayList<>();

        Path testsDir = findTestsDir();
        if (testsDir == null) {
            System.err.println("Warning: test-data directory not found, skipping SQLi folding tests");
            return testCases;
        }

        List<Path> foldingFiles = Files.list(testsDir)
            .filter(p -> p.getFileName().toString().contains("-folding-"))
            .sorted()
            .collect(Collectors.toList());

        for (Path file : foldingFiles) {
            Map<String, String> data = readTestData(file);
            testCases.add(new Object[]{
                file.getFileName().toString(),
                data.get("--INPUT--"),
                data.get("--EXPECTED--")
            });
        }

        return testCases;
    }

    @Test
    public void testSQLiFolding() {
        String inputValue = input != null ? input : "";
        String expectedValue = expected != null ? expected.trim() : "";

        SqliState state = new SqliState();
        LibInjectionSQLi.sqli_init(state, inputValue,
            LibInjectionSQLi.FLAG_QUOTE_NONE | LibInjectionSQLi.FLAG_SQL_ANSI);

        int numTokens = LibInjectionSQLi.sqli_fold(state);

        StringBuilder actual = new StringBuilder();
        for (int i = 0; i < numTokens; i++) {
            if (actual.length() > 0) {
                actual.append("\n");
            }
            actual.append(printToken(state.tokenvec[i]));
        }

        assertEquals("File: " + testName + "\nInput: " + inputValue,
            expectedValue, actual.toString().trim());
    }

    private String printToken(SqliToken t) {
        StringBuilder out = new StringBuilder();
        out.append(t.type);
        out.append(" ");

        switch (t.type) {
            case 's':
                out.append(printTokenString(t));
                break;
            case 'v':
                int vc = t.count;
                if (vc == 1) {
                    out.append("@");
                } else if (vc == 2) {
                    out.append("@@");
                }
                out.append(printTokenString(t));
                break;
            default:
                out.append(new String(t.val, 0, t.len));
        }

        return out.toString().trim();
    }

    private String printTokenString(SqliToken t) {
        StringBuilder out = new StringBuilder();
        if (t.str_open != '\0') {
            out.append(t.str_open);
        }
        out.append(new String(t.val, 0, t.len));
        if (t.str_close != '\0') {
            out.append(t.str_close);
        }
        return out.toString();
    }

    private static Path findTestsDir() {
        String[] possiblePaths = {
            "test-data/libinjection-go/tests",
            "../test-data/libinjection-go/tests",
            "libinjection-jvm/test-data/libinjection-go/tests"
        };

        for (String path : possiblePaths) {
            Path p = Paths.get(path);
            if (Files.exists(p)) {
                return p;
            }
        }
        return null;
    }

    private static Map<String, String> readTestData(Path file) throws IOException {
        Map<String, String> data = new HashMap<>();
        String state = "";

        try (BufferedReader reader = Files.newBufferedReader(file)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.equals("--TEST--") || trimmed.equals("--INPUT--") || trimmed.equals("--EXPECTED--")) {
                    state = trimmed;
                } else {
                    String current = data.getOrDefault(state, "");
                    if (!current.isEmpty()) {
                        current += "\n";
                    }
                    data.put(state, current + trimmed);
                }
            }
        }

        data.replaceAll((k, v) -> v != null ? v.trim() : "");
        return data;
    }
}
