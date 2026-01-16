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
public class SQLiTests {

    private final String testName;
    private final String input;
    private final String expected;

    public SQLiTests(String testName, String input, String expected) {
        this.testName = testName;
        this.input = input;
        this.expected = expected;
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws IOException {
        List<Object[]> testCases = new ArrayList<>();

        Path testsDir = findTestsDir();
        if (testsDir == null) {
            System.err.println("Warning: test-data directory not found, skipping SQLi tests");
            return testCases;
        }

        List<Path> sqliFiles = Files.list(testsDir)
            .filter(p -> p.getFileName().toString().contains("-sqli-"))
            .sorted()
            .collect(Collectors.toList());

        for (Path file : sqliFiles) {
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
    public void testSQLiFingerprint() {
        String inputValue = input != null ? input : "";
        String expectedValue = expected != null ? expected.trim() : "";

        LibInjectionSQLi.SqliResult result = LibInjectionSQLi.libinjection_sqli(inputValue);

        String actual = result.isSqli ? result.fingerprint : "";
        assertEquals("File: " + testName + "\nInput: " + inputValue, expectedValue, actual.trim());
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
