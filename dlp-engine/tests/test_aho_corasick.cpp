// Dependency-free assert-based unit tests (Day 5 R3; runs via CTest).
// Covers: the classic AC set (he/she/his/hers), overlapping matches,
// case-insensitivity, no-match, empty input.
#include "dlp_engine.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool contains(const std::vector<std::string> &values, const std::string &value) {
    for (const std::string &candidate : values) {
        if (candidate == value) {
            return true;
        }
    }
    return false;
}

void test_classic_set() {
    // The textbook Aho-Corasick set (he/she/his/hers).
    dlp::AhoCorasick engine;
    engine.add_pattern("he", "HE");
    engine.add_pattern("she", "SHE");
    engine.add_pattern("his", "HIS");
    engine.add_pattern("hers", "HERS");
    engine.finalize();

    const dlp::DetectionResult result = engine.scan("ushers");
    assert(result.detected);
    // "ushers": he (1), she (0-2), hers (1-4) — his does NOT match.
    assert(!contains(result.matches, "HIS"));
    assert(contains(result.matches, "HE"));
    assert(contains(result.matches, "SHE"));
    assert(contains(result.matches, "HERS"));
    assert(result.matches.size() == 3);
}

void test_overlapping_matches() {
    // Overlapping occurrences at distinct offsets must all be reported
    // (dictionary suffix chains via output links).
    dlp::AhoCorasick engine;
    engine.add_pattern("aaa", "A3");
    engine.add_pattern("aa", "A2");
    engine.finalize();

    const dlp::DetectionResult result = engine.scan("aaaa");
    assert(result.detected);
    assert(contains(result.matches, "A2"));
    assert(contains(result.matches, "A3"));
}

void test_case_insensitive() {
    const dlp::AhoCorasick engine = dlp::AhoCorasick::with_default_keywords();
    const dlp::DetectionResult result = engine.scan("API_KEY=... and PaSsWoRd=...");
    assert(result.detected);
    assert(contains(result.matches, "API_KEY"));
    assert(contains(result.matches, "PASSWORD"));
    // mixed-case keyword with the underscore form
    const dlp::DetectionResult result2 = engine.scan("My Api_Key leaked");
    assert(contains(result2.matches, "API_KEY"));
}

void test_no_match() {
    const dlp::AhoCorasick engine = dlp::AhoCorasick::with_default_keywords();
    const dlp::DetectionResult result = engine.scan("nothing sensitive in here");
    assert(!result.detected);
    assert(result.matches.empty());
}

void test_empty_input() {
    const dlp::AhoCorasick engine = dlp::AhoCorasick::with_default_keywords();
    const dlp::DetectionResult result = engine.scan("");
    assert(!result.detected);
    assert(result.matches.empty());
}

void test_default_categories() {
    const dlp::AhoCorasick engine = dlp::AhoCorasick::with_default_keywords();
    const dlp::DetectionResult result = engine.scan(
        "password=x apikey=y secret=z aadhaar=1 credit_card=q");
    assert(result.detected);
    // All five sensitive categories present, sorted alphabetically.
    assert(result.matches ==
           std::vector<std::string>({"AADHAAR", "API_KEY", "CREDIT_CARD",
                                     "PASSWORD", "SECRET"}));
}

void test_keyword_substring_context() {
    // Keywords count as context signals when they stand alone or form part
    // of a labeled field (client_secret=, aadhaar_number) — underscore and
    // hyphen are delimiters.
    const dlp::AhoCorasick engine = dlp::AhoCorasick::with_default_keywords();
    assert(engine.scan("my secret value").detected);
    assert(engine.scan("client_secret=abc").detected);
    assert(contains(engine.scan("client_secret=abc").matches, "SECRET"));
    assert(contains(engine.scan("aadhaar_number").matches, "AADHAAR"));
}

void test_whole_word_filter() {
    // Delimited keyword boundary: `api_key=secret123` must yield ["API_KEY"] only
    // because "secret123" is part of an alphanumeric token, not a standalone keyword.
    const dlp::AhoCorasick engine = dlp::AhoCorasick::with_default_keywords();
    const dlp::DetectionResult result = engine.scan("api_key=secret123");
    assert(result.detected);
    assert(result.matches == std::vector<std::string>({"API_KEY"}));

    // Same category: a genuine standalone hit elsewhere in the text still
    // confirms the category despite a boundary-blocked candidate.
    const dlp::DetectionResult mixed = engine.scan("secret123 and secret value");
    assert(contains(mixed.matches, "SECRET"));

    // Classic substring semantics remain for custom (non-whole-word) patterns.
    dlp::AhoCorasick custom;
    custom.add_pattern("secret", "SECRET");
    custom.finalize();
    assert(custom.scan("secret123").detected);
}

}  // namespace

int main() {
    test_classic_set();
    test_overlapping_matches();
    test_case_insensitive();
    test_no_match();
    test_empty_input();
    test_default_categories();
    test_keyword_substring_context();
    test_whole_word_filter();
    std::cout << "all aho-corasick tests passed" << std::endl;
    return 0;
}
