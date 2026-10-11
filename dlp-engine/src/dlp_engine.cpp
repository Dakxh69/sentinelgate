// Engine layer: built-in keyword -> category map and
// factory that initializes and finalizes the Aho-Corasick automaton.
#include "dlp_engine.hpp"

namespace dlp {

const std::unordered_map<std::string, std::string> &default_keywords() {
    static const std::unordered_map<std::string, std::string> keywords = {
        {"password", "PASSWORD"},
        {"api_key", "API_KEY"},
        {"apikey", "API_KEY"},
        {"secret", "SECRET"},
        {"aadhaar", "AADHAAR"},
        {"credit_card", "CREDIT_CARD"},
    };
    return keywords;
}

AhoCorasick AhoCorasick::with_default_keywords() {
    AhoCorasick engine;
    // Built-in labels use whole-word boundaries so context labels match correctly.
    for (const auto &[keyword, category] : default_keywords()) {
        engine.add_pattern(keyword, category, true);
    }
    engine.finalize();
    return engine;
}

}  // namespace dlp
