// SentinelGate C++ DLP engine — Aho-Corasick keyword scanner.
//
// scan(text) -> DetectionResult performs a single-pass multi-pattern search
// using a trie with BFS failure and output links. Matching is case-insensitive.
#ifndef DLP_ENGINE_HPP
#define DLP_ENGINE_HPP

#include <string>
#include <unordered_map>
#include <vector>

namespace dlp {

// One pattern ending at a trie node.
struct AcOutput {
    std::string category;
    std::size_t length = 0;  // pattern length (for whole-word boundary check)
    bool whole_word = false; // require non-alphanumeric delimiters
};

// A node in the Aho-Corasick trie (goto/fail/output).
struct AcNode {
    std::unordered_map<char, int> next;
    int failure = 0;   // BFS failure link (node index; root = 0)
    bool is_word = false;
    std::vector<AcOutput> outputs;  // patterns ending here (lowercase)
};

// Result of one scan: detected flag + alphabetically sorted unique category names.
// Raw matched text is never stored or emitted.
struct DetectionResult {
    bool detected = false;
    std::vector<std::string> matches;  // sorted, unique categories
};

class AhoCorasick {
  public:
    AhoCorasick();

    // Build with default keyword pattern map.
    static AhoCorasick with_default_keywords();

    // Add a pattern (lowercased internally) tagged with a category.
    void add_pattern(const std::string &pattern, const std::string &category,
                     bool whole_word = false);

    // Finalize: build failure + output links via BFS. Must be called after
    // all add_pattern calls and before scan.
    void finalize();

    // Single-pass scan. Throws std::logic_error when the automaton was not finalized.
    DetectionResult scan(const std::string &text) const;

  private:
    std::vector<AcNode> nodes_;
    bool finalized_ = false;
};

// Built-in keyword -> category map.
const std::unordered_map<std::string, std::string> &default_keywords();

}  // namespace dlp

#endif  // DLP_ENGINE_HPP
