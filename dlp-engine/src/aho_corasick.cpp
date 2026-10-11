// Aho-Corasick implementation: trie + BFS failure links + output links;
// single pass over input text. Matching is case-insensitive.
//
// Whole-word boundary mode ensures non-alphanumeric delimiters surround matches
// so that keywords like `api_key` match without falsely triggering on arbitrary substrings.
#include "dlp_engine.hpp"

#include <cctype>
#include <queue>
#include <set>
#include <stdexcept>

namespace dlp {

namespace {

std::string to_lower(const std::string &text) {
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

inline bool is_alnum(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0;
}

// Whole-word boundary check for a match of `length` ending at `end`
// (exclusive). Both edges must be non-alphanumeric (or the text edge).
bool word_delimited(const std::string &text, std::size_t start,
                    std::size_t end) {
    const bool left_ok = start == 0 || !is_alnum(text[start - 1]);
    const bool right_ok = end == text.size() || !is_alnum(text[end]);
    return left_ok && right_ok;
}

}  // namespace

AhoCorasick::AhoCorasick() { nodes_.emplace_back(); }  // root at index 0

void AhoCorasick::add_pattern(const std::string &pattern,
                              const std::string &category, bool whole_word) {
    if (finalized_) {
        throw std::logic_error("add_pattern called after finalize()");
    }
    if (pattern.empty()) {
        return;  // empty patterns never match anything useful
    }
    const std::string lowered = to_lower(pattern);
    int current = 0;
    for (char c : lowered) {
        auto it = nodes_[current].next.find(c);
        if (it == nodes_[current].next.end()) {
            nodes_.emplace_back();
            const int created = static_cast<int>(nodes_.size()) - 1;
            nodes_[current].next.emplace(c, created);
            current = created;
        } else {
            current = it->second;
        }
    }
    nodes_[current].is_word = true;
    nodes_[current].outputs.push_back(
        AcOutput{category, lowered.size(), whole_word});
}

void AhoCorasick::finalize() {
    if (finalized_) {
        return;
    }
    // BFS: root's failure link is itself (represented as 0); depth-1 nodes
    // fail to the root.
    std::queue<int> queue;
    for (const auto &[symbol, child] : nodes_[0].next) {
        (void)symbol;
        nodes_[child].failure = 0;
        queue.push(child);
    }
    while (!queue.empty()) {
        const int node = queue.front();
        queue.pop();
        for (const auto &[symbol, child] : nodes_[node].next) {
            int failure = nodes_[node].failure;
            while (failure != 0 &&
                   nodes_[failure].next.find(symbol) ==
                       nodes_[failure].next.end()) {
                failure = nodes_[failure].failure;
            }
            const auto it = nodes_[failure].next.find(symbol);
            const int fallback =
                (it != nodes_[failure].next.end() && it->second != child)
                    ? it->second
                    : 0;
            nodes_[child].failure = fallback;
            // Output links: inherit the suffix-node outputs (dictionary
            // suffix chains), so overlapping patterns ending here are all
            // candidates.
            for (const AcOutput &out : nodes_[fallback].outputs) {
                nodes_[child].outputs.push_back(out);
            }
            queue.push(child);
        }
    }
    finalized_ = true;
}

DetectionResult AhoCorasick::scan(const std::string &text) const {
    if (!finalized_) {
        throw std::logic_error("scan called before finalize()");
    }
    const std::string haystack = to_lower(text);

    // Report the highest-priority outcome per category in a single pass:
    // a plain hit outranks a word-boundary-blocked candidate, so a category
    // with a genuine standalone hit is never suppressed by a same-category
    // candidate that failed the boundary check elsewhere in the text.
    std::set<std::string> confirmed;
    std::set<std::string> boundary_blocked;

    int current = 0;
    for (std::size_t position = 0; position < haystack.size(); ++position) {
        const char raw = haystack[position];
        // Follow failure links until a transition exists (or we sit at root).
        while (current != 0 &&
               nodes_[current].next.find(raw) == nodes_[current].next.end()) {
            current = nodes_[current].failure;
        }
        const auto it = nodes_[current].next.find(raw);
        if (it != nodes_[current].next.end()) {
            current = it->second;
        } else {
            current = 0;
        }
        for (const AcOutput &out : nodes_[current].outputs) {
            const std::size_t start = position + 1 - out.length;
            const bool ok =
                !out.whole_word || word_delimited(haystack, start, position + 1);
            if (ok) {
                confirmed.insert(out.category);
            } else {
                boundary_blocked.insert(out.category);
            }
        }
    }

    DetectionResult result;
    for (const std::string &category : confirmed) {
        result.matches.push_back(category);
    }
    result.detected = !result.matches.empty();
    return result;
}

}  // namespace dlp
