// CLI entrypoint: `dlp-engine --scan` reads text on stdin,
// and outputs a JSON object to stdout:
//   {"detected": true, "matches": ["API_KEY", "PASSWORD"]}
// Exit 0 on success, non-zero on any error.
#include "dlp_engine.hpp"

#include <exception>
#include <iostream>
#include <sstream>
#include <string>

namespace {

int run_scan() {
    std::ostringstream buffer;
    buffer << std::cin.rdbuf();
    if (std::cin.bad()) {
        std::cerr << "dlp-engine: stdin read failure" << std::endl;
        return 2;
    }

    const dlp::AhoCorasick engine = dlp::AhoCorasick::with_default_keywords();
    const dlp::DetectionResult result = engine.scan(buffer.str());

    // One JSON line; matches are already alphabetically sorted and unique.
    std::cout << "{\"detected\": "
              << (result.detected ? "true" : "false") << ", \"matches\": [";
    for (std::size_t i = 0; i < result.matches.size(); ++i) {
        if (i > 0) {
            std::cout << ", ";
        }
        std::cout << '"' << result.matches[i] << '"';
    }
    std::cout << "]}\n";
    std::cout.flush();
    return std::cout.good() ? 0 : 2;
}

}  // namespace

int main(int argc, char **argv) {
    try {
        // Only `dlp-engine --scan` is a valid invocation (spec section 26).
        if (argc != 2 || std::string(argv[1]) != "--scan") {
            std::cerr << "usage: dlp-engine --scan   (text on stdin, one JSON"
                         " line on stdout)" << std::endl;
            return 1;
        }
        return run_scan();
    } catch (const std::exception &exc) {
        std::cerr << "dlp-engine: error: " << exc.what() << std::endl;
        return 3;
    }
}
