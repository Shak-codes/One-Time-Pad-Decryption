#include <iostream>
#include <string>
#include <vector>

#include "../lib/json.hpp"
#include "WordTrie.h"

using json = nlohmann::json;

int main() {
  // Load the suffix trie once
  WordTrie trie("dictionary/english-words.all");
  std::cerr << "Trie loaded. Waiting for commands...\n";

  std::string line;
  while (std::getline(std::cin, line)) {
    try {
      // Parse input JSON
      json input = json::parse(line);
      std::string command = input["command"];
      std::string type = input["type"];
      std::string string = input["string"];
      json output;

      if (command == "count" && type == "prefix") {
        int count = trie.countPrefix(string);
        output = {{"count", count}};
      } else if (command == "count" && type == "suffix") {
        int count = trie.countSuffix(string);
        output = {{"count", count}};
      } else if (command == "count" && type == "reverse") {
        int count = trie.countReverse(string);
        output = {{"count", count}};
      } else if (command == "find" && type == "prefix") {
        std::vector<std::string> result = trie.findByPrefix(string);
        if (result.size() > 50) {
          result.resize(50);
        }
        output = result;
      } else if (command == "find" && type == "suffix") {
        std::vector<std::string> result = trie.findBySuffix(string);
        if (result.size() > 50) {
          result.resize(50);
        }
        output = result;
      } else {
        output = {{"error", "Invalid command"}};
      }

      // Output JSON response
      std::cout << output.dump() << std::endl;
    } catch (const std::exception& e) {
      // Handle errors gracefully
      std::cerr << "Error: " << e.what() << std::endl;
      std::cout << json({{"error", "Invalid input"}}).dump() << std::endl;
    }
  }

  std::cerr << "Shutting down...\n";
  return 0;
}
