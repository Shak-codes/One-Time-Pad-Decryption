#ifndef WORDTRIE_H
#define WORDTRIE_H

#include <string>
#include <unordered_map>
#include <vector>

struct Node {
  std::unordered_map<char, Node*> children;  // Map of child nodes
  std::vector<int>
      word_indices;  // List of indices of words containing this prefix/suffix
  int words_count = 0;  // Number of words containing this prefix/suffix

  Node() = default;
  ~Node();
};

class WordTrie {
 private:
  Node* prefix_root;
  Node* suffix_root;
  std::vector<std::string> str_arr;  // Global array of words

 public:
  WordTrie(const std::string& file_path);
  ~WordTrie();

  void insert(int word_index);

  int countPrefix(const std::string& prefix) const;
  int countSuffix(const std::string& suffix) const;

  std::vector<std::string> findByPrefix(const std::string& prefix) const;
  std::vector<std::string> findBySuffix(const std::string& suffix) const;

  const std::vector<std::string>& getStrArr() const;
};

#endif
