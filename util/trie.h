#ifndef UTIL_TRIE_H
#define UTIL_TRIE_H

#include <stdint.h>
#include <new>

namespace util {
  template<typename Value>
  class trie {
    public:
      typedef Value value_type;

      // Constructor.
      trie() = default;

      // Destructor.
      ~trie();

      // Clear.
      void clear();

      // Insert.
      // 'keylen': key length in bits.
      bool insert(const void* key, size_t keylen, const value_type& val);

      // Find key.
      // 'keylen': key length in bits.
      const value_type* find(const void* key, size_t keylen) const;

    private:
      struct node {
        value_type val;

        node* children[2] = {nullptr};

        // Constructor.
        node() = default;
        node(const value_type& v);
      };

      node* _M_root = nullptr;

      // Delete node.
      static void erase(node* n);

      // Disable copy constructor and assignment operator.
      trie(const trie&) = delete;
      trie& operator=(const trie&) = delete;
  };

  template<typename Value>
  inline trie<Value>::~trie()
  {
    clear();
  }

  template<typename Value>
  inline void trie<Value>::clear()
  {
    if (_M_root) {
      erase(_M_root);
      _M_root = nullptr;
    }
  }

  template<typename Value>
  bool trie<Value>::insert(const void* key,
                           size_t keylen,
                           const value_type& val)
  {
    // If the key is not empty...
    if (keylen > 0) {
      const uint8_t* const k = static_cast<const uint8_t*>(key);

      node* cur = _M_root;
      node* prev = nullptr;

      uint8_t prevbit = 0;

      // For each bit...
      size_t i = 0;
      do {
        // If the current node doesn't exist...
        if (!cur) {
          // Create a new node.
          if ((cur = new (std::nothrow) node()) != nullptr) {
            // If this is not the first node...
            if (prev) {
              prev->children[prevbit] = cur;
            } else {
              // Save pointer to the root node.
              _M_root = cur;
            }
          } else {
            return false;
          }
        }

        // Save current node.
        prev = cur;

        // Get current bit.
        const uint8_t bit = (k[i >> 3] >> (7 - (i & 0x07))) & 0x01;

        // Make 'cur' point to the child node.
        cur = cur->children[bit];

        // Save previous bit.
        prevbit = bit;
      } while (++i < keylen);

      if (!cur) {
        // Create a new node.
        if ((cur = new (std::nothrow) node(val)) != nullptr) {
          prev->children[prevbit] = cur;
        } else {
          return false;
        }
      } else {
        if (cur->children[0]) {
          erase(cur->children[0]);
          cur->children[0] = nullptr;
        }

        if (cur->children[1]) {
          erase(cur->children[1]);
          cur->children[1] = nullptr;
        }

        cur->val = val;
      }

      return true;
    }

    return false;
  }

  template<typename Value>
  const typename trie<Value>::value_type*
  trie<Value>::find(const void* key, size_t keylen) const
  {
    // If the key is not empty...
    if (keylen > 0) {
      const uint8_t* const k = static_cast<const uint8_t*>(key);

      const node* cur = _M_root;

      // For each bit...
      size_t i = 0;
      do {
        // If the current node exists...
        if (cur) {
          // Get current bit.
          const uint8_t bit = (k[i >> 3] >> (7 - (i & 0x07))) & 0x01;

          if (cur->children[bit]) {
            // Make 'cur' point to the child node.
            cur = cur->children[bit];
          } else {
            break;
          }
        } else {
          return nullptr;
        }
      } while (++i < keylen);

      return ((!cur->children[0]) && (!cur->children[1])) ? &cur->val : nullptr;
    }

    return nullptr;
  }

  template<typename Value>
  inline trie<Value>::node::node(const value_type& v)
    : val(v)
  {
  }

  template<typename Value>
  inline void trie<Value>::erase(node* node)
  {
    if (node->children[0]) {
      erase(node->children[0]);
    }

    if (node->children[1]) {
      erase(node->children[1]);
    }

    delete node;
  }
}

#endif // UTIL_TRIE_H
