#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>
#include <shared_mutex>
#include <stack>

using namespace std;

/// ConcurrentHashTable is a concurrent hash table (a Key/Value store).  It is
/// not resizable, which means that the O(1) guarantees of a hash table are lost
/// if the number of elements in the table gets too big.
///
/// The ConcurrentHashTable is templated on the Key and Value types
///
/// The general structure of the ConcurrentHashTable is that we have an array of
/// buckets.  Each bucket has a mutex and a vector of entries.  Each entry is a
/// pair, consisting of a key and a value.  We can use std::hash() to choose a
/// bucket from a key.
template <typename K, typename V> class ConcurrentHashTable {
  struct bucket {
    mutable shared_mutex mtx;
    vector<pair<K, V>> elements;
  };
  vector<bucket*> hashTable;

public:
  /// Construct a concurrent hash table by specifying the number of buckets it
  /// should have
  ///
  /// @param _buckets The number of buckets in the concurrent hash table
  ConcurrentHashTable(size_t _buckets) {
    //std::cout << "ConcurrentHashTable: entered.\n";
    for(size_t i = 0; i < _buckets; i++) {
      hashTable.push_back(new bucket);
    }
  }

  /// Clear the Concurrent Hash Table.  This operation needs to use 2pl
  void clear() {
    //std::cout << "clear: entered.\n";
    int size = hashTable.size();
    //aquire all locks uniquely
    for(int i = 0; i < size; i++) {
      hashTable[i]->mtx.lock();
    }
    for(int i = 0; i < size; i++) {
      if(hashTable[i]->elements.size()) {
        hashTable[i]->elements.clear();
      }
      hashTable[i]->mtx.unlock();
    }
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key The key to insert
  /// @param val The value to insert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  /// existed in the table
  bool insert(K key, V val, std::function<void()> on_success) {
    //printf("inserting!!!!");
    hash<K> key_hash;
    size_t rv = key_hash(key);
    size_t index = rv % hashTable.size();
    hashTable[index]->mtx.lock();
    for(size_t i = 0; i < hashTable[index]->elements.size(); i++) {
      if(hashTable[index]->elements[i].first == key) {
        //printf("nah bitch");
        hashTable[index]->mtx.unlock();
        return false;
      }
    }
    /*hashTable[index]->mtx.unlock();
    printf("yeet");
    hashTable[index]->mtx.lock();*/
    hashTable[index]->elements.push_back(make_pair(key, val));
    on_success();
    hashTable[index]->mtx.unlock();
    //printf("yote");
    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key The key to upsert
  /// @param val The value to upsert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table and was thus updated instead
  bool upsert(K key, V val, std::function<void()> on_ins, std::function<void()> on_upt) { 
    hash<K> key_hash;
    size_t index = key_hash(key) % hashTable.size();
    hashTable[index]->mtx.lock_shared();
    bool exists = false;
    size_t i;
    for(i = 0; i < hashTable[index]->elements.size(); i++) {
      if(hashTable[index]->elements[i].first == key) {
        exists = true;
        break;
      }
    }
    hashTable[index]->mtx.unlock();
    hashTable[index]->mtx.lock();
    if(exists) {
       hashTable[index]->elements[i].second = val;
       on_upt();
       hashTable[index]->mtx.unlock();
       return false;
    }
    hashTable[index]->elements.push_back(make_pair(key, val));
    on_ins();
    hashTable[index]->mtx.unlock();
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with(K key, std::function<void(V &)> f) {
    //std::cout << "do_with: entered.\n";

    hash<K> key_hash;
    size_t index = key_hash(key) % hashTable.size();
    hashTable[index]->mtx.lock_shared();
    bool exists = false;
    size_t i;
    for(i = 0; i < hashTable[index]->elements.size(); i++) {
      if(hashTable[index]->elements[i].first == key) {
        exists = true;
        break;
      }
    }
    hashTable[index]->mtx.unlock();
    if(!exists) return false;
    hashTable[index]->mtx.lock();
    f(hashTable[index]->elements[i].second);
    hashTable[index]->mtx.unlock();
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with_readonly(K key, std::function<void(const V &)> f) {
    //std::cout << "do_with_readonly: entered.\n";

    hash<K> key_hash;
    size_t index = key_hash(key) % hashTable.size();
    hashTable[index]->mtx.lock_shared();
    size_t i;
    for(i = 0; i < hashTable[index]->elements.size(); i++) {
      if(hashTable[index]->elements[i].first == key) {
        f(hashTable[index]->elements[i].second);
        hashTable[index]->mtx.unlock();
        return true;
      }
    }
    hashTable[index]->mtx.unlock();
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key The key whose mapping should be removed
  ///
  /// @returns true if the key was found and the value unmapped, false otherwise
  bool remove(K key, std::function<void()> on_success) { 
    //std::cout << "remove: entered.\n";

    hash<K> key_hash;
    size_t index = key_hash(key) % hashTable.size();
    hashTable[index]->mtx.lock_shared();
    size_t i;
    for(i = 0; i < hashTable[index]->elements.size(); i++) {
      if(hashTable[index]->elements[i].first == key) {
        hashTable[index]->mtx.unlock();
        hashTable[index]->mtx.lock();
        hashTable[index]->elements.erase(hashTable[index]->elements.begin() + i);
        on_success();
        hashTable[index]->mtx.unlock();
        return true;
      }
    }
    return false;
  }

  /// Apply a function to every key/value pair in the ConcurrentHashTable.  Note
  /// that the function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  void do_all_readonly(std::function<void(const K, const V &)> f, std::function<void()> then) {
    //std::cout << "do_all_readonly: entered.\n";
    size_t size = hashTable.size();
    //aquire all locks
    for(size_t i = 0; i < size; i++) {
      hashTable[i]->mtx.lock_shared();
    }
    then();
    for(size_t i = 0; i < size; i++) {
        for(size_t j = 0; j < hashTable[i]->elements.size(); j++) {
          f(hashTable[i]->elements[j].first, hashTable[i]->elements[j].second);
        }
        hashTable[i]->mtx.unlock();
    }
  }
};