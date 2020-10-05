#include <deque>
#include <shared_mutex>
#include <mutex>
#include <thread>
#include <atomic>
#include <utility>
#include "mru.h"

using namespace std;

/// mru_manager::Internal is the class that stores all the members of a
/// mru_manager object. To avoid pulling too much into the .h file, we are using
/// the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct mru_manager::Internal {
  /// Construct the Internal object by setting the fields that are
  /// user-specified
  ///
  deque<string> mru;
  size_t max;
  mutable std::shared_mutex mtx;
  /// @param elements The number of elements that can be tracked
  Internal(size_t elements) : max(elements){}
};

/// Construct the mru_manager by specifying how many things it should track
mru_manager::mru_manager(size_t elements) : fields(new Internal(elements)) {}

/// Destruct an mru_manager
mru_manager::~mru_manager() = default;

/// Insert an element into the mru_manager, making sure that (a) there are no
/// duplicates, and (b) the manager holds no more than /max_size/ elements.
///
/// @param elt The element to insert
void mru_manager::insert(const string &elt) {
  this->remove(elt);
  this->fields->mtx.lock();
  this->fields->mru.push_back(elt);
  this->fields->mtx.unlock();
}

/// Remove an instance of an element from the mru_manager.  This can leave the
/// manager in a state where it has fewer than max_size elements in it.
///
/// @param elt The element to remove
void mru_manager::remove(const string &elt) {
  this->fields->mtx.lock();
  auto it = this->fields->mru.begin();
  for(; it != this->fields->mru.end(); it++) {
    if(!it->compare(elt)) {
      this->fields->mru.erase(it);
      break;
    }
  }
  this->fields->mtx.unlock();
}

/// Clear the mru_manager
void mru_manager::clear() {
  this->fields->mtx.lock();
  this->fields->mru.clear();
  this->fields->mtx.unlock();
}

/// Produce a concatenation of the top entries, in order of popularit
///
/// @returns A newline-separated list of values
string mru_manager::get() {
  this->fields->mtx.lock_shared();
  string rv(*this->fields->mru.end());
  auto it = this->fields->mru.end() - 1;
  for(; it != this->fields->mru.begin(); it--) {
    rv.append("\n" + *it);
  }
  this->fields->mtx.unlock();
  return rv;
};