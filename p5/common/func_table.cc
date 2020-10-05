#include <atomic>
#include <dlfcn.h>
#include <iostream>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/file.h"
#include "../common/functypes.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "func_table.h"

using namespace std;

/// func_table::Internal is the private struct that holds all of the fields of
/// the func_table object.  Organizing the fields as an Internal is part of the
/// PIMPL pattern.
///
/// Among other things, this struct will probably need to have a map of loaded
/// functions and a shared_mutex.  The map will probably need to hold some kind
/// of struct that is able to support graceful shutdown, as well as the
/// association of names to map/reduce functions
struct func_table::Internal {};

/// Construct a function table for storing registered functions
func_table::func_table() : fields(new Internal()) {}

/// Destruct a function table
func_table::~func_table() = default;

/// Register the map() and reduce() functions from the provided .so, and
/// associate them with the provided name.
///
/// @param mrname The name to associate with the functions
/// @param so     The so contents from which to find the functions
///
/// @returns a vec with a status message
vec func_table::register_mr(const string &mrname, const vec &so) {
  return vec_from_string(RES_ERR_SO);
}

/// Get the (already-registered) map() and reduce() functions asssociated with
/// a name.
///
/// @param name The name with which the functions were mapped
///
/// @returns A pair of function pointers, or {nullptr, nullptr} on error
pair<map_func, reduce_func> func_table::get_mr(const string &mrname) {
  return {nullptr, nullptr};
}

/// When the function table shuts down, we need to de-register all the .so
/// files that were loaded.
void func_table::shutdown() {}