#include <sys/wait.h>
#include <unistd.h>

#include "../common/contextmanager.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_storage.h"
#include "server_storage_internal.h"

using namespace std;

/// Perform the child half of a map/reduce communication
///
/// @param in_fd   The fd from which to read data from the parent
/// @param out_fd  The fd on which to write data to the parent
/// @param mapper  The map function to run on each pair received from the
///                parent
/// @param reducer The reduce function to run on the results of mapper
///
/// @returns false if any error occurred, true otherwise
bool child_mr(int in_fd, int out_fd, map_func mapper, reduce_func reducer) {
  return false;
}

/// Register a .so with the function table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param mrname    The name to use for the registration
/// @param so        The .so file contents to register
///
/// @returns A vec with the result message
vec Storage::register_mr(const string &user_name, const string &pass,
                         const string &mrname, const vec &so) {
  return vec_from_string(RES_ERR_LOGIN);
};

/// Run a map/reduce on all the key/value pairs of the kv_store
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, to authenticate
/// @param mrname    The name of the map/reduce functions to use
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
pair<bool, vec> Storage::invoke_mr(const string &user_name, const string &pass,
                                   const string &mrname) {
  return {true, vec_from_string(RES_ERR_LOGIN)};
}