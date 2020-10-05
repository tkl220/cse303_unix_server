#include <iostream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"

#include "server_storage.h"

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal {
  /// AuthTableEntry represents one user stored in the authentication table
  struct AuthTableEntry {
    /// The name of the user; max 64 characters
    string username;

    /// The hashed password.  Note that the password is a max of 128 chars
    string pass_hash;

    /// The user's content
    vec content;
  };

  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  ///
  /// NB: this isn't needed in assignment 1, but will be useful for backwards
  ///     compatibility later on.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// The map of authentication information, indexed by username
  unordered_map<string, AuthTableEntry> auth_table;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// Construct the Storage::Internal object by setting the filename
  ///
  /// @param fname The name of the file that should be used to load/store the
  ///              data
  Internal(const string &fname) : filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname The name of the file that should be used to load/store the
///              data
Storage::Storage(const string &fname) : fields(new Internal(fname)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading an auth_table from this.filename.
/// Note that load() begins by clearing the auth_table, so that when the call
/// is complete, exactly and only the contents of the file are in the
/// auth_table.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load() {
  std::cout << "load: entered.\n";
  if(!file_exists(this->fields->filename)) {
    std::cerr << "load: file does not exist.\n";
    return true;
  }
  this->fields->auth_table.clear();
  vec data = load_entire_file(this->fields->filename);
  if(!data.size()) {
    std::cerr << "load: no data in file.\n";
    return true;
  }
  int i = 8;
  while( i < data.size()) {
    std::cout << "load: in while, i = " << i << ".\n";
    int *u_size = (int32_t*)(data.data() + i);
    i += U_SIZE_SIZE;
    std::string user(reinterpret_cast<char*>(data.data()) + i, *u_size);
    i += *u_size;
    int *p_size = (int32_t*)(data.data() + i);
    i += P_SIZE_SIZE;
    std::string pass(reinterpret_cast<char*>(data.data()) + i, *p_size);
    i += *p_size;
    int *c_size = (int32_t*)(data.data() + i);
    i += C_SIZE_SIZE;
    std::string content(reinterpret_cast<char*>(data.data()) + i, *c_size);
    i += *c_size;

    Storage::Internal::AuthTableEntry new_entry;
    new_entry.username = user;
    new_entry.pass_hash = pass;
    new_entry.content = vec_from_string(content);
    this->fields->auth_table.insert({user, new_entry});
  }
  std::cout << "load: end of while.\n";
  return false;
}

bool Storage::exists(const string &user_name) {
  return this->fields->auth_table.count(user_name) != 0;
}

pair<bool, vec> Storage::error_check(const std::string &user_name, const std::string &pass) {
  if(!exists(user_name)) {
    std::cerr << "error_check: user exists.\n"; 
    return {true, vec_from_string(RES_ERR_NO_USER)};
  } else if(!auth(user_name, pass)) {
    std::cerr << "error_check: authentication failed.\n"; 
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }
  return {false, vec_from_string(RES_OK)};
}


/// Create a new entry in the Auth table.  If the user_name already exists, we
/// should return an error.  Otherwise, hash the password, and then save an
/// entry with the username, hashed password, and a zero-byte content.
///
/// @param user_name The user name to register
/// @param pass      The password to associate with that user name
///
/// @returns False if the username already exists, true otherwise
bool Storage::add_user(const string &user_name, const string &pass) {
  
  if(exists(user_name)) {
    std::cerr << "add_user: user exists.\n"; 
    return false;
  }
  Storage::Internal::AuthTableEntry new_user;
  std::cout << "user = " << user_name << ", length = " << user_name.size() << ".\n";
  std::cout << "pass = " << pass << ", length = " << pass.size() << ".\n";
  unsigned char hash[MD5_DIGEST_LENGTH];
  MD5_CTX context;
  MD5_Init(&context);
  MD5_Update(&context, (unsigned char*)pass.c_str(), pass.size());
  MD5_Final(hash, &context);
  //MD5((unsigned char*)pass.c_str(), pass.size(), hash);
  char mdString[33];
  for(int i = 0; i < 16; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)hash[i]);
  printf("md5 digest: %s\n", mdString);
  new_user.username = user_name;
  new_user.pass_hash = string(mdString);
  printf("md5 digest: %s\n", new_user.pass_hash.c_str());
  new_user.content = {};
  this->fields->auth_table.insert({user_name, new_user});
  std::cout << "add_user: added user : " << user_name << " count = " << this->fields->auth_table.count(user_name) <<std::endl;
  if(this->fields->auth_table.count(user_name) == 0) {
    std::cout << "add_user: ERROR CAN'T FIND USER :: " << user_name << std::endl;
  }
  return true;
}

/// Set the data bytes for a user, but do so if and only if the password
/// matches
///
/// @param user_name The name of the user whose content is being set
/// @param pass      The password for the user, used to authenticate
/// @param content   The data to set for this user
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
vec Storage::set_user_data(const string &user_name, const string &pass,
                           const vec &content) {
  pair<bool, vec> check = error_check(user_name, pass);
  if(check.first) {
    return check.second;
  }
  this->fields->auth_table.at(user_name).content = content;
  std::cout << "set_user_data: " << user_name << "'s content set to: " << reinterpret_cast<const char*>(content.data()) << std::endl;
  return vec_from_string(RES_OK);
}

/// Return a copy of the user data for a user, but do so only if the password
/// matches
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param who       The name of the user whose content is being fetched
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          data (possibly an error message) that is the result of the
///          attempt.  Note that "no data" is an error
pair<bool, vec> Storage::get_user_data(const string &user_name,
                                       const string &pass, const string &who) {
  
  std::cout << "user = " << user_name << ", length = " << user_name.size() << ".\n";
  if (this->fields->auth_table.count(user_name) == 0) {
    std::cerr << "get_user_data: user: " << user_name << ", not found.\n";
    return {false, vec_from_string(RES_ERR_LOGIN)};
  } else if(!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  } else if (this->fields->auth_table.count(who) == 0) {
    std::cerr << "get_user_data: user: " << who << " not found.\n";
    return {false, vec_from_string(RES_ERR_NO_USER)};
  }
  Storage::Internal::AuthTableEntry user_who = this->fields->auth_table.at(who);
  vec data = user_who.content;
  if(data.size() == 0) {
    std::cerr << "get_user_data: user: " << who << " has no content.\n";
    return {false, vec_from_string(RES_ERR_NO_DATA)};
  }
  return {true, data};
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name,
                                       const string &pass) {
  std::cout << "get_all_users: entered.\n";
  pair<bool, vec> check = error_check(user_name, pass);
  if(check.first) {
    return check;
  }
  vec users(this->fields->auth_table.size());
  for(pair<std::string, Storage::Internal::AuthTableEntry> element : this->fields->auth_table) {
    vec_append(users, element.first);
    vec_append(users, "\n");
  }
  return {true, users};
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass) {
  std::cout << "auth: entered.\n";
  unsigned char hash[MD5_DIGEST_LENGTH];
  MD5_CTX context;
  MD5_Init(&context);
  MD5_Update(&context, (unsigned char*)pass.c_str(), pass.size());
  MD5_Final(hash, &context);
  std::cout << "user = " << user_name << ", length = " << user_name.size() << ".\n";
  std::cout << "pass = " << pass << ", length = " << pass.size() << ".\n";
  char mdString[33];
  for(int i = 0; i < 16; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)hash[i]);
  printf("md5 digest: %s\n", mdString);
  /*for(int i = 0; i < 16; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)(this->fields->auth_table.at(user_name).pass_hash[i]));*/
  printf("md5 digest: %s\n", this->fields->auth_table.at(user_name).pass_hash.c_str());
  return string(mdString, 32).compare(this->fields->auth_table.at(user_name).pass_hash) == 0;
}

/// Write the entire Storage object (right now just the Auth table) to the
/// file specified by this.filename.  To ensure durability, Storage must be
/// persisted in two steps.  First, it must be written to a temporary file
/// (this.filename.tmp).  Then the temporary file can be renamed to replace
/// the older version of the Storage object.
void Storage::persist() {
  std::cout << "persist: entered.\n";
  vec data = {};
  for(pair<std::string, Storage::Internal::AuthTableEntry> element : this->fields->auth_table) {
    vec_append(data, Storage::Internal::AUTHENTRY);
    vec_append(data, (int)(element.first.size()));
    vec_append(data, element.first);
    vec_append(data, (int)(element.second.pass_hash.size()));
    vec_append(data, element.second.pass_hash);
    vec_append(data, (int)(element.second.content.size()));
    if(element.second.content.size() > 0) {
      vec_append(data, element.second.content);
    }
  }
  write_file(this->fields->filename + ".tmp", reinterpret_cast<const char*>(data.data()), data.size());
}

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}
