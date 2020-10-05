#include <iostream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/hashtable.h"
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
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// A unique 8-byte code to use as a prefix each time a KV pair is written to
  /// disk.
  inline static const string KVENTRY = "KVKVKVKV";
  
  /// A unique 8-byte code for incremental persistence of changes to the auth
  /// table
  inline static const string AUTHDIFF = "AUTHDIFF";

  /// A unique 8-byte code for incremental persistence of updates to the kv
  /// store
  inline static const string KVUPDATE = "KVUPDATE";

  /// A unique 8-byte code for incremental persistence of deletes to the kv
  /// store
  inline static const string KVDELETE = "KVDELETE";

  /// The map of authentication information, indexed by username
  ConcurrentHashTable<string, AuthTableEntry> auth_table;

  /// The map of key/value pairs
  ConcurrentHashTable<string, vec> kv_store;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  FILE* f_ptr;

  /// Construct the Storage::Internal object by setting the filename and bucket
  /// count
  ///
  /// @param fname       The name of the file that should be used to load/store
  ///                    the data
  /// @param num_buckets The number of buckets for the hash
  Internal(string fname, size_t num_buckets)
      : auth_table(num_buckets), kv_store(num_buckets), filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname       The name of the file that should be used to load/store
///                    the data
/// @param num_buckets The number of buckets for the hash
Storage::Storage(const string &fname, size_t num_buckets)
    : fields(new Internal(fname, num_buckets)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading this.filename.  Note that load()
/// begins by clearing the maps, so that when the call is complete,
/// exactly and only the contents of the file are in the Storage object.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
///- Authentication entry format:
///    - Magic 8-byte constant AUTHAUTH
///    - 4-byte binary write of the length of the username
///    - Binary write of the bytes of the username
///    - Binary write of the length of pass_hash
///    - Binary write of the bytes of pass_hash
///    - Binary write of num_bytes
///    - If num_bytes > 0, a binary write of the bytes field
///  - K/V entry format:
///    - Magic 8-byte constant KVKVKVKV
///    - 4-byte binary write of the length of the key
///    - Binary write of the bytes of the key
///    - Binary write of the length of value
///    - Binary write of the bytes of value
/// - AUTHDIFF: when a user's content changes in the Auth table
///   - Magic 8-byte constant AUTHDIFF
///   - 4-byte binary write of the length of the username
///   - Binary write of the bytes of the username
///   - Binary write of num_bytes of the content
///   - If num_bytes > 0, a binary write of the bytes field
/// - KVUPDATE: when a key's value is changed via upsert
///   - Magic 8-byte constant KVUPDATE
///    - 4-byte binary write of the length of the key
///    - Binary write of the bytes of the key
///    - Binary write of the length of value
///    - Binary write of the bytes of value
/// - KVDELETE: when a key is removed from the key/value store
///   - Magic 8-byte constant KVDELETE
///    - 4-byte binary write of the length of the key
///    - Binary write of the bytes of the key
bool Storage::load() {
  this->fields->f_ptr = fopen(fields->filename.c_str(), "r");
  if (this->fields->f_ptr == nullptr) {
    cerr << "File not found: " << fields->filename << endl;
    this->fields->f_ptr = fopen(fields->filename.c_str(), "w");
    return true;
  }
  this->fields->auth_table.clear();
  this->fields->kv_store.clear();
  vec data = load_entire_file(this->fields->filename);
  if(!data.size()) {
    return true;
  }
  size_t i = 0;
  //cout << "parsing data of size " << data.size() << endl;
  while(i < data.size()) {
    //std::cout << "load: in while, i = " << i << ".\n";
    string magic(reinterpret_cast<char*>(data.data()) + i, 8);
    //cout << "magic = '" << magic << "'.\n";
    if(!magic.compare(Storage::Internal::AUTHENTRY)) {
      //handle authtable entry
      i += 8;
      int *u_len = (int32_t*)(data.data() + i);
      //cout << "u_len = " << *u_len << endl;
      i += 4;
      string user(reinterpret_cast<char*>(data.data()) + i, *u_len);
      //cout << "user = " << user << endl;
      i += *u_len;
      int *p_len = (int32_t*)(data.data() + i);
      //cout << "p_len = " << *p_len << endl;
      i += 4;
      string pass(reinterpret_cast<char*>(data.data()) + i, *p_len);
      //cout << "pass = " << pass << endl;
      i += *p_len;
      int *c_len = (int32_t*)(data.data() + i);
      //cout << "c_len = " << *c_len << endl;
      i += 4;
      string content;
      if(*c_len) {
        content.assign(reinterpret_cast<char*>(data.data()) + i, *c_len);
        //cout << "content = " << content << endl;
        i += *c_len;
      }

      Storage::Internal::AuthTableEntry new_entry;
      new_entry.username = user;
      new_entry.pass_hash = pass;
      new_entry.content = vec_from_string(content);
      this->fields->auth_table.insert(user, new_entry, [&](){});

    } else if(!magic.compare(Storage::Internal::KVENTRY)) {
      //handle kv entry
      i += 8;
      int *k_len = (int32_t*)(data.data() + i);
      //cout << "k_len = " << *k_len << endl;
      i += 4;
      string key(reinterpret_cast<char*>(data.data()) + i, *k_len);
      //cout << "key = " << key << endl;
      i += *k_len;
      int *v_len = (int32_t*)(data.data() + i);
      //cout << "v_len = " << *v_len << endl;
      i += 4;
      string value(reinterpret_cast<char*>(data.data()) + i, *v_len);
      //cout << "value = " << value << endl;
      i += *v_len;

      this->fields->kv_store.insert(key, vec_from_string(value), [&](){});
    } /// - KVUPDATE: when a key's value is changed via upsert
      ///   - Magic 8-byte constant KVUPDATE
      ///    - 4-byte binary write of the length of the key
      ///    - Binary write of the bytes of the key
      ///    - Binary write of the length of value
      ///    - Binary write of the bytes of value
    else if(!magic.compare(Storage::Internal::KVUPDATE)) {
      //handle kv entry
      i += 8;
      int *k_len = (int32_t*)(data.data() + i);
      //cout << "k_len = " << *k_len << endl;
      i += 4;
      string key(reinterpret_cast<char*>(data.data()) + i, *k_len);
      //cout << "key = " << key << endl;
      i += *k_len;
      int *v_len = (int32_t*)(data.data() + i);
      //cout << "v_len = " << *v_len << endl;
      i += 4;
      string value(reinterpret_cast<char*>(data.data()) + i, *v_len);
      //cout << "value = " << value << endl;
      i += *v_len;

      this->fields->kv_store.upsert(key, vec_from_string(value), [&](){}, [&](){});
    } /// - KVDELETE: when a key is removed from the key/value store
      ///   - Magic 8-byte constant KVDELETE
      ///    - 4-byte binary write of the length of the key
      ///    - Binary write of the bytes of the key
    else if(!magic.compare(Storage::Internal::KVDELETE)) {
      //handle kv entry
      i += 8;
      int *k_len = (int32_t*)(data.data() + i);
      //cout << "k_len = " << *k_len << endl;
      i += 4;
      string key(reinterpret_cast<char*>(data.data()) + i, *k_len);
      //cout << "key = " << key << endl;
      i += *k_len;

      this->fields->kv_store.remove(key, [&](){});
    } /// - AUTHDIFF: when a user's content changes in the Auth table
      ///   - Magic 8-byte constant AUTHDIFF
      ///   - 4-byte binary write of the length of the username
      ///   - Binary write of the bytes of the username
      ///   - Binary write of num_bytes of the content
      ///   - If num_bytes > 0, a binary write of the bytes field
    else if(!magic.compare(Storage::Internal::AUTHDIFF)) {
      //handle kv entry
      i += 8;
      int *u_len = (int32_t*)(data.data() + i);
      //cout << "u_len = " << *u_len << endl;
      i += 4;
      string user(reinterpret_cast<char*>(data.data()) + i, *u_len);
      //cout << "user = " << user << endl;
      i += *u_len;
      int *c_len = (int32_t*)(data.data() + i);
      //cout << "c_len = " << *c_len << endl;
      i += 4;
      string content;
      if(*c_len) {
        content.assign(reinterpret_cast<char*>(data.data()) + i, *c_len);
        //cout << "content = " << content << endl;
        i += *c_len;
      }
      this->fields->auth_table.do_with(user, [&](Storage::Internal::AuthTableEntry &entry){entry.content = vec_from_string(content);});
    } else if (i < data.size()) {
      //unknown magic bytes 
      return false;
    }
  }
  cerr << "Loaded: " << this->fields->filename << "\n";
  fclose(this->fields->f_ptr);
  this->fields->f_ptr = fopen(fields->filename.c_str(), "a+");
  return true;
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
  Storage::Internal::AuthTableEntry new_user;
  unsigned char md5_digest[MD5_DIGEST_LENGTH];
  unsigned char* hashed = MD5((unsigned char*)&pass, pass.length(), (unsigned char*)&md5_digest);
  const char* hashed_pass = reinterpret_cast<const char*>(hashed);
  new_user.username = user_name;
  new_user.pass_hash = hashed_pass;
  vec data;
  bool result = this->fields->auth_table.insert(user_name, new_user, [&]() {
    vec_append(data, Storage::Internal::AUTHENTRY);
    vec_append(data, (int)(new_user.username.size()));
    vec_append(data, new_user.username);
    vec_append(data, (int)16);
    vec hash(hashed_pass, hashed_pass + 16);
    //vec_append(data, (int)new_user.pass_hash.size()); //why doesn't this work? (it works for persist)
    //vec_append(data, new_user.pass_hash); // ^^ 
    vec_append(data, hash);
    vec_append(data, (int)new_user.content.size());
    fwrite(data.data(), sizeof(char), data.size(), this->fields->f_ptr);
    fflush(this->fields->f_ptr);
  });
  //std::cout << "add_user: result of insert = " << (bool)result << std::endl;
  return result;
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
vec Storage::set_user_data(const string &user_name, const string &pass, const vec &content) {
  if(!auth(user_name, pass)) {
    //std::cerr << "error_check: authentication failed.\n"; 
    return vec_from_string(RES_ERR_LOGIN);
  }
  vec data;
  this->fields->auth_table.do_with(user_name, [&](Storage::Internal::AuthTableEntry &entry) { 
    entry.content = content;
    vec_append(data, Storage::Internal::AUTHDIFF);
    vec_append(data, (int)(user_name.size()));
    vec_append(data, user_name);
    vec_append(data, (int)(content.size()));
    if(content.size() > 0) {
      vec_append(data, content);
    }
    fwrite(data.data(), sizeof(char), data.size(), this->fields->f_ptr);
    fflush(this->fields->f_ptr);
  });
  //std::cout << "set_user_data: " << user_name << "'s content set to: " << reinterpret_cast<const char*>(content.data()) << std::endl;
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
pair<bool, vec> Storage::get_user_data(const string &user_name, const string &pass, const string &who) {
                               //std::cout << "get_user_data: entered.\n";

  //std::cout << "user = " << user_name << ", length = " << user_name.size() << ".\n";
  if(!auth(user_name, pass)) {
    //std::cerr << "error_check: authentication failed.\n"; 
    return {true, vec_from_string(RES_ERR_LOGIN)};
  } else if(!this->fields->auth_table.do_with_readonly(who, [&](const Storage::Internal::AuthTableEntry &entry){})) {
    //std::cerr << "get_user_data: user: " << who << " not found.\n";
    return {true, vec_from_string(RES_ERR_NO_USER)};
  }
  vec data;
  this->fields->auth_table.do_with_readonly(user_name, [&](const Storage::Internal::AuthTableEntry &entry){
    data = entry.content;
  });
  if(data.empty()) {
    //std::cerr << "get_user_data: user: " << who << " has no content.\n";
    return {true, vec_from_string(RES_ERR_NO_DATA)};
  }
  return {false, data};
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name, const string &pass) {
  //std::cout << "get_all_users: entered.\n";
  if(!auth(user_name, pass)) {
    //std::cerr << "error_check: authentication failed.\n"; 
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }
  vec users;
  this->fields->auth_table.do_all_readonly([&](const string user_name, const Storage::Internal::AuthTableEntry &entry) {
    vec_append(users, user_name);
    vec_append(users, '\n');
  }, [](){});
  return {false, users};
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass) {
  //std::cout << "auth: entered.\n";
  Storage::Internal::AuthTableEntry check;
  unsigned char md5_digest[MD5_DIGEST_LENGTH];
  unsigned char* hashed = MD5((unsigned char*)&pass, pass.length(), (unsigned char*)&md5_digest);
  const char* hashed_pass;
  hashed_pass = reinterpret_cast<const char*>(hashed);
  check.pass_hash = hashed_pass;
  bool authenticated = false;
  //std::cout << "check.hashed_pass: " << hashed_pass << endl;
  function check_func = [&](Storage::Internal::AuthTableEntry &entry){ 
    if(entry.pass_hash.compare(check.pass_hash)) authenticated = true;
  };
  this->fields->auth_table.do_with(user_name, check_func);
  return authenticated;
}

/// Write the entire Storage object to the file specified by this.filename.
/// To ensure durability, Storage must be persisted in two steps.  First, it
/// must be written to a temporary file (this.filename.tmp).  Then the
/// temporary file can be renamed to replace the older version of the Storage
/// object.
///- Authentication entry format:
///    - Magic 8-byte constant AUTHAUTH
///    - 4-byte binary write of the length of the username
///    - Binary write of the bytes of the username
///    - Binary write of the length of pass_hash
///    - Binary write of the bytes of pass_hash
///    - Binary write of num_bytes
///    - If num_bytes > 0, a binary write of the bytes field
///  - K/V entry format:
///    - Magic 8-byte constant KVKVKVKV
///    - 4-byte binary write of the length of the key
///    - Binary write of the bytes of the key
///    - Binary write of the length of value
///    - Binary write of the bytes of value
void Storage::persist() {
  fclose(this->fields->f_ptr);
  vec data = {};
  this->fields->auth_table.do_all_readonly([&](const string user_name, const Storage::Internal::AuthTableEntry &entry){
    vec_append(data, Storage::Internal::AUTHENTRY);
    vec_append(data, (int)(entry.username.size()));
    vec_append(data, entry.username);
    vec_append(data, (int)(entry.pass_hash.size()));
    vec_append(data, entry.pass_hash);
    vec_append(data, (int)(entry.content.size()));
    if(entry.content.size() > 0) {
      vec_append(data, entry.content);
    }
  }, [&](){
    fields->kv_store.do_all_readonly([&](const string key2, const vec &value2) {
      vec_append(data, Storage::Internal::KVENTRY);
      vec_append(data, (int)(key2.size()));
      vec_append(data, key2);
      vec_append(data, (int)(value2.size()));
      vec_append(data, value2);
      write_file(this->fields->filename + ".tmp", reinterpret_cast<const char*>(data.data()), data.size());
    }, [](){});
  });
  write_file(this->fields->filename + ".tmp", reinterpret_cast<const char*>(data.data()), data.size());
  rename((this->fields->filename + ".tmp").c_str(), this->fields->filename.c_str());
}

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}

/// Create a new key/value mapping in the table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose mapping is being created
/// @param val       The value to copy into the map
///
/// @returns A vec with the result message
vec Storage::kv_insert(const string &user_name, const string &pass,
                       const string &key, const vec &val) {
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }
  vec data;
  //std::cerr << "passed auth in kv_insert";
  if (!this->fields->kv_store.insert(key, val, [&](){
    vec_append(data, Storage::Internal::KVENTRY);
    vec_append(data, (int)(key.size()));
    vec_append(data, key);
    vec_append(data, (int)(val.size()));
    vec_append(data, val);
    fwrite(data.data(), sizeof(char), data.size(), this->fields->f_ptr);
    fflush(this->fields->f_ptr);
  })) return vec_from_string(RES_ERR_KEY);
  return vec_from_string(RES_OK);
};

/// Get a copy of the value to which a key is mapped
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose value is being fetched
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          data (possibly an error message) that is the result of the
///          attempt.
pair<bool, vec> Storage::kv_get(const string &user_name, const string &pass, const string &key) {
  if (!auth(user_name, pass)) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }
  vec data;
  if(!this->fields->kv_store.do_with_readonly(key, [&](const vec value){vec_append(data, value);})) {
    return {true, vec_from_string(RES_ERR_KEY)};
  }
  //if(!data.size()) return {true, vec_from_string(RES_ERR_NO_DATA)};
  return {false, data};
};

/// Delete a key/value mapping
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose value is being deleted
///
/// @returns A vec with the result message
vec Storage::kv_delete(const string &user_name, const string &pass,
                       const string &key) {
  vec data;
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }
  if(!this->fields->kv_store.remove(key,[&](){
    vec_append(data, Storage::Internal::KVDELETE);
    vec_append(data, (int)(key.size()));
    vec_append(data, key);
    fwrite(data.data(), sizeof(char), data.size(), this->fields->f_ptr);
    fflush(this->fields->f_ptr);
  })) {
    return vec_from_string(RES_ERR_KEY);
  }
  return vec_from_string(RES_OK);
};

/// Insert or update, so that the given key is mapped to the give value
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose mapping is being upserted
/// @param val       The value to copy into the map
///
/// @returns A vec with the result message.  Note that there are two "OK"
///          messages, depending on whether we get an insert or an update.
vec Storage::kv_upsert(const string &user_name, const string &pass,
                       const string &key, const vec &val) {
  //std::cout << "kv_upsert: entered.\n";
  vec data;
  // Authenticate
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }
  if (fields->kv_store.upsert(key, vec(val), [&](){
    vec_append(data, Storage::Internal::KVENTRY);
    vec_append(data, (int)(key.size()));
    vec_append(data, key);
    vec_append(data, (int)(val.size()));
    vec_append(data, val);
    fwrite(data.data(), sizeof(char), data.size(), this->fields->f_ptr);
    fflush(this->fields->f_ptr);
  }, [&]() {
    vec_append(data, Storage::Internal::KVUPDATE);
    vec_append(data, (int)(key.size()));
    vec_append(data, key);
    vec_append(data, (int)(val.size()));
    vec_append(data, val);
    fwrite(data.data(), sizeof(char), data.size(), this->fields->f_ptr);
    fflush(this->fields->f_ptr);
  }))
    return vec_from_string(RES_OKINS);
  return vec_from_string(RES_OKUPD);
};

/// Return all of the keys in the kv_store, as a "\n"-delimited string
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A pair with a bool to indicate errors, and a vec with the result
///          (possibly an error message).
pair<bool, vec> Storage::kv_all(const string &user_name, const string &pass) {
  //std::cout << "get_all_users: entered.\n";
  /*if(!this->fields->auth_table.do_with_readonly(user_name, [&](const Storage::Internal::AuthTableEntry &entry){})) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  } else */if(!auth(user_name, pass)) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }
  vec values;
  this->fields->kv_store.do_all_readonly([&](string key, vec value){
    vec_append(values, key);
    vec_append(values, "\n");
  }, [](){});
  if(!values.size()) {
    return {true, vec_from_string(RES_ERR_NO_DATA)};
  }
  return {false, values};
};