#include <string>

#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_storage.h"

#include <algorithm>
#include <vector>

using namespace std;



/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_all(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  cerr << "server_cmd_all is not implemented\n";
  
  return false;
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_set(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  cerr << "server_cmd_set is not implemented\n";
  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_get(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  int i = 0;
  char c = req[i];
  while(i < req.size() && c != '\n') c = req[++i];
  string user(reinterpret_cast<const char*>(req.data()), i);
  int j = ++i;
  c = req[i];
  while(i < req.size() && c != '\n') c = req[++i];
  string pass(reinterpret_cast<const char*>(req.data()) + j, i - j);
  string who(reinterpret_cast<const char*>(req.data()) + i + 1, req.size() - i);
  cout << "server_cmd_get: user, pass, who = " << user << ", " << pass << ", " << who << ".\n";
  string res(RES_OK);
  if(!user.size() || !pass.size() || !who.size() || user.size() > LEN_UNAME || pass.size() > LEN_PASS || who.size() > LEN_UNAME) {
    res = RES_ERR_MSG_FMT;
  } 
  pair<bool, vec> rv = storage.get_user_data(user, pass, who);
  cout << "error, size = " << (char*)rv.second.data() << ", " << rv.second.size() << endl;
  if(!rv.first) {
    res = string((char*)(rv.second.data()));
  }
  vec enc_res = aes_crypt_msg(ctx, res);
  if(!send_reliably(sd, enc_res)) {
    cerr << "server_cmd_reg: send_reliably() failed.\n";
  }
  cout << "server_cmd_reg: sent " << enc_res.size() << " bytes.\n";
  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_reg(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  int i = 0;
  char c = (char)req[i];
  while(i < req.size() && c != '\n') {
    c = req[++i];
  }
  string user(reinterpret_cast<const char*>(req.data()), i);
  string pass(reinterpret_cast<const char*>(req.data()) + i + 1, req.size() - i - 1);
  cout << "server_cmd_reg: user, pass = " << user << ", " << pass << "."<< endl;
  string res(RES_OK);
  if(!user.size() || !pass.size() || user.size() > LEN_UNAME || pass.size() > LEN_PASS) {
    res = RES_ERR_MSG_FMT;
  } else if(!storage.add_user(user, pass)) {
    res = RES_ERR_USER_EXISTS;
  }
  vec enc_res = aes_crypt_msg(ctx, res);
  if(!send_reliably(sd, enc_res)) {
    cerr << "server_cmd_reg: send_reliably() failed.\n";
  }
  cout << "server_cmd_reg: sent " << enc_res.size() << " bytes.\n";
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
void server_cmd_key(int sd, const vec &pubfile) {
  if(!send_reliably(sd, reinterpret_cast<const char*>(pubfile.data()))) {
    cerr << "server_cmd_key: failed to send RSA key.\n";
  }
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns true, to indicate that the server should stop, or false on an error
bool server_cmd_bye(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  cerr << "server_cmd_bye is not implemented\n";
  return false;
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_sav(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  cerr << "server_cmd_sav is not implemented\n";
  return false;
}
