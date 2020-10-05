#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string>
#include <sys/random.h>
#include <sstream>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "client_commands.h"

using namespace std;

/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
///
/// @returns true if the padding was done, false on any error
bool padR(vec &v, size_t sz) {
  unsigned char buff[sz-v.size()];
  cout << "orginal v = " << v.size() << ", sz = " << sz << ".\n";
  if(!RAND_bytes(buff, sz-v.size())) {
    cerr << "padR: RAND_bytes() failed.\n";
    return false;
  }
  string s((char*)buff, sz-v.size());
  vec_append(v, vec_from_string(s));
  if(v.size() != sz) {
    cerr << "padR: bad v.size() = " << v.size() << ".\n";
    return false;
  }
  return true;
}

/// Check if the provided result vector is a string representation of ERR_CRYPTO
///
/// @param v The vector being compared to RES_ERR_CRYPTO
///
/// @returns true if the vector contents are RES_ERR_CRYPTO, false otherwise
bool check_error(const vec &res) {
  if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_OK.c_str(), sizeof(RES_OK))) {
    cout << "check_error: server response OK.\n";
    return false;
  }
  if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_USER_EXISTS.c_str(), sizeof(RES_ERR_USER_EXISTS))) {
    cerr << "client_send_cmd: server response - user exists.\n";
  } else if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_LOGIN.c_str(), sizeof(RES_ERR_LOGIN))) {
    cerr << "client_send_cmd: server response - password or user invalid\n";
  } else if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_MSG_FMT.c_str(), sizeof(RES_ERR_MSG_FMT))) {
    cerr << "client_send_cmd: server response - message format error.\n";
  } else if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_NO_DATA.c_str(), sizeof(RES_ERR_NO_DATA))) {
    cerr << "client_send_cmd: server response - no data\n";
  } else if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_NO_USER.c_str(), sizeof(RES_ERR_NO_USER))) {
    cerr << "client_send_cmd: server response - invalid user.\n";
  } else if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_INV_CMD.c_str(), sizeof(RES_ERR_INV_CMD))) {
    cerr << "client_send_cmd: server response - invalid command\n";
  } else if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_XMIT.c_str(), sizeof(RES_ERR_XMIT))) {
    cerr << "client_send_cmd: server response - trasmit error\n";
  } else if(!strncmp(reinterpret_cast<const char*>(res.data()), RES_ERR_CRYPTO.c_str(), sizeof(RES_ERR_CRYPTO))) {
    cerr << "client_send_cmd: server response - could not decrypt.\n";
  }
  return true;
}

/// If a buffer consists of OK.bbbb.d+, where bbbb is a 4-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const vec &buff, const string &filename) {
  int *size = (int *)&buff[2];
  if(!write_file(filename, reinterpret_cast<const char*>(buff.data())+6, *size)) {
    cerr << "send_result_to_file: write_file() failed.\n";
  }
}

/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// Many of the messages in our server have a common form (@rblock.@ablock):
///   - @rblock padR(enc(pubkey, "CMD".aeskey.length(@msg)))
///   - @ablock enc(aeskey, @msg)
///
/// @param sd  An open socket
/// @param pub The server's public key, for encrypting the aes key
/// @param cmd The command that is being sent
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (decrypted) result, or an empty vector on error
vec client_send_cmd(int sd, RSA *pub, const string &cmd, const vec &msg) {
  unsigned char enc[LEN_RKBLOCK];
  vec AES_key = create_aes_key();
  vec ablock = aes_crypt_msg(create_aes_context(AES_key, true), msg);
  vec rblock = vec_from_string(cmd);
  vec_append(rblock, AES_key);
  vec_append(rblock, (int)ablock.size());
  cout << "client_send_cmd: created ablock of size = " << ablock.size() << ", number of bytes = " << sizeof((int)ablock.size()) << endl;

  padR(rblock, LEN_RBLOCK_CONTENT);
  cout << "client_send_cmd: padded rblock.size() = " << rblock.size() << endl;

  int rv = RSA_public_encrypt(LEN_RBLOCK_CONTENT, rblock.data(), enc, pub, RSA_PKCS1_OAEP_PADDING);
  char err_buff[1024];
  ERR_error_string(ERR_get_error(), err_buff);
  cout << "client_send_cmd: RSA_public_encrypt returned rv = " << rv << ", error code = " << err_buff << ".\n";
  string s((char*)enc, LEN_RKBLOCK);
  vec enc_rblock = vec_from_string(s);

  vec block;
  vec_append(block, enc_rblock);
  vec_append(block, ablock);

  if(!send_reliably(sd, block)) {
    cerr << "client_send_cmd: failed to send.\n";
    return {};
  }
  vec res = reliable_get_to_eof(sd);
  if(!res.size()) {
    cerr << "client_send_cmd: reliable_get_to_eof failed.\n";
    return {};
  }
  cout << "client_send_cmd: read " << res.size() << " bytes.\n";
  res = aes_crypt_msg(create_aes_context(AES_key, false), res);
  cout << "client_send_cmd: res = " << res.data() << endl;
  cout << "error, size = " << (char*)res.data() << ", " << res.size() << endl;
  if(check_error(res)) {
    return {};
  }
  return res;
}

/// client_key() writes a request for the server's key on a socket descriptor.
/// When it gets it, it writes it to a file.
///
/// @param sd      An open socket
/// @param keyfile The name of the file to which the key should be written
void client_key(int sd, const string &keyfile) {
  cerr << "client_key: entered.\n";
  vec kblock(LEN_RKBLOCK, '\0');
  kblock[0] = 'K';
  kblock[1] = 'E';
  kblock[2] = 'Y';
  if(!send_reliably(sd, kblock)) {
    cerr << "client_key: reliable_send() failed.\n";
  }
  cerr << "client_key: send reliably returned.\n";
  vec RSA_key(LEN_RSA_PUBKEY);
  vec::iterator pos = RSA_key.begin();
  int rv;
  if((rv= reliable_get_to_eof_or_n(sd, pos, LEN_RSA_PUBKEY)) != LEN_RSA_PUBKEY) {
    cerr << "client_key: invalid RSA_key length = " << RSA_key.size() << ", rv = " << rv << ".\n";
    return;
  }
  cerr << "client_key: reliable get to eof returned.\n";
  if(!write_file(keyfile, reinterpret_cast<char*>(RSA_key.data()), LEN_RSA_PUBKEY)) {
    cerr << "client_key: failed to write RSA_key to " << keyfile << ".\n";
  }
  cout << reinterpret_cast<unsigned char*>(RSA_key.data());
  cout << "client_key: returning....\n";
}

/// client_reg() sends the REG command to register a new user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_reg(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec msg = vec_from_string(user + "\n" + pass);
  client_send_cmd(sd, pubkey, REQ_REG, msg);
}

/// client_bye() writes a request for the server to exit.
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_bye(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec msg = vec_from_string(user + "\n" + pass);
  client_send_cmd(sd, pubkey, REQ_BYE, msg);
}

/// client_sav() writes a request for the server to save its contents
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
void client_sav(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec msg = vec_from_string(user + "\n" + pass);
  client_send_cmd(sd, pubkey, REQ_SAV, msg);
}

/// client_set() sends the SET command to set the content for a user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void client_set(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &setfile, const string &) {
  if(setfile.size() > LEN_CONTENT) {
    cerr << "client_set: setfile exceeds " << LEN_CONTENT << " bytes.\n";
    return;
  }
  ostringstream val;
  val << setfile.size();
  vec msg = vec_from_string(user + "\n" + pass + "\n" + val.str() + setfile);
  client_send_cmd(sd, pubkey, REQ_SET, msg);
}

/// client_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void client_get(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &getname, const string &) {
  vec msg = vec_from_string(user + "\n" + pass + "\n" + getname);
  auto res = client_send_cmd(sd, pubkey, REQ_GET, msg);
  // Send the result to file, or print an error
  if(res.size()) {
    send_result_to_file(res, getname + ".file.dat");
  }
}

/// client_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
/// @param allfile The file where the result should go
void client_all(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &allfile, const string &) {
  vec msg = vec_from_string(user + "\n" + pass);
  auto res = client_send_cmd(sd, pubkey, REQ_ALL, msg);
  // Send the result to file, or print an error
  send_result_to_file(res, allfile + ".file.dat");
}
