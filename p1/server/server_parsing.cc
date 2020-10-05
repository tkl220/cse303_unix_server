#include <cstring>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_parsing.h"
#include "server_storage.h"

using namespace std;

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to send to the client
/// @param storage The Storage object with which clients interact
///
/// @returns true if the server should halt immediately, false otherwise
bool serve_client(int sd, RSA *pri, const vec &pub, Storage &storage) {
  cerr << "serve_client: entered\n";
  vec req(LEN_RKBLOCK);
  vec::iterator pos = req.begin();
  if(reliable_get_to_eof_or_n(sd, pos, LEN_RKBLOCK) == -1) {
    cerr << "serve_client: reliable_get_to_eof_or_n failed.\n";
    return false;
  }
  cout << "serve_client: req.size() = " << req.size() << endl;
  cerr << "serve_client: returned from reliable_get_to_eof.\n";
  if(req.size() == LEN_RKBLOCK && !strncmp(reinterpret_cast<const char*>(req.data()), "KEY", 3)) {
    cerr << "serve_client: KEY command received.\n";
    // KEY request
    server_cmd_key(sd, pub);
    return false;
  }
  cerr << "serve_client: only KEY request implemented.\n";
  // Figure out which command was requested, and run it
  // RSA decrypt
  unsigned char dec[LEN_RBLOCK_CONTENT];
  int bytes_dec;
  if((bytes_dec = RSA_private_decrypt(LEN_RKBLOCK, req.data(), dec, pri, RSA_PKCS1_OAEP_PADDING)) != LEN_RBLOCK_CONTENT) {
    char err_buff[1024];
    ERR_error_string(ERR_get_error(), err_buff);
    cerr << "serve_client: error - decrypt failed, bytes_dec = " << bytes_dec << ", error code = " << err_buff << endl;
  }
  // find command
  cout << "serve_client: bytes_dec = " << bytes_dec << endl;
  string cmd((char*)dec, 3);
  cout << "serve_client: found cmd = " << cmd[0] << cmd[1] << cmd[2] << endl;
  vec AES_key = vec_from_string(string((char*)(dec + 3), 48));
  int *ablock_len = (int32_t*)(dec + 51);
  cout << "serve_client: ablock_len = " << *ablock_len << endl;
  // read ablock
  vec enc_ablock(*ablock_len);
  pos = enc_ablock.begin();
  if(reliable_get_to_eof_or_n(sd, pos, *ablock_len) == -1) {
    cerr << "serve_client: reliable_get_to_eof_or_n() failed.\n";
    return false;
  }
  // AES decrypt
  EVP_CIPHER_CTX *ctx = create_aes_context(AES_key, false);
  vec ablock = aes_crypt_msg(ctx, enc_ablock);
  reset_aes_context(ctx, AES_key, true);
  if(!ablock.size()) {
    cerr << "serve_client: aes_crypt_msg() failed, or no input.\n";
    ablock = aes_crypt_msg(ctx, RES_ERR_CRYPTO);
    if(!send_reliably(sd, ablock)) {
      cerr << "server_client: send_reliably() failed.\n";
    }
    cout << "serve_client: send_reliably() succeeded with " << ablock.size() << " bytes sent.\n";
    return false;
  }
  cout << "serve_client: (size = " << ablock.size() << ") ablock = " << reinterpret_cast<const char*>(ablock.data()) << endl;
  // call method
  vector<string> cmds = {REQ_REG, REQ_BYE, REQ_SET, REQ_GET, REQ_ALL, REQ_SAV};
  decltype(server_cmd_reg) *funcs[] = {server_cmd_reg, server_cmd_bye, server_cmd_set,
                                   server_cmd_get, server_cmd_all, server_cmd_sav};
  for (size_t i = 0; i < cmds.size(); ++i) {
    if (cmd == cmds[i]) {
      funcs[i](sd, storage, ctx, ablock);
    }
  }
  return false;
}
