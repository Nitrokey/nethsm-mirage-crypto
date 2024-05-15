#include "mirage_crypto.h"

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"


#define __define_hash(name, upper)                                           \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _init (value ctx) {                                         \
    struct name ## _ctx ctx_;                                                \
    memset(&ctx_, 0, sizeof(struct name ## _ctx));              \
    _mc_ ## name ## _init (&ctx_);         \
    memcpy(Bytes_val(ctx), &ctx_, sizeof(struct name ## _ctx));              \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _update (value ctx, value src, value len) {                 \
    struct name ## _ctx ctx_;                                                \
    memcpy(&ctx_, Bytes_val(ctx), sizeof(struct name ## _ctx));              \
    _mc_ ## name ## _update (                                                \
      &ctx_,                               \
      _ba_uint8 (src), Int_val (len));                                       \
    memcpy(Bytes_val(ctx), &ctx_, sizeof(struct name ## _ctx));              \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _finalize (value ctx, value dst) {                          \
    struct name ## _ctx ctx_;                                                \
    memcpy(&ctx_, Bytes_val(ctx), sizeof(struct name ## _ctx));              \
    _mc_ ## name ## _finalize (                                              \
      &ctx_, _ba_uint8 (dst));             \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _ctx_size (__unit ()) {                                     \
    return Val_int (upper ## _CTX_SIZE);                                     \
  }

__define_hash (md5, MD5)
__define_hash (sha1, SHA1)
__define_hash (sha224, SHA224)
__define_hash (sha256, SHA256)
__define_hash (sha384, SHA384)
__define_hash (sha512, SHA512)
