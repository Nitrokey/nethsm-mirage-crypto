open Nethsm_crypto

module P256 : Dh_dsa = struct
  module Params = struct
    let a =
      "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"

    let b =
      "\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B"

    let g_x =
      "\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96"

    let g_y =
      "\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5"

    let p =
      "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

    let n =
      "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51"

    let pident =
      "\x3F\xFF\xFF\xFF\xC0\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    (* (Params.p + 1) / 4*)

    let byte_length = 32
    let bit_length = 256
    let fe_length = 32
    let first_byte_bits = None
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit
      = "mc_p256_mul"
    [@@noalloc]

    external sub : out_field_element -> field_element -> field_element -> unit
      = "mc_p256_sub"
    [@@noalloc]

    external add : out_field_element -> field_element -> field_element -> unit
      = "mc_p256_add"
    [@@noalloc]

    external to_montgomery : out_field_element -> field_element -> unit
      = "mc_p256_to_montgomery"
    [@@noalloc]

    external from_octets : out_field_element -> string -> unit
      = "mc_p256_from_bytes"
    [@@noalloc]

    external set_one : out_field_element -> unit = "mc_p256_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_p256_nz" [@@noalloc]

    external sqr : out_field_element -> field_element -> unit = "mc_p256_sqr"
    [@@noalloc]

    external from_montgomery : out_field_element -> field_element -> unit
      = "mc_p256_from_montgomery"
    [@@noalloc]

    external to_octets : bytes -> field_element -> unit = "mc_p256_to_bytes"
    [@@noalloc]

    external inv : out_field_element -> field_element -> unit = "mc_p256_inv"
    [@@noalloc]

    external select_c :
      out_field_element -> bool -> field_element -> field_element -> unit
      = "mc_p256_select"
    [@@noalloc]

    external scalar_mult_c : out_point -> string -> point -> unit
      = "mc_p256_scalar_mult"
    [@@noalloc]

    external scalar_mult_add_c : out_point -> string -> string -> point -> unit
      = "mc_p256_scalar_mult_add"
    [@@noalloc]

    external scalar_mult_base_c : out_point -> string -> unit
      = "mc_p256_scalar_mult_base"
    [@@noalloc]
  end

  module Foreign_n = struct
    external mul :
      out_scalar_element -> scalar_element -> scalar_element -> unit
      = "mc_np256_mul"
    [@@noalloc]

    external add :
      out_scalar_element -> scalar_element -> scalar_element -> unit
      = "mc_np256_add"
    [@@noalloc]

    external inv : out_scalar_element -> scalar_element -> unit = "mc_np256_inv"
    [@@noalloc]

    external one : out_scalar_element -> unit = "mc_np256_one" [@@noalloc]

    external from_bytes : out_scalar_element -> string -> unit
      = "mc_np256_from_bytes"
    [@@noalloc]

    external to_bytes : bytes -> scalar_element -> unit = "mc_np256_to_bytes"
    [@@noalloc]

    external from_montgomery : out_scalar_element -> scalar_element -> unit
      = "mc_np256_from_montgomery"
    [@@noalloc]

    external to_montgomery : out_scalar_element -> scalar_element -> unit
      = "mc_np256_to_montgomery"
    [@@noalloc]
  end

  module Fe = Make_field_element (Params) (Foreign)
  module P = Make_point (Params) (Foreign) (Fe)
  module S = Make_scalar (Params) (P)
  module Dh = Make_dh (Params) (P) (S)
  module Fn = Make_scalar_element (Params) (Foreign_n)
  module Dsa = Make_dsa (Params) (Fn) (P) (S) (Digestif.SHA256)
end

module P384 : Dh_dsa = struct
  module Params = struct
    let a =
      "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFC"

    let b =
      "\xB3\x31\x2F\xA7\xE2\x3E\xE7\xE4\x98\x8E\x05\x6B\xE3\xF8\x2D\x19\x18\x1D\x9C\x6E\xFE\x81\x41\x12\x03\x14\x08\x8F\x50\x13\x87\x5A\xC6\x56\x39\x8D\x8A\x2E\xD1\x9D\x2A\x85\xC8\xED\xD3\xEC\x2A\xEF"

    let g_x =
      "\xAA\x87\xCA\x22\xBE\x8B\x05\x37\x8E\xB1\xC7\x1E\xF3\x20\xAD\x74\x6E\x1D\x3B\x62\x8B\xA7\x9B\x98\x59\xF7\x41\xE0\x82\x54\x2A\x38\x55\x02\xF2\x5D\xBF\x55\x29\x6C\x3A\x54\x5E\x38\x72\x76\x0A\xB7"

    let g_y =
      "\x36\x17\xde\x4a\x96\x26\x2c\x6f\x5d\x9e\x98\xbf\x92\x92\xdc\x29\xf8\xf4\x1d\xbd\x28\x9a\x14\x7c\xe9\xda\x31\x13\xb5\xf0\xb8\xc0\x0a\x60\xb1\xce\x1d\x7e\x81\x9d\x7a\x43\x1d\x7c\x90\xea\x0e\x5f"

    let p =
      "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF"

    let n =
      "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC7\x63\x4D\x81\xF4\x37\x2D\xDF\x58\x1A\x0D\xB2\x48\xB0\xA7\x7A\xEC\xEC\x19\x6A\xCC\xC5\x29\x73"

    let pident =
      "\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBF\xFF\xFF\xFF\xC0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"
    (* (Params.p + 1) / 4*)

    let byte_length = 48
    let bit_length = 384
    let fe_length = 48
    let first_byte_bits = None
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit
      = "mc_p384_mul"
    [@@noalloc]

    external sub : out_field_element -> field_element -> field_element -> unit
      = "mc_p384_sub"
    [@@noalloc]

    external add : out_field_element -> field_element -> field_element -> unit
      = "mc_p384_add"
    [@@noalloc]

    external to_montgomery : out_field_element -> field_element -> unit
      = "mc_p384_to_montgomery"
    [@@noalloc]

    external from_octets : out_field_element -> string -> unit
      = "mc_p384_from_bytes"
    [@@noalloc]

    external set_one : out_field_element -> unit = "mc_p384_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_p384_nz" [@@noalloc]

    external sqr : out_field_element -> field_element -> unit = "mc_p384_sqr"
    [@@noalloc]

    external from_montgomery : out_field_element -> field_element -> unit
      = "mc_p384_from_montgomery"
    [@@noalloc]

    external to_octets : bytes -> field_element -> unit = "mc_p384_to_bytes"
    [@@noalloc]

    external inv : out_field_element -> field_element -> unit = "mc_p384_inv"
    [@@noalloc]

    external select_c :
      out_field_element -> bool -> field_element -> field_element -> unit
      = "mc_p384_select"
    [@@noalloc]

    external scalar_mult_c : out_point -> string -> point -> unit
      = "mc_p384_scalar_mult"
    [@@noalloc]

    external scalar_mult_add_c : out_point -> string -> string -> point -> unit
      = "mc_p384_scalar_mult_add"
    [@@noalloc]

    external scalar_mult_base_c : out_point -> string -> unit
      = "mc_p384_scalar_mult_base"
    [@@noalloc]
  end

  module Foreign_n = struct
    external mul :
      out_scalar_element -> scalar_element -> scalar_element -> unit
      = "mc_np384_mul"
    [@@noalloc]

    external add :
      out_scalar_element -> scalar_element -> scalar_element -> unit
      = "mc_np384_add"
    [@@noalloc]

    external inv : out_scalar_element -> scalar_element -> unit = "mc_np384_inv"
    [@@noalloc]

    external one : out_scalar_element -> unit = "mc_np384_one" [@@noalloc]

    external from_bytes : out_scalar_element -> string -> unit
      = "mc_np384_from_bytes"
    [@@noalloc]

    external to_bytes : bytes -> scalar_element -> unit = "mc_np384_to_bytes"
    [@@noalloc]

    external from_montgomery : out_scalar_element -> scalar_element -> unit
      = "mc_np384_from_montgomery"
    [@@noalloc]

    external to_montgomery : out_scalar_element -> scalar_element -> unit
      = "mc_np384_to_montgomery"
    [@@noalloc]
  end

  module Fe = Make_field_element (Params) (Foreign)
  module P = Make_point (Params) (Foreign) (Fe)
  module S = Make_scalar (Params) (P)
  module Dh = Make_dh (Params) (P) (S)
  module Fn = Make_scalar_element (Params) (Foreign_n)
  module Dsa = Make_dsa (Params) (Fn) (P) (S) (Digestif.SHA384)
end

module P521 : Dh_dsa = struct
  module Params = struct
    let a =
      "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"

    let b =
      "\x00\x51\x95\x3E\xB9\x61\x8E\x1C\x9A\x1F\x92\x9A\x21\xA0\xB6\x85\x40\xEE\xA2\xDA\x72\x5B\x99\xB3\x15\xF3\xB8\xB4\x89\x91\x8E\xF1\x09\xE1\x56\x19\x39\x51\xEC\x7E\x93\x7B\x16\x52\xC0\xBD\x3B\xB1\xBF\x07\x35\x73\xDF\x88\x3D\x2C\x34\xF1\xEF\x45\x1F\xD4\x6B\x50\x3F\x00"

    let g_x =
      "\x00\xC6\x85\x8E\x06\xB7\x04\x04\xE9\xCD\x9E\x3E\xCB\x66\x23\x95\xB4\x42\x9C\x64\x81\x39\x05\x3F\xB5\x21\xF8\x28\xAF\x60\x6B\x4D\x3D\xBA\xA1\x4B\x5E\x77\xEF\xE7\x59\x28\xFE\x1D\xC1\x27\xA2\xFF\xA8\xDE\x33\x48\xB3\xC1\x85\x6A\x42\x9B\xF9\x7E\x7E\x31\xC2\xE5\xBD\x66"

    let g_y =
      "\x01\x18\x39\x29\x6a\x78\x9a\x3b\xc0\x04\x5c\x8a\x5f\xb4\x2c\x7d\x1b\xd9\x98\xf5\x44\x49\x57\x9b\x44\x68\x17\xaf\xbd\x17\x27\x3e\x66\x2c\x97\xee\x72\x99\x5e\xf4\x26\x40\xc5\x50\xb9\x01\x3f\xad\x07\x61\x35\x3c\x70\x86\xa2\x72\xc2\x40\x88\xbe\x94\x76\x9f\xd1\x66\x50"

    let p =
      "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

    let n =
      "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFA\x51\x86\x87\x83\xBF\x2F\x96\x6B\x7F\xCC\x01\x48\xF7\x09\xA5\xD0\x3B\xB5\xC9\xB8\x89\x9C\x47\xAE\xBB\x6F\xB7\x1E\x91\x38\x64\x09"

    let pident =
      "\x01\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

    let byte_length = 66
    let bit_length = 521

    let fe_length =
      if Sys.word_size == 64 then 72
      else 68 (* TODO: is this congruent with C code? *)

    let first_byte_bits = Some 0x01
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit
      = "mc_p521_mul"
    [@@noalloc]

    external sub : out_field_element -> field_element -> field_element -> unit
      = "mc_p521_sub"
    [@@noalloc]

    external add : out_field_element -> field_element -> field_element -> unit
      = "mc_p521_add"
    [@@noalloc]

    external from_octets : out_field_element -> string -> unit
      = "mc_p521_from_bytes"
    [@@noalloc]

    external set_one : out_field_element -> unit = "mc_p521_set_one" [@@noalloc]

    external sqr : out_field_element -> field_element -> unit = "mc_p521_sqr"
    [@@noalloc]

    external to_octets : bytes -> field_element -> unit = "mc_p521_to_bytes"
    [@@noalloc]

    external inv : out_field_element -> field_element -> unit = "mc_p521_inv"
    [@@noalloc]

    external select_c :
      out_field_element -> bool -> field_element -> field_element -> unit
      = "mc_p521_select"
    [@@noalloc]

    external scalar_mult_base_c : out_point -> string -> unit
      = "mc_p521_scalar_mult_base"
    [@@noalloc]

    external scalar_mult_c : out_point -> string -> point -> unit
      = "mc_p521_scalar_mult"
    [@@noalloc]

    external scalar_mult_add_c : out_point -> string -> string -> point -> unit
      = "mc_p521_scalar_mult_add"
    [@@noalloc]

    let nz =
      let zero = Bytes.make Params.byte_length '\000' in
      fun x ->
        let tmp = Bytes.create Params.byte_length in
        to_octets tmp x;
        not (Bytes.equal tmp zero)
  end

  module Foreign_n = struct
    external mul :
      out_scalar_element -> scalar_element -> scalar_element -> unit
      = "mc_np521_mul"
    [@@noalloc]

    external add :
      out_scalar_element -> scalar_element -> scalar_element -> unit
      = "mc_np521_add"
    [@@noalloc]

    external inv : out_scalar_element -> scalar_element -> unit = "mc_np521_inv"
    [@@noalloc]

    external one : out_scalar_element -> unit = "mc_np521_one" [@@noalloc]

    external from_bytes : out_scalar_element -> string -> unit
      = "mc_np521_from_bytes"
    [@@noalloc]

    external to_bytes : bytes -> scalar_element -> unit = "mc_np521_to_bytes"
    [@@noalloc]

    external from_montgomery : out_scalar_element -> scalar_element -> unit
      = "mc_np521_from_montgomery"
    [@@noalloc]

    external to_montgomery : out_scalar_element -> scalar_element -> unit
      = "mc_np521_to_montgomery"
    [@@noalloc]
  end

  module Fe = Make_field_element_usol (Params) (Foreign)
  module P = Make_point (Params) (Foreign) (Fe)
  module S = Make_scalar (Params) (P)
  module Dh = Make_dh (Params) (P) (S)
  module Fn = Make_scalar_element (Params) (Foreign_n)
  module Dsa = Make_dsa (Params) (Fn) (P) (S) (Digestif.SHA512)
end
