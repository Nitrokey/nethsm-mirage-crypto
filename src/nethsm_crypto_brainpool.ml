open Nethsm_crypto

module Twist (P : Parameters_twisted) (Fe : Field_element) : Transform = struct
  let z = Fe.from_be_octets P.z
  let z2 = Fe.sqr z
  let z3 = Fe.mul z2 z
  let z_inv = Fe.inv z
  let z_inv2 = Fe.sqr z_inv
  let z_inv3 = Fe.mul z_inv2 z_inv

  let in_x = Fe.mul z2
  let in_y = Fe.mul z3
  let out_x = Fe.mul z_inv2
  let out_y = Fe.mul z_inv3
end

module Make_point_twisted
  (P : Parameters_twisted) (F : Foreign_point) (Fe : Field_element)
  : Point = Make_point_base(P)(F)(Fe)(Twist(P)(Fe))

module BrainpoolP256 : Dh_dsa  = struct
  (* These are the parameters of the twisted curve variant brainpoolP256t1,
  which allows use of optimized algorithms for a=-3. For the support of the
  regular curve brainpoolP256r1 the coordinates are mapped from regular to
  twisted representation and vice versa. *)
  module Params = struct
    let a = "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x74"
    let b = "\x66\x2C\x61\xC4\x30\xD8\x4E\xA4\xFE\x66\xA7\x73\x3D\x0B\x76\xB7\xBF\x93\xEB\xC4\xAF\x2F\x49\x25\x6A\xE5\x81\x01\xFE\xE9\x2B\x04"
    let g_x = "\xA3\xE8\xEB\x3C\xC1\xCF\xE7\xB7\x73\x22\x13\xB2\x3A\x65\x61\x49\xAF\xA1\x42\xC4\x7A\xAF\xBC\x2B\x79\xA1\x91\x56\x2E\x13\x05\xF4"
    let g_y = "\x2D\x99\x6C\x82\x34\x39\xC5\x6D\x7F\x7B\x22\xE1\x46\x44\x41\x7E\x69\xBC\xB6\xDE\x39\xD0\x27\x00\x1D\xAB\xE8\xF3\x5B\x25\xC9\xBE"
    let p = "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x77"
    let n = "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x71\x8C\x39\x7A\xA3\xB5\x61\xA6\xF7\x90\x1E\x0E\x82\x97\x48\x56\xA7"
    let pident = "\x2A\x7E\xD5\xF6\xE8\x7B\xAA\x6F\x0F\x99\x82\xA4\x27\x60\xE3\x5C\x9B\x8E\xFD\x88\xF5\x49\x88\x0A\x08\x04\xD2\x07\x47\xDB\x94\xDE" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 32
    let bit_length = 256
    let fe_length = 32
    let first_byte_bits = None
    let z = "\x3E\x2D\x4B\xD9\x59\x7B\x58\x63\x9A\xE7\xAA\x66\x9C\xAB\x98\x37\xCF\x5C\xF2\x0A\x2C\x85\x2D\x10\xF6\x55\x66\x8D\xFC\x15\x0E\xF0"
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp256_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp256_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp256_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp256_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_brainpoolp256_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_brainpoolp256_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_brainpoolp256_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_brainpoolp256_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp256_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_brainpoolp256_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_brainpoolp256_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_brainpoolp256_select" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_brainpoolp256t1_scalar_mult_base" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_brainpoolp256t1_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_brainpoolp256t1_scalar_mult_add" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nbrainpoolp256_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nbrainpoolp256_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nbrainpoolp256_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point_twisted(Params)(Foreign)(Fe)
  module S = Make_scalar(Params)(P)
  module Dh = Make_dh(Params)(P)(S)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(S)(Digestif.SHA256)
end

module BrainpoolP384 : Dh_dsa  = struct
  (* These are the parameters of the twisted curve variant *)
  module Params = struct
    let a = "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB4\x12\xB1\xDA\x19\x7F\xB7\x11\x23\xAC\xD3\xA7\x29\x90\x1D\x1A\x71\x87\x47\x00\x13\x31\x07\xEC\x50"
    let b = "\x7F\x51\x9E\xAD\xA7\xBD\xA8\x1B\xD8\x26\xDB\xA6\x47\x91\x0F\x8C\x4B\x93\x46\xED\x8C\xCD\xC6\x4E\x4B\x1A\xBD\x11\x75\x6D\xCE\x1D\x20\x74\xAA\x26\x3B\x88\x80\x5C\xED\x70\x35\x5A\x33\xB4\x71\xEE"
    let g_x = "\x18\xDE\x98\xB0\x2D\xB9\xA3\x06\xF2\xAF\xCD\x72\x35\xF7\x2A\x81\x9B\x80\xAB\x12\xEB\xD6\x53\x17\x24\x76\xFE\xCD\x46\x2A\xAB\xFF\xC4\xFF\x19\x1B\x94\x6A\x5F\x54\xD8\xD0\xAA\x2F\x41\x88\x08\xCC"
    let g_y = "\x25\xAB\x05\x69\x62\xD3\x06\x51\xA1\x14\xAF\xD2\x75\x5A\xD3\x36\x74\x7F\x93\x47\x5B\x7A\x1F\xCA\x3B\x88\xF2\xB6\xA2\x08\xCC\xFE\x46\x94\x08\x58\x4D\xC2\xB2\x91\x26\x75\xBF\x5B\x9E\x58\x29\x28"
    let p = "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB4\x12\xB1\xDA\x19\x7F\xB7\x11\x23\xAC\xD3\xA7\x29\x90\x1D\x1A\x71\x87\x47\x00\x13\x31\x07\xEC\x53"
    let n = "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB3\x1F\x16\x6E\x6C\xAC\x04\x25\xA7\xCF\x3A\xB6\xAF\x6B\x7F\xC3\x10\x3B\x88\x32\x02\xE9\x04\x65\x65"
    let pident = "\x23\x2E\x47\xA0\xA8\xCE\x1B\x4A\x03\xD7\x5B\xDF\x94\x39\x90\x77\xC5\x4B\xDC\x42\x7B\x55\x15\xAD\x04\xAC\x76\x86\x5F\xED\xC4\x48\xEB\x34\xE9\xCA\x64\x07\x46\x9C\x61\xD1\xC0\x04\xCC\x41\xFB\x15" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 48
    let bit_length = 384
    let fe_length = 48
    let first_byte_bits = None
    let z = "\x41\xDF\xE8\xDD\x39\x93\x31\xF7\x16\x6A\x66\x07\x67\x34\xA8\x9C\xD0\xD2\xBC\xDB\x7D\x06\x8E\x44\xE1\xF3\x78\xF4\x1E\xCB\xAE\x97\xD2\xD6\x3D\xBC\x87\xBC\xCD\xDC\xCC\x5D\xA3\x9E\x85\x89\x29\x1C"
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp384_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp384_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp384_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp384_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_brainpoolp384_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_brainpoolp384_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_brainpoolp384_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_brainpoolp384_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp384_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_brainpoolp384_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_brainpoolp384_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_brainpoolp384_select" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_brainpoolp384_scalar_mult_base" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_brainpoolp384_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_brainpoolp384_scalar_mult_add" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nbrainpoolp384_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nbrainpoolp384_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nbrainpoolp384_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point_twisted(Params)(Foreign)(Fe)
  module S = Make_scalar(Params)(P)
  module Dh = Make_dh(Params)(P)(S)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(S)(Digestif.SHA384)
end

module BrainpoolP512 : Dh_dsa  = struct
  (* These are the parameters of the twisted curve variant *)
  module Params = struct
    let a = "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x71\x7D\x4D\x9B\x00\x9B\xC6\x68\x42\xAE\xCD\xA1\x2A\xE6\xA3\x80\xE6\x28\x81\xFF\x2F\x2D\x82\xC6\x85\x28\xAA\x60\x56\x58\x3A\x48\xF0"
    let b = "\x7C\xBB\xBC\xF9\x44\x1C\xFA\xB7\x6E\x18\x90\xE4\x68\x84\xEA\xE3\x21\xF7\x0C\x0B\xCB\x49\x81\x52\x78\x97\x50\x4B\xEC\x3E\x36\xA6\x2B\xCD\xFA\x23\x04\x97\x65\x40\xF6\x45\x00\x85\xF2\xDA\xE1\x45\xC2\x25\x53\xB4\x65\x76\x36\x89\x18\x0E\xA2\x57\x18\x67\x42\x3E"
    let g_x = "\x64\x0E\xCE\x5C\x12\x78\x87\x17\xB9\xC1\xBA\x06\xCB\xC2\xA6\xFE\xBA\x85\x84\x24\x58\xC5\x6D\xDE\x9D\xB1\x75\x8D\x39\xC0\x31\x3D\x82\xBA\x51\x73\x5C\xDB\x3E\xA4\x99\xAA\x77\xA7\xD6\x94\x3A\x64\xF7\xA3\xF2\x5F\xE2\x6F\x06\xB5\x1B\xAA\x26\x96\xFA\x90\x35\xDA"
    let g_y = "\x5B\x53\x4B\xD5\x95\xF5\xAF\x0F\xA2\xC8\x92\x37\x6C\x84\xAC\xE1\xBB\x4E\x30\x19\xB7\x16\x34\xC0\x11\x31\x15\x9C\xAE\x03\xCE\xE9\xD9\x93\x21\x84\xBE\xEF\x21\x6B\xD7\x1D\xF2\xDA\xDF\x86\xA6\x27\x30\x6E\xCF\xF9\x6D\xBB\x8B\xAC\xE1\x98\xB6\x1E\x00\xF8\xB3\x32"
    let p = "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x71\x7D\x4D\x9B\x00\x9B\xC6\x68\x42\xAE\xCD\xA1\x2A\xE6\xA3\x80\xE6\x28\x81\xFF\x2F\x2D\x82\xC6\x85\x28\xAA\x60\x56\x58\x3A\x48\xF3"
    let n = "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x70\x55\x3E\x5C\x41\x4C\xA9\x26\x19\x41\x86\x61\x19\x7F\xAC\x10\x47\x1D\xB1\xD3\x81\x08\x5D\xDA\xDD\xB5\x87\x96\x82\x9C\xA9\x00\x69"
    let pident = "\x2A\xB7\x67\x6E\x36\xFA\x71\x22\xCF\xF5\x39\xAB\x8C\xF2\x7F\x01\xF2\xCC\x23\x6C\xEC\xF2\x74\x83\xB5\x98\xE7\x32\x9C\x0C\xC2\x1C\x5F\x53\x66\xC0\x26\xF1\x9A\x10\xAB\xB3\x68\x4A\xB9\xA8\xE0\x39\x8A\x20\x7F\xCB\xCB\x60\xB1\xA1\x4A\x2A\x98\x15\x96\x0E\x92\x3D" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 64
    let bit_length = 512
    let fe_length = 64
    let first_byte_bits = None
    let z = "\x12\xEE\x58\xE6\x76\x48\x38\xB6\x97\x82\x13\x6F\x0F\x2D\x3B\xA0\x6E\x27\x69\x57\x16\x05\x40\x92\xE6\x0A\x80\xBE\xDB\x21\x2B\x64\xE5\x85\xD9\x0B\xCE\x13\x76\x1F\x85\xC3\xF1\xD2\xA6\x4E\x3B\xE8\xFE\xA2\x22\x0F\x01\xEB\xA5\xEE\xB0\xF3\x5D\xBD\x29\xD9\x22\xAB"
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp512_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp512_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp512_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp512_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_brainpoolp512_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_brainpoolp512_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_brainpoolp512_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_brainpoolp512_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp512_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_brainpoolp512_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_brainpoolp512_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_brainpoolp512_select" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_brainpoolp512_scalar_mult_base" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_brainpoolp512_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_brainpoolp512_scalar_mult_add" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nbrainpoolp512_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nbrainpoolp512_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nbrainpoolp512_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point_twisted(Params)(Foreign)(Fe)
  module S = Make_scalar(Params)(P)
  module Dh = Make_dh(Params)(P)(S)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(S)(Digestif.SHA512)
end
