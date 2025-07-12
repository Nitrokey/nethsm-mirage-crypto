open Nethsm_crypto

module type Bip340 = sig
  type priv
  type pub
  val byte_length : int
  val bit_length : int
  val priv_of_octets : string -> (priv, error) result
  val priv_to_octets : priv -> string
  val pub_of_octets : string -> (pub, error) result
  val pub_to_octets : pub -> string
  val pub_of_priv : priv -> pub
  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  val sign : key:priv -> ?aux_rand:string -> string -> string * string
  val verify : key:pub -> string * string -> string -> bool
end

module type P256k1 = sig
  module Dh : Dh
  module Dsa : Dsa
  module Bip340 : Bip340
end

module type Scalar_element_bip340 = sig
  include Scalar_element
  val opp : scalar_element -> scalar_element
end

module type Foreign_n_bip340 = sig
  include Foreign_n
  val opp : out_scalar_element -> scalar_element -> unit
end

module Make_scalar_element_bip340 (P : Parameters)(F : Foreign_n_bip340) : Scalar_element_bip340 = struct
  include Make_scalar_element(P)(F)

  let opp a =
    let tmp = create () in
    F.opp tmp a;
    of_se_out tmp

end

module Make_bip340 (Param : Parameters) (F : Scalar_element_bip340) (P : Point) (S : Scalar) : Bip340 = struct
  module H = Digestif.SHA256

  type priv = scalar
  type pub = Pub of string (* 32-byte X coordinate *)
  let byte_length = Param.byte_length
  let bit_length = Param.bit_length

  let priv_of_octets = S.of_octets
  let priv_to_octets = S.to_octets

  let rev_string buf =
    let len = String.length buf in
    let res = Bytes.create len in
    for i = 0 to len - 1 do
      Bytes.set res (len - 1 - i) (String.get buf i)
    done ;
    Bytes.unsafe_to_string res

  let xor_scalar (s1 : string) (s2 : string) : string =
    let l = Param.byte_length in
    assert (String.length s1 = l);
    assert (String.length s2 = l);
    let result = Bytes.create l in
    (* Process 8 bytes at a time using Int64 operations *)
    for i = 0 to (l/8)-1 do
      let offset = i * 8 in
      (* Extract 8-byte chunks as Int64 values *)
      let w1 = String.get_int64_ne s1 offset in
      let w2 = String.get_int64_ne s2 offset in
      (* XOR the 64-bit words *)
      let xor_result = Int64.logxor w1 w2 in
      (* Store result back *)
      Bytes.set_int64_ne result offset xor_result
    done;
    Bytes.unsafe_to_string result

  (* Tagged hash function *)
  let tagged_hash tag =
    let tag_hash = H.digest_string tag |> H.to_raw_string in
    let ctx = H.feed_string H.empty (tag_hash ^ tag_hash) in
    fun msg ->
      H.feed_string ctx msg |> H.get |> H.to_raw_string

  let tagged_hash_aux = tagged_hash "BIP0340/aux"
  let tagged_hash_nonce = tagged_hash "BIP0340/nonce"
  let tagged_hash_challenge = tagged_hash "BIP0340/challenge"

  (* Check if a point has even Y coordinate *)
  let has_even_y point =
    match P.to_affine point with
    | None -> false (* Point at infinity *)
    | Some (_, y) ->
      (* Check if first byte is even in little-endian *)
      (Char.code (String.get y 0) land 1) = 0

  (* Extract X coordinate from a point *)
  let x_of_point =
    let zero = String.make Param.byte_length '\000' in
    fun point ->
      match P.to_affine point with
      | None -> zero (* Return zero bytes for infinity *)
      | Some (x, _) -> rev_string x (* Reverse to get big-endian format *)

  (* Derive public key from private key *)
  let pub_of_priv priv =
    (* Calculate P = d*G *)
    let point = P.scalar_mult_base priv in

    (* Return X coordinate *)
    Pub (x_of_point point)

  (* Generate key pair *)
  let generate ?g () =
    let d =
      let rec go () =
        match S.of_octets (Mirage_crypto_rng.generate ?g Param.byte_length) with
        | Ok x -> x
        | Error _ -> go ()
      in
      go ()
    in
    let pubkey = pub_of_priv d in
    (d, pubkey)

  (* Public key from octets *)
  let pub_of_octets bytes =
    if String.length bytes != Param.byte_length then
      Error `Invalid_length
    else
      Ok (Pub bytes)

  (* Public key to octets *)
  let pub_to_octets (Pub pub) = pub

  (* Sign a message *)
  let sign ~key ?aux_rand msg =
    (* Calculate P = key*G *)
    let p_point = P.scalar_mult_base key in
    (* Determine if d needs to be negated based on Y coordinate *)
    let d =
      let fe = F.from_be_octets (S.to_octets key) in
      if has_even_y p_point then fe else F.opp fe
    in
    (* Generate aux_rand if not provided *)
    let a = match aux_rand with
      | Some a -> a
      | None -> Mirage_crypto_rng.generate Param.byte_length
    in
    (* Compute t = bytes(d) XOR hash_aux(a) *)
    let d_be = F.from_montgomery d |> F.to_be_octets in
    let t = xor_scalar d_be (tagged_hash_aux a) in
    (* Compute rand *)
    let p_be = x_of_point p_point in
    let nonce_input = t ^ p_be ^ msg in
    let rand_be = tagged_hash_nonce nonce_input in
    (* Convert to field element, from_be_octets implies (mod n) because of to_montgomery *)
    let k' = F.from_be_octets rand_be in
    (* Convert k' to scalar, fails if k' == 0 *)
    let k_sc' = Result.get_ok (S.of_octets (F.to_be_octets (F.from_montgomery k'))) in
    (* Compute R = k'*G *)
    let r_point = P.scalar_mult_base k_sc' in
    (* Determine k based on Y coordinate of R *)
    let k =
      if has_even_y r_point then k'
      else F.opp k'
    in
    (* Extract r from R *)
    let r_be = x_of_point r_point in
    (* Compute challenge e *)
    let challenge_input = r_be ^ p_be ^ msg in
    let e_be = tagged_hash_challenge challenge_input in
    (* Convert to field element, from_be_octets implies (mod n) because of to_montgomery *)
    let e = F.from_be_octets e_be in
    (* Compute e*d *)
    let ed = F.mul e d in
    (* s = k + e*d *)
    let s = F.add k ed in
    let s_be = F.from_montgomery s |> F.to_be_octets in
    (r_be, s_be)

  (* Verify a signature *)
  let verify ~key (r, s) msg =
    if String.length r != byte_length || String.length s != byte_length then false else
    match S.of_octets s with Error _ -> false | Ok s_sc ->
    (* Compute challenge e *)
    let (Pub pk_be) = key in
    let challenge_input = r ^ pk_be ^ msg in
    (* *)
    let e_be = tagged_hash_challenge challenge_input in
    (* Convert to field element, from_be_octets implies (mod n) because of to_montgomery *)
    let e = F.from_be_octets e_be in
    (* Create a compressed point (0x02 prefix) *)
    let compressed = "\x02" ^ pk_be in
    (* Lift x to point P *)
    match P.of_octets compressed with
    | Error _ -> false
    | Ok p_point ->
    (* negate e if y(P) is even *)
    let e = if has_even_y p_point
      then F.opp e
      else e
    in
    match F.from_montgomery e |> F.to_be_octets |> S.of_octets with
    | Error _ -> false
    | Ok e_sc ->
    (* Compute R = s*G + e*P *)
    let r_point = P.scalar_mult_add s_sc e_sc p_point in
    let r' = x_of_point r_point in
    (* Check R is not infinity *)
    not (P.is_infinity r_point) &&
    (* Check appropriate Y coordinate parity *)
    has_even_y r_point &&
    (* Check x(R) = r *)
    r' = r
end

module P256k1 : P256k1  = struct
  module Params = struct
    let a = ""
    let b = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07"
    let g_x = "\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98"
    let g_y = "\x48\x3A\xDA\x77\x26\xA3\xC4\x65\x5D\xA4\xFB\xFC\x0E\x11\x08\xA8\xFD\x17\xB4\x48\xA6\x85\x54\x19\x9C\x47\xD0\x8F\xFB\x10\xD4\xB8"
    let p = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F"
    let n = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41"
    let pident = "\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBF\xFF\xFF\x0C" (* (Params.p + 1) / 4*)
    let byte_length = 32
    let bit_length = 256
    let fe_length = 32
    let first_byte_bits = None
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_secp256k1_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_secp256k1_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_secp256k1_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_secp256k1_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_secp256k1_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_secp256k1_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_secp256k1_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_secp256k1_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_secp256k1_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_secp256k1_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_secp256k1_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_secp256k1_select" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_secp256k1_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_secp256k1_scalar_mult_add" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_secp256k1_scalar_mult_base" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nsecp256k1_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nsecp256k1_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_inv" [@@noalloc]
    external opp : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_opp" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nsecp256k1_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nsecp256k1_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nsecp256k1_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point(Params)(Foreign)(Fe)
  module S = Make_scalar(Params)(P)
  module Dh = Make_dh(Params)(P)(S)
  module Fn = Make_scalar_element_bip340(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(S)(Digestif.SHA256)
  module Bip340 = Make_bip340(Params)(Fn)(P)(S)
end
