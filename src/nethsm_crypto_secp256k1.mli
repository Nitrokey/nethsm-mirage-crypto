open Nethsm_crypto

(** BIP-340 Schnorr signature *)
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

(** The SECP256K1 curve. *)
module P256k1 : sig
  module Dh : Dh
  module Dsa : Dsa
  module Bip340 : Bip340
end
