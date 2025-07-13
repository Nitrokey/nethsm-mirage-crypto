open Nethsm_crypto

module P256 : Dh_dsa
(** The NIST P-256 curve, also known as SECP256R1. *)

module P384 : Dh_dsa
(** The NIST P-384 curve, also known as SECP384R1. *)

module P521 : Dh_dsa
(** The NIST P-521 curve, also known as SECP521R1. *)
