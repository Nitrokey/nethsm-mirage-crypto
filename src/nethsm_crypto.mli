(** {1 Elliptic curve cryptography} *)

(** Nethsm-crypto implements public key cryptography with named elliptic curves.
    Ephemeral key exchanges with {{!Dh}Diffie-Hellman} and
    {{!Dsa}digital signatures (ECDSA)} are implemented. *)

type error =
  [ `Invalid_range
  | `Invalid_format
  | `Invalid_length
  | `Not_on_curve
  | `At_infinity
  | `Low_order ]
(** The type for errors. *)

val pp_error : Format.formatter -> error -> unit
(** Pretty printer for errors *)

exception Message_too_long
(** Raised if the provided message is too long for the curve. *)

(** Diffie-Hellman key exchange. *)
module type Dh = sig
  type secret
  (** Type for private keys. *)

  val secret_of_octets :
    ?compress:bool -> string -> (secret * string, error) result
  (** [secret_of_octets ~compress secret] decodes the provided buffer as
      {!secret}. If [compress] is provided and [true] (defaults to [false]), the
      shared part will be compressed. May result in an error if the buffer had
      an invalid length or was not in bounds. *)

  val secret_to_octets : secret -> string
  (** [secret_to_octets secret] encodes the provided secret into a freshly
      allocated buffer. *)

  val gen_key :
    ?compress:bool -> ?g:Mirage_crypto_rng.g -> unit -> secret * string
  (** [gen_key ~compress ~g ()] generates a private and a public key for
      Ephemeral Diffie-Hellman. If [compress] is provided and [true] (defaults
      to [false]), the shared part will be compressed. The returned key pair
      MUST only be used for a single key exchange.

      The generated private key is checked to be greater than zero and lower
      than the group order meaning the public key cannot be the point at
      inifinity. *)

  val key_exchange : secret -> string -> (string, error) result
  (** [key_exchange secret received_public_key] performs Diffie-Hellman key
      exchange using your secret and the data received from the other party.
      Returns the shared secret or an error if the received data is wrongly
      encoded, doesn't represent a point on the curve or represent the point at
      infinity.

      The shared secret is returned as is i.e. not stripped from leading 0x00
      bytes.

      The public key encoding is described
      {{:http://www.secg.org/sec1-v2.pdf}in SEC 1} from SECG. *)
end

(** Digital signature algorithm. *)
module type Dsa = sig
  type priv
  (** The type for private keys. *)

  type pub
  (** The type for public keys. *)

  val byte_length : int
  (** [byte_length] is the size of a ECDSA signature in bytes. *)

  val bit_length : int
  (** [bit_length] is the number of significant bits in a ECDSA signature *)

  (** {2 Serialisation} *)

  val priv_of_octets : string -> (priv, error) result
  (** [priv_of_octets buf] decodes a private key from the buffer [buf]. If the
      provided data is invalid, an error is returned. *)

  val priv_to_octets : priv -> string
  (** [priv_to_octets p] encode the private key [p] to a buffer. *)

  val pub_of_octets : string -> (pub, error) result
  (** [pub_of_octets buf] decodes a public key from the buffer [buf]. If the
      provided data is invalid, an error is returned. *)

  val pub_to_octets : ?compress:bool -> pub -> string
  (** [pub_to_octets ~compress p] encodes the public key [p] into a buffer. If
      [compress] is provided and [true] (default [false]), the compressed
      representation is returned. *)

  (** {2 Deriving the public key} *)

  val pub_of_priv : priv -> pub
  (** [pub_of_priv p] extracts the public key from the private key [p]. *)

  (** {2 Key generation} *)

  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  (** [generate ~g ()] generates a key pair. *)

  (** {2 Cryptographic operations} *)

  val sign : key:priv -> ?k:string -> string -> string * string
  (** [sign ~key ~k digest] signs the message [digest] using the private [key].
      The [digest] is not processed further - it should be the hash of the
      message to sign. If [k] is not provided, it is computed using the
      deterministic construction from RFC 6979. The result is a pair of [r] and
      [s].

      Warning: there {{:https://www.hertzbleed.com/2h2b.pdf}are}
      {{:https://www.hertzbleed.com/hertzbleed.pdf}attacks} that recover the
      private key from a power and timing analysis of the RFC 6979 computation
      of [k] - thus it is advised to provide a good nonce ([k]) explicitly,
      which is independent of key and digest.

      @raise Invalid_argument if [k] is not suitable or not in range.
      @raise Message_too_long if the bit size of [msg] exceeds the curve. *)

  val verify : key:pub -> string * string -> string -> bool
  (** [verify ~key (r, s) digest] verifies the signature [r, s] on the message
      [digest] with the public [key]. The return value is [true] if verification
      was successful, [false] otherwise. If the message has more bits than the
      group order, the result is false. *)

  (** [K_gen] can be instantiated over a hashing module to obtain an RFC6979
      compliant [k]-generator for that hash. *)
  module K_gen (H : Digestif.S) : sig
    val generate : key:priv -> string -> string
    (** [generate ~key digest] deterministically takes the given private key and
        message digest to a [k] suitable for seeding the signing process. *)
  end
end

(** Elliptic curve with Diffie-Hellman and DSA. *)
module type Dh_dsa = sig
  module Dh : Dh
  (** Diffie-Hellman key exchange. *)

  module Dsa : Dsa
  (** Digital signature algorithm. *)
end

(** {1 Internal interfaces} *)

type field_element = Fe of string [@@unboxed]
type out_field_element = Fe_out of bytes [@@unboxed]
type scalar_element = Se of string [@@unboxed]
type out_scalar_element = Se_out of bytes [@@unboxed]
type point = Point of string [@@unboxed]
type out_point = Point_out of bytes [@@unboxed]
type scalar = Scalar of string

module type Parameters = sig
  val a : string
  val b : string
  val g_x : string
  val g_y : string
  val p : string
  val n : string
  val pident : string
  val byte_length : int
  val bit_length : int
  val fe_length : int
  val first_byte_bits : int option
end

module type Parameters_twisted = sig
  include Parameters

  val z : string
end

module type Foreign_field = sig
  val mul : out_field_element -> field_element -> field_element -> unit
  val sub : out_field_element -> field_element -> field_element -> unit
  val add : out_field_element -> field_element -> field_element -> unit
  val from_octets : out_field_element -> string -> unit
  val set_one : out_field_element -> unit
  val nz : field_element -> bool
  val sqr : out_field_element -> field_element -> unit
  val to_octets : bytes -> field_element -> unit
  val inv : out_field_element -> field_element -> unit

  val select_c :
    out_field_element -> bool -> field_element -> field_element -> unit
end

module type Foreign_mont = sig
  include Foreign_field

  val to_montgomery : out_field_element -> field_element -> unit
  val from_montgomery : out_field_element -> field_element -> unit
end

module type Foreign_point = sig
  val scalar_mult_base_c : out_point -> string -> unit
  val scalar_mult_c : out_point -> string -> point -> unit
  val scalar_mult_add_c : out_point -> string -> string -> point -> unit
end

module type Field_element = sig
  val create : unit -> out_field_element
  val mul : field_element -> field_element -> field_element
  val sub : field_element -> field_element -> field_element
  val add : field_element -> field_element -> field_element
  val from_montgomery : field_element -> field_element
  val zero : field_element
  val one : field_element
  val nz : field_element -> bool
  val sqr : field_element -> field_element
  val inv : field_element -> field_element

  val select :
    bool -> then_:field_element -> else_:field_element -> field_element

  val from_be_octets : string -> field_element
  val to_octets : field_element -> string
end

module Make_field_element : functor (P : Parameters) (F : Foreign_mont) ->
  Field_element

module Make_field_element_usol : functor (P : Parameters) (F : Foreign_field) ->
  Field_element

module type Point = sig
  val is_infinity : point -> bool
  val of_octets : string -> (point, error) result
  val to_octets : compress:bool -> point -> string
  val to_affine : point -> (string * string) option
  val to_affine_raw : point -> (field_element * field_element) option
  val x_of_finite_point : point -> string
  val scalar_mult : scalar -> point -> point
  val scalar_mult_add : scalar -> scalar -> point -> point
  val scalar_mult_base : scalar -> point
end

module Make_point (P : Parameters) (F : Foreign_point) (Fe : Field_element) :
  Point

module Make_point_twisted
    (P : Parameters_twisted)
    (F : Foreign_point)
    (Fe : Field_element) : Point

module type Scalar = sig
  val not_zero : string -> bool
  val is_in_range : string -> bool
  val of_octets : string -> (scalar, error) result
  val to_octets : scalar -> string
end

module Make_scalar (Param : Parameters) (P : Point) : Scalar
module Make_dh (Param : Parameters) (P : Point) (S : Scalar) : Dh

module type Foreign_n = sig
  val mul : out_scalar_element -> scalar_element -> scalar_element -> unit
  val add : out_scalar_element -> scalar_element -> scalar_element -> unit
  val inv : out_scalar_element -> scalar_element -> unit
  val one : out_scalar_element -> unit
  val from_bytes : out_scalar_element -> string -> unit
  val to_bytes : bytes -> scalar_element -> unit
  val from_montgomery : out_scalar_element -> scalar_element -> unit
  val to_montgomery : out_scalar_element -> scalar_element -> unit
end

module type Scalar_element = sig
  val from_octets_raw : string -> scalar_element
  val from_be_octets : string -> scalar_element
  val to_be_octets : scalar_element -> string
  val mul : scalar_element -> scalar_element -> scalar_element
  val add : scalar_element -> scalar_element -> scalar_element
  val inv : scalar_element -> scalar_element
  val one : scalar_element
  val from_montgomery : scalar_element -> scalar_element
  val to_montgomery : scalar_element -> scalar_element
end

module Make_scalar_element : functor (P : Parameters) (F : Foreign_n) -> sig
  val of_se_out : out_scalar_element -> scalar_element
  val create : unit -> out_scalar_element
  val create_octets : unit -> bytes
  val from_octets_raw : string -> scalar_element
  val from_be_octets : string -> scalar_element
  val to_be_octets : scalar_element -> string
  val mul : scalar_element -> scalar_element -> scalar_element
  val add : scalar_element -> scalar_element -> scalar_element
  val inv : scalar_element -> scalar_element
  val one : scalar_element
  val from_montgomery : scalar_element -> scalar_element
  val to_montgomery : scalar_element -> scalar_element
end

module Make_dsa : functor
  (Param : Parameters)
  (F : Scalar_element)
  (P : Point)
  (S : Scalar)
  (H : Digestif.S)
  -> sig
  type priv = scalar

  val byte_length : int
  val bit_length : int
  val priv_of_octets : string -> (scalar, error) result
  val priv_to_octets : scalar -> string
  val padded : string -> string

  module K_gen : functor (H : Digestif.S) -> sig
    val drbg : Mirage_crypto_rng.Hmac_drbg(H).g Mirage_crypto_rng.generator
    val g : key:priv -> string -> Mirage_crypto_rng.g
    val bits2int : bytes -> string
    val gen : Mirage_crypto_rng.g -> string
    val generate : key:priv -> string -> string
  end

  module K_gen_default : sig
    val drbg : Mirage_crypto_rng.Hmac_drbg(H).g Mirage_crypto_rng.generator
    val g : key:priv -> string -> Mirage_crypto_rng.g
    val bits2int : bytes -> string
    val gen : Mirage_crypto_rng.g -> string
    val generate : key:priv -> string -> string
  end

  type pub = point

  val pub_of_octets : string -> (point, error) result
  val pub_to_octets : ?compress:bool -> point -> string
  val generate : ?g:Mirage_crypto_rng.g -> unit -> scalar * point
  val x_of_finite_point_mod_n : point -> string option
  val sign : key:scalar -> ?k:string -> string -> string * string
  val pub_of_priv : scalar -> point
  val verify : key:point -> string * string -> string -> bool
end
