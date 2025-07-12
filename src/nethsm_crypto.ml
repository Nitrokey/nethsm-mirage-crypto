type error = [
  | `Invalid_format
  | `Invalid_length
  | `Invalid_range
  | `Not_on_curve
  | `At_infinity
  | `Low_order
]

let error_to_string = function
  | `Invalid_format -> "invalid format"
  | `Not_on_curve -> "point is not on curve"
  | `At_infinity -> "point is at infinity"
  | `Invalid_length -> "invalid length"
  | `Invalid_range -> "invalid range"
  | `Low_order -> "low order"

let pp_error fmt e =
  Format.fprintf fmt "Cannot parse point: %s" (error_to_string e)

let rev_string buf =
  let len = String.length buf in
  let res = Bytes.create len in
  for i = 0 to len - 1 do
    Bytes.set res (len - 1 - i) (String.get buf i)
  done ;
  Bytes.unsafe_to_string res

exception Message_too_long

let bit_at buf i =
  let byte_num = i / 8 in
  let bit_num = i mod 8 in
  let byte = String.get_uint8 buf byte_num in
  byte land (1 lsl bit_num) <> 0

module type Dh = sig
  type secret
  val secret_of_octets : ?compress:bool -> string ->
    (secret * string, error) result
  val secret_to_octets : secret -> string
  val gen_key : ?compress:bool -> ?g:Mirage_crypto_rng.g -> unit ->
    secret * string
  val key_exchange : secret -> string -> (string, error) result
end

module type Dsa = sig
  type priv
  type pub
  val byte_length : int
  val bit_length : int
  val priv_of_octets : string -> (priv, error) result
  val priv_to_octets : priv -> string
  val pub_of_octets : string -> (pub, error) result
  val pub_to_octets : ?compress:bool -> pub -> string
  val pub_of_priv : priv -> pub
  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  val sign : key:priv -> ?k:string -> string -> string * string
  val verify : key:pub -> string * string -> string -> bool
  module K_gen (H : Digestif.S) : sig
    val generate : key:priv -> string -> string
  end
end

module type Dh_dsa = sig
  module Dh : Dh
  module Dsa : Dsa
end

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
  val pident: string
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
  val select_c : out_field_element -> bool -> field_element -> field_element -> unit
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
  val select : bool -> then_:field_element -> else_:field_element -> field_element
  val from_be_octets : string -> field_element
  val to_octets : field_element -> string
end

module Make_field_element_base (P : Parameters) (F : Foreign_field) = struct
  let of_fe_out (Fe_out b) = Fe (Bytes.unsafe_to_string b)

  let create () = Fe_out (Bytes.create P.fe_length)

  let mul a b =
    let tmp = create () in
    F.mul tmp a b;
    of_fe_out tmp

  let sub a b =
    let tmp = create () in
    F.sub tmp a b;
    of_fe_out tmp

  let add a b =
    let tmp = create () in
    F.add tmp a b;
    of_fe_out tmp

  let zero = Fe (String.make P.fe_length '\000')

  let one =
    let fe = create () in
    F.set_one fe;
    of_fe_out fe

  let nz a = F.nz a

  let sqr a =
    let tmp = create () in
    F.sqr tmp a;
    of_fe_out tmp

  let inv a =
    let tmp = create () in
    F.inv tmp a;
    of_fe_out tmp

  let select bit ~then_ ~else_ =
    let tmp = create () in
    F.select_c tmp bit then_ else_;
    of_fe_out tmp

  let create_octets () =
    Bytes.create P.byte_length

  let to_octets fe =
    let tmp = create_octets () in
    F.to_octets tmp fe;
    Bytes.unsafe_to_string tmp

  let from_be_octets ~to_montgomery buf =
    let buf_rev = rev_string buf in
    let tmp = create () in
    F.from_octets tmp buf_rev;
    let tmp = to_montgomery tmp in
    of_fe_out tmp

end

module Make_field_element (P : Parameters) (F : Foreign_mont) : Field_element = struct
  include Make_field_element_base(P)(F)

  let from_montgomery a =
    let tmp = create () in
    F.from_montgomery tmp a;
    of_fe_out tmp

  let to_montgomery x = F.to_montgomery x (of_fe_out x); x

  let from_be_octets = from_be_octets ~to_montgomery
end

module Make_field_element_usol (P : Parameters) (F : Foreign_field) : Field_element = struct
  include Make_field_element_base(P)(F)

  let from_montgomery x = x

  let to_montgomery x = x
  let from_be_octets = from_be_octets ~to_montgomery
end


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

module type Transform = sig
  val in_x : field_element -> field_element
  val in_y : field_element -> field_element
  val out_x : field_element -> field_element
  val out_y : field_element -> field_element
end

module NoTransform : Transform = struct
  open Fun
  let in_x = id
  let in_y = id
  let out_x = id
  let out_y = id
end

module Make_point_base (P : Parameters) (F : Foreign_point) (Fe: Field_element)
    (T : Transform) : Point = struct

  let pident = rev_string P.pident
  let make (Fe x) (Fe y) = Point (String.cat x y)
  let p_x (Point p) = Fe (String.sub p 0 P.fe_length)
  let p_y (Point p) = Fe (String.sub p P.fe_length P.fe_length)
  let out_point () = Point_out (Bytes.create (P.fe_length * 2))
  let out_p_to_p (Point_out p) = Point (Bytes.unsafe_to_string p)

  let at_infinity () =
    let x = Fe.zero in
    let y = Fe.zero in
    make x y

  let is_infinity (p : point) = not (Fe.nz (p_y p))

  let add_ax =
    if String.length P.a = 0 then
      fun ~x:_ n -> n
    else
      let a = Fe.from_be_octets P.a in
      fun ~x n ->
        let ax = Fe.mul a x in
        Fe.add n ax

  let is_solution_to_curve_equation =
    let b = Fe.from_be_octets P.b in
    fun ~x ~y ->
      let x3 = Fe.mul x x in
      let x3 = Fe.mul x3 x in
      let y2 = Fe.mul y y in
      let sum = add_ax ~x x3 in
      let sum = Fe.add sum b in
      let sum = Fe.sub sum y2 in
      not (Fe.nz sum)

  let check_coordinate buf =
    (* ensure buf < p: *)
    match Eqaf.compare_be_with_len ~len:P.byte_length buf P.p >= 0 with
    | true -> None
    | exception Invalid_argument _ -> None
    | false -> Some (Fe.from_be_octets buf)

  let validate_finite_point_fe x y =
    if is_solution_to_curve_equation ~x ~y then
      Ok (make x y)
    else Error `Not_on_curve

  (** Convert coordinates to a finite point ensuring:
      - x < p
      - y < p
      - y^2 = x^3 + ax + b
  *)
  let validate_finite_point ~x ~y =
    match (check_coordinate x, check_coordinate y) with
    | Some x, Some y ->
      let x, y = T.in_x x, T.in_y y in
      validate_finite_point_fe x y
    | _ -> Error `Invalid_range

  let to_affine_raw p =
    if is_infinity p then
      None
    else
      let x = Fe.from_montgomery (p_x p) in
      let y = Fe.from_montgomery (p_y p) in
      Some (T.out_x x, T.out_y y)

  let to_affine p =
    Option.map (fun (x, y) -> Fe.to_octets x, Fe.to_octets y)
      (to_affine_raw p)

  let to_octets ~compress p =
    let buf =
      match to_affine p with
      | None -> String.make 1 '\000'
      | Some (x, y) ->
        let len_x = String.length x and len_y = String.length y in
        let res = Bytes.create (1 + len_x + len_y) in
        Bytes.set res 0 '\004' ;
        let rev_x = rev_string x and rev_y = rev_string y in
        Bytes.unsafe_blit_string rev_x 0 res 1 len_x ;
        Bytes.unsafe_blit_string rev_y 0 res (1 + len_x) len_y ;
        Bytes.unsafe_to_string res
    in
    if compress then
      let out = Bytes.create (P.byte_length + 1) in
      let ident =
        2 + (String.get_uint8 buf ((P.byte_length * 2) - 1)) land 1
      in
      Bytes.unsafe_blit_string buf 1 out 1 P.byte_length;
      Bytes.set_uint8 out 0 ident;
      Bytes.unsafe_to_string out
    else
      buf

  let x_of_finite_point p =
    match to_affine p with None -> assert false | Some (x, _) -> rev_string x

  let pow x exp =
    let r0 = ref Fe.one in
    let r1 =  ref x in
    for i = P.byte_length * 8 - 1 downto 0 do
      let bit = bit_at exp i in
      let multiplied = Fe.mul !r0 !r1 in
      let r0_sqr = Fe.sqr !r0 in
      let r1_sqr = Fe.sqr !r1 in
      r0 := Fe.select bit ~then_:multiplied ~else_:r0_sqr;
      r1 := Fe.select bit ~then_:r1_sqr ~else_:multiplied;
    done;
    !r0

  let decompress =
  (* When p = 4*k+3, as is the case of NIST-P256, there is an efficient square
     root algorithm to recover the y, as follows:

    Given the compact representation of Q as x,
     y2 = x^3 + a*x + b
     y' = y2^((p+1)/4)
     y = min(y',p-y')
     Q=(x,y) is the canonical representation of the point
  *)
    let b = Fe.from_be_octets P.b in
    let p = Fe.from_be_octets P.p in
    fun pk ->
      match check_coordinate (String.sub pk 1 P.byte_length) with
      | None -> Error `Invalid_range
      | Some x ->
      let x = T.in_x x in
      let x3 = Fe.mul x x in
      let x3 = Fe.mul x3 x in (* x3 *)
      let sum = add_ax ~x x3 in
      let sum = Fe.add sum b in (* y^2 *)
      let y = pow sum pident in (* https://tools.ietf.org/id/draft-jivsov-ecc-compact-00.xml#sqrt point 4.3*)
      let y' = Fe.sub p y in
      let y_str = Fe.to_octets (Fe.from_montgomery (T.out_y y)) in (* number must not be in montgomery domain*)
      let ident = String.get_uint8 pk 0 in
      let signY =
        2 + (String.get_uint8 y_str 1) land 1
      in
      let y = if Int.equal signY ident then y else y' in
      validate_finite_point_fe x y

  let of_octets buf =
    let len = P.byte_length in
    if String.length buf = 0 then
      Error `Invalid_format
    else
      match String.get_uint8 buf 0 with
      | 0x00 when String.length buf = 1 ->
        Ok (at_infinity ())
      | 0x02 | 0x03 when String.length pident > 0 ->
        decompress buf
      | 0x04 when String.length buf = 1 + len + len ->
        let x = String.sub buf 1 len in
        let y = String.sub buf (1 + len) len in
        validate_finite_point ~x ~y
      | 0x00 | 0x04 -> Error `Invalid_length
      | _ -> Error `Invalid_format

  let scalar_mult_base (Scalar d) =
    assert (String.length d = P.byte_length);
    let tmp = out_point () in
    F.scalar_mult_base_c tmp (rev_string d);
    out_p_to_p tmp

  let scalar_mult (Scalar s) p =
    assert (String.length s = P.byte_length);
    let tmp = out_point () in
    F.scalar_mult_c tmp (rev_string s) p;
    out_p_to_p tmp

  let scalar_mult_add (Scalar a) (Scalar b) p =
    assert (String.length a = P.byte_length);
    assert (String.length b = P.byte_length);
    let tmp = out_point () in
    F.scalar_mult_add_c tmp (rev_string a) (rev_string b) p;
    out_p_to_p tmp
end

module Make_point
  (P : Parameters) (F : Foreign_point) (Fe : Field_element)
  : Point = Make_point_base(P)(F)(Fe)(NoTransform)


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

module type Scalar = sig
  val not_zero : string -> bool
  val is_in_range : string -> bool
  val of_octets : string -> (scalar, error) result
  val to_octets : scalar -> string
end

module Make_scalar (Param : Parameters) (P : Point) : Scalar = struct
  let not_zero =
    let zero = String.make Param.byte_length '\000' in
    fun buf -> not (Eqaf.equal buf zero)

  let is_in_range buf =
    not_zero buf
    && Eqaf.compare_be_with_len ~len:Param.byte_length Param.n buf > 0

  let of_octets buf =
    match is_in_range buf with
    | exception Invalid_argument _ -> Error `Invalid_length
    | true -> Ok (Scalar buf)
    | false -> Error `Invalid_range

  let to_octets (Scalar buf) = buf
end

module Make_dh (Param : Parameters) (P : Point) (S : Scalar) : Dh = struct
  let point_of_octets c =
    match P.of_octets c with
    | Ok p when not (P.is_infinity p) -> Ok p
    | Ok _ -> Error `At_infinity
    | Error _ as e -> e

  let point_to_octets = P.to_octets

  type secret = scalar

  let share ?(compress = false) private_key =
    let public_key = P.scalar_mult_base private_key in
    point_to_octets ~compress public_key

  let secret_of_octets ?compress s =
    match S.of_octets s with
    | Ok p -> Ok (p, share ?compress p)
    | Error _ as e -> e

  let secret_to_octets s =
    S.to_octets s

  let rec generate_private_key ?g () =
    let candidate = Mirage_crypto_rng.generate ?g Param.byte_length in
    match S.of_octets candidate with
    | Ok secret -> secret
    | Error _ -> generate_private_key ?g ()

  let gen_key ?compress ?g () =
    let private_key = generate_private_key ?g () in
    private_key, share ?compress private_key

  let key_exchange secret received =
    match point_of_octets received with
    | Error _ as err -> err
    | Ok shared -> Ok (P.x_of_finite_point (P.scalar_mult secret shared))
end

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

module Make_scalar_element (P : Parameters) (F : Foreign_n) = struct
  let of_se_out (Se_out x) = Se (Bytes.unsafe_to_string x)

  let create () = Se_out (Bytes.create P.fe_length)

  let create_octets () = Bytes.create P.byte_length

  let from_octets_raw v =
    let v' = create () in
    F.from_bytes v' v;
    of_se_out v'

  let from_be_octets v =
    let v' = create () in
    F.from_bytes v' (rev_string v);
    F.to_montgomery v' (of_se_out v');
    of_se_out v'

  let to_be_octets v =
    let buf = create_octets () in
    F.to_bytes buf v;
    rev_string (Bytes.unsafe_to_string buf)

  let mul a b =
    let tmp = create () in
    F.mul tmp a b;
    of_se_out tmp

  let add a b =
    let tmp = create () in
    F.add tmp a b;
    of_se_out tmp

  let inv a =
    let tmp = create () in
    F.inv tmp a;
    F.to_montgomery tmp (of_se_out tmp);
    of_se_out tmp

  let one =
    let tmp = create () in
    F.one tmp;
    of_se_out tmp

  let from_montgomery a =
    let tmp = create () in
    F.from_montgomery tmp a;
    of_se_out tmp

  let to_montgomery a =
    let tmp = create () in
    F.to_montgomery tmp a;
    of_se_out tmp
end

module Make_dsa (Param : Parameters) (F : Scalar_element) (P : Point) (S : Scalar) (H : Digestif.S) = struct
  type priv = scalar

  let byte_length = Param.byte_length

  let bit_length = Param.bit_length

  let priv_of_octets= S.of_octets

  let priv_to_octets = S.to_octets

  let padded msg =
    let l = String.length msg in
    let bl = Param.byte_length in
    let first_byte_ok () =
      match Param.first_byte_bits with
      | None -> true
      | Some m -> (String.get_uint8 msg 0) land (0xFF land (lnot m)) = 0
    in
    if l > bl || (l = bl && not (first_byte_ok ())) then
      raise Message_too_long
    else if l = bl then
      msg
    else
      ( let res = Bytes.make bl '\000' in
        Bytes.unsafe_blit_string msg 0 res (bl - l) l ;
        Bytes.unsafe_to_string res )

  (* RFC 6979: compute a deterministic k *)
  module K_gen (H : Digestif.S) = struct
    let drbg : 'a Mirage_crypto_rng.generator =
      let module M = Mirage_crypto_rng.Hmac_drbg (H) in (module M)

    let g ~key msg =
      let g = Mirage_crypto_rng.create ~strict:true drbg in
      Mirage_crypto_rng.reseed ~g (S.to_octets key ^ msg);
      g

    (* Defined in RFC 6979 sec 2.3.2 with
       - blen = 8 * Param.byte_length
       - qlen = Param.bit_length *)
    let bits2int r =
      (* keep qlen *leftmost* bits *)
      let shift = (8 * Param.byte_length) - Param.bit_length in
      if shift = 0 then
        Bytes.unsafe_to_string r
      else
        (* Assuming shift is < 8 *)
        let r' = Bytes.create Param.byte_length in
        let p = ref 0x00 in
        for i = 0 to Param.byte_length - 1 do
          let x = Bytes.get_uint8 r i in
          let v = (x lsr shift) lor (!p lsl (8 - shift)) in
          p := x;
          Bytes.set_uint8 r' i v
        done;
        Bytes.unsafe_to_string r'

    (* take qbit length, and ensure it is suitable for ECDSA (> 0 & < n) *)
    let gen g =
      let rec go () =
        let b = Bytes.create Param.byte_length in
        Mirage_crypto_rng.generate_into ~g b Param.byte_length;
        (* truncate to the desired number of bits *)
        let r = bits2int b in
        if S.is_in_range r then r else go ()
      in
      go ()

    let generate ~key buf = gen (g ~key (padded buf))
  end

  module K_gen_default = K_gen(H)

  type pub = point

  let pub_of_octets = P.of_octets

  let pub_to_octets ?(compress = false) pk = P.to_octets ~compress pk

  let generate ?g () =
    (* FIPS 186-4 B 4.2 *)
    let d =
      let rec one () =
        match S.of_octets (Mirage_crypto_rng.generate ?g Param.byte_length) with
        | Ok x -> x
        | Error _ -> one ()
      in
      one ()
    in
    let q = P.scalar_mult_base d in
    (d, q)

  let x_of_finite_point_mod_n p =
    match P.to_affine p with
    | None -> None
    | Some (x, _) ->
      let x = F.from_octets_raw x in
      let x = F.mul x F.one in
      Some (F.to_be_octets x)

  let sign ~key ?k msg =
    let msg = padded msg in
    let e = F.from_be_octets msg in
    let g = K_gen_default.g ~key msg in
    let rec do_sign g =
      let again () =
        match k with
        | None -> do_sign g
        | Some _ -> invalid_arg "k not suitable"
      in
      let k' = match k with None -> K_gen_default.gen g | Some k -> k in
      let ksc = match S.of_octets k' with
        | Ok ksc -> ksc
        | Error _ -> invalid_arg "k not in range" (* if no k is provided, this cannot happen since K_gen_*.gen already preserves the Scalar invariants *)
      in
      let point = P.scalar_mult_base ksc in
      match x_of_finite_point_mod_n point with
      | None -> again ()
      | Some r ->
        let r_mon = F.from_be_octets r in
        let kmon = F.from_be_octets k' in
        let kinv = F.inv kmon in
        let dmon = F.from_be_octets (S.to_octets key) in
        let rd = F.mul r_mon dmon in
        let cmon = F.add e rd in
        let smon = F.mul kinv cmon in
        let s = F.from_montgomery smon in
        let s = F.to_be_octets s in
        if S.not_zero s && S.not_zero r then
          r, s
        else
          again ()
    in
    do_sign g

  let pub_of_priv priv = P.scalar_mult_base priv

  let verify ~key (r, s) msg =
    try
      let r = padded r and s = padded s in
      if not (S.is_in_range r && S.is_in_range s) then
        false
      else
        let msg = padded msg in
        let z = F.from_be_octets msg in
        let s_mon = F.from_be_octets s in
        let s_inv = F.inv s_mon in
        let u1 = F.mul z s_inv in
        let r_mon = F.from_be_octets r in
        let u2 = F.mul r_mon s_inv in
        let u1 = F.from_montgomery u1 in
        let u2 = F.from_montgomery u2 in
        match
          S.of_octets (F.to_be_octets u1),
          S.of_octets (F.to_be_octets u2)
        with
        | Ok u1, Ok u2 ->
          let point = P.scalar_mult_add u1 u2 key
          in
          begin match x_of_finite_point_mod_n point with
            | None -> false (* point is infinity *)
            | Some r' -> String.equal r r'
          end
        | Error _, _ | _, Error _ -> false
    with
    | Message_too_long -> false

end
