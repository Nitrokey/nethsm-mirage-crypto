open Nethsm_crypto_nist
open Nethsm_crypto_secp256k1
open Nethsm_crypto_brainpool

module Time = struct
  let time ~n f a =
    let t1 = Sys.time () in
    for _ = 1 to n do
      ignore (f a)
    done;
    let t2 = Sys.time () in
    t2 -. t1

  let warmup () =
    let x = ref 0 in
    let rec go start =
      if Sys.time () -. start < 1. then (
        for i = 0 to 10000 do
          x := !x + i
        done;
        go start)
    in
    go (Sys.time ())
end

let count_period = 10.

let count f n =
  ignore (f n);
  let i1 = 5 in
  let t1 = Time.time ~n:i1 f n in
  let iters = int_of_float (float i1 *. count_period /. t1) in
  let time = Time.time ~n:iters f n in
  (iters, time)

let count title f to_str args =
  Printf.printf "\n* [%s]\n%!" title;
  args
  |> List.iter @@ fun arg ->
     Gc.full_major ();
     let iters, time = count f arg in
     Printf.printf "    %s:  %.03f ops per second (%d iters in %.03f)\n%!"
       (to_str arg)
       (float iters /. time)
       iters time

let msg_str = String.make 100 '\xAA'
let msg_str_32 = String.sub msg_str 0 32
let msg_str_48 = String.sub msg_str 0 48
let msg_str_64 = String.sub msg_str 0 64
let msg_str_65 = String.sub msg_str 0 65

let ecdsa_p256 =
  Result.get_ok
    (P256.Dsa.priv_of_octets
       "\x08\x9f\x4f\xfc\xcc\xf9\xba\x13\xfe\xdd\x09\x42\xef\x08\xcf\x2d\x90\x9f\x32\xe2\x93\x4a\xb5\xc9\x3b\x6c\x99\xbe\x5a\x9f\xf5\x27")

let ecdsa_p256_sig () = P256.Dsa.sign ~key:ecdsa_p256 msg_str_32

let ecdsa_p256k1 =
  Result.get_ok
    (P256k1.Dsa.priv_of_octets
       "\x08\x9f\x4f\xfc\xcc\xf9\xba\x13\xfe\xdd\x09\x42\xef\x08\xcf\x2d\x90\x9f\x32\xe2\x93\x4a\xb5\xc9\x3b\x6c\x99\xbe\x5a\x9f\xf5\x27")

let ecdsa_p256k1_sig () = P256k1.Dsa.sign ~key:ecdsa_p256k1 msg_str_32

let ecdsa_p384 =
  Result.get_ok
    (P384.Dsa.priv_of_octets
       "\xf5\xc0\xc9\xfb\x95\x17\x86\x41\xaf\x76\xf3\x83\x1f\x41\xe2\xd3\x7c\xfa\xaf\xff\xc7\xe6\x01\x72\xcf\xb0\x89\xfe\x60\x4b\x56\xa6\x1c\x7c\x31\xa6\x90\x4b\x3b\x5d\x08\x20\x7a\x4b\x81\xe2\x5e\xa5")

let ecdsa_p384_sig () = P384.Dsa.sign ~key:ecdsa_p384 msg_str_48

let ecdsa_p521 =
  Result.get_ok
    (P521.Dsa.priv_of_octets
       "\x00\xb1\x8f\x60\xc0\x35\x2a\xd8\xe3\xef\x98\x2f\x1d\xdf\xcf\x6e\xec\x7f\xa6\xca\xf0\xe6\xf3\x68\x35\x4a\x8b\x02\xb2\xd8\xac\x1e\x05\x9e\x30\x98\x91\xe2\xbf\xa8\x57\x91\xa5\xe7\x1b\x40\xbd\xec\xbf\x90\x2b\xf2\x43\xdc\x3b\x00\x80\x49\x5c\xf4\xd9\x1c\x78\x72\x8b\xd5")

let ecdsa_p521_sig () = P521.Dsa.sign ~key:ecdsa_p521 msg_str_65

let ecdsa_brainpoolp256 =
  Result.get_ok
    (BrainpoolP256.Dsa.priv_of_octets
       "\x08\x9f\x4f\xfc\xcc\xf9\xba\x13\xfe\xdd\x09\x42\xef\x08\xcf\x2d\x90\x9f\x32\xe2\x93\x4a\xb5\xc9\x3b\x6c\x99\xbe\x5a\x9f\xf5\x27")

let ecdsa_brainpoolp256_sig () =
  BrainpoolP256.Dsa.sign ~key:ecdsa_brainpoolp256 msg_str_32

let ecdsa_brainpoolp384 =
  Result.get_ok
    (BrainpoolP384.Dsa.priv_of_octets
       "\x24\xdd\xf0\xfb\xb4\x1c\x28\x36\x5d\x30\x2d\xd9\xd2\x6f\xf9\xc3\x2c\x76\xc8\x5f\xa8\xb9\x13\x8a\x3e\xc6\x21\xd0\xca\xff\x6d\xe8\xa7\x24\xb4\x5d\x6f\xe0\xd9\x18\x00\x44\x24\x2b\x9f\x41\xc8\x4b")

let ecdsa_brainpoolp384_sig () =
  BrainpoolP384.Dsa.sign ~key:ecdsa_brainpoolp384 msg_str_48

let ecdsa_brainpoolp512 =
  Result.get_ok
    (BrainpoolP512.Dsa.priv_of_octets
       "\x62\x80\xeb\x95\x40\x5f\xa8\xc0\xe9\xd9\x70\x54\x73\x01\xbb\xef\xb1\x52\xc8\xc8\x11\x4a\xbc\x73\x0c\x89\xbf\x6d\xb3\xf7\xd9\x49\xfc\xfd\x7e\xbb\x82\xfd\x2d\xbd\x43\xd2\x8d\x47\xbf\x4e\xd9\x5d\xe9\x7b\xae\xd1\x9f\x7d\x08\x7c\xf3\x03\xd2\xb0\xcd\x41\x37\x67")

let ecdsa_brainpoolp512_sig () =
  BrainpoolP512.Dsa.sign ~key:ecdsa_brainpoolp512 msg_str_64

let bip340 =
  Result.get_ok
    (P256k1.Bip340.priv_of_octets
       "\x08\x9f\x4f\xfc\xcc\xf9\xba\x13\xfe\xdd\x09\x42\xef\x08\xcf\x2d\x90\x9f\x32\xe2\x93\x4a\xb5\xc9\x3b\x6c\x99\xbe\x5a\x9f\xf5\x27")

let bip340_sig () =
  P256k1.Bip340.sign ~key:bip340 ~aux_rand:(String.make 32 '\000') msg_str_32

let ecdsas =
  [
    ("P256", `P256 (ecdsa_p256, ecdsa_p256_sig ()));
    ("P256k1", `P256k1 (ecdsa_p256k1, ecdsa_p256k1_sig ()));
    ("P384", `P384 (ecdsa_p384, ecdsa_p384_sig ()));
    ("P521", `P521 (ecdsa_p521, ecdsa_p521_sig ()));
    ( "BrainpoolP256",
      `BrainpoolP256 (ecdsa_brainpoolp256, ecdsa_brainpoolp256_sig ()) );
    ( "BrainpoolP384",
      `BrainpoolP384 (ecdsa_brainpoolp384, ecdsa_brainpoolp384_sig ()) );
    ( "BrainpoolP512",
      `BrainpoolP512 (ecdsa_brainpoolp512, ecdsa_brainpoolp512_sig ()) );
    ("Bip340", `P256k1_bip340 (bip340, bip340_sig ()));
  ]

let ecdh_shares =
  [
    ( "P256",
      `P256
        ( P256.Dh.secret_of_octets
            "\x47\x0d\x57\x70\x6c\x77\x06\xb6\x8a\x3f\x42\x3a\xea\xf4\xff\x7f\xdd\x02\x49\x4a\x10\xd3\xe3\x81\xc3\xc1\x1f\x72\x76\x80\x2c\xdc"
          |> Result.get_ok |> fst,
          "\x04\x11\xb3\xfc\x82\x72\x1c\x26\x9a\x19\x90\x9a\x3b\x2f\xc2\x6d\x98\x95\x82\x6d\x0c\xfc\xbc\x1f\x76\x26\xe4\x88\xf0\x1f\x4c\xa6\xb5\xc5\xed\x76\xad\xee\x7a\xf8\x1b\xb2\x0b\x17\xcf\x23\x1c\xbf\x0c\x67\xdb\x02\x95\xd6\x8d\x1d\x92\xc2\xd2\xa5\xa8\x06\x38\xd7\x8d"
        ) );
    ( "P256k1",
      `P256k1
        ( P256k1.Dh.secret_of_octets
            "\x47\x0d\x57\x70\x6c\x77\x06\xb6\x8a\x3f\x42\x3a\xea\xf4\xff\x7f\xdd\x02\x49\x4a\x10\xd3\xe3\x81\xc3\xc1\x1f\x72\x76\x80\x2c\xdc"
          |> Result.get_ok |> fst,
          "\x04\xd8\x09\x6a\xf8\xa1\x1e\x0b\x80\x03\x7e\x1e\xe6\x82\x46\xb5\xdc\xbb\x0a\xeb\x1c\xf1\x24\x4f\xd7\x67\xdb\x80\xf3\xfa\x27\xda\x2b\x39\x68\x12\xea\x16\x86\xe7\x47\x2e\x96\x92\xea\xf3\xe9\x58\xe5\x0e\x95\x00\xd3\xb4\xc7\x72\x43\xdb\x1f\x2a\xcd\x67\xba\x9c\xc4"
        ) );
    ( "P384",
      `P384
        ( P384.Dh.secret_of_octets
            "\xee\x55\xe2\x9b\x61\x75\x2d\x5a\x3e\x52\x56\x56\xdb\x8b\xd8\xfe\x6f\x94\xfa\xb8\xaa\xcc\x9e\x92\xac\xff\x4c\x48\x12\xbf\x7a\x61\x87\xab\xa4\x6c\xc6\x0a\xb8\xf0\x8e\xfc\xf2\xd5\x74\x58\x4b\x74"
          |> Result.get_ok |> fst,
          "\x04\x04\x89\xcf\x24\xbc\x80\xbf\x89\xfd\xfe\x9c\x05\xec\xc3\x9f\x69\x16\xad\x45\x09\xd9\x39\x85\x97\x95\x0d\x3d\x24\xe8\x28\xf6\xbf\x56\xba\x4a\xd6\xd2\x1e\xd7\x86\x3b\xed\x68\xe4\x13\x36\x4b\xd4\xc7\xb1\xe9\x04\x7d\x36\x12\x4c\x69\x53\xbe\x7c\x61\x20\x9c\xb3\xfc\x56\x45\x2f\x73\x05\x29\x37\x83\xc7\xc0\xed\x92\x9d\x6c\x98\xc7\xbc\x97\xf6\x0a\x72\xed\x22\x69\xa8\xeb\x19\xbb\x7e\xe1\x31"
        ) );
    ( "P521",
      `P521
        ( P521.Dh.secret_of_octets
            "\x00\xaa\x47\x0b\xa1\xcc\x84\x3b\xa3\x14\x82\x1e\x72\xde\x4c\xd2\x99\xae\xc1\xf2\x6e\x9d\x64\xa0\xd8\x7d\xb1\x8a\x3d\xa9\xf6\x5c\x45\xec\xfc\xc5\x61\x7f\xf0\xd7\x3b\x2e\x0e\x1c\xdf\xf8\x04\x8e\x01\xbe\x5e\x20\x14\x94\x12\xe7\xdb\xfa\xb7\xfe\xae\x24\x9b\x1b\xfa\x4d"
          |> Result.get_ok |> fst,
          "\x04\x00\x1d\x16\x29\xee\xb1\xc4\x25\xf9\x04\xd7\x55\x33\x00\x79\xd1\x3c\x77\xda\x92\x1e\x01\xcf\x50\xd7\x17\xe0\xd6\x85\x0a\x81\xa3\x90\x2b\xb9\x2a\x03\xfa\xea\xcb\xd6\x28\x9c\x15\x90\x68\x5a\x60\x44\xb5\xe9\x4d\xcf\xc4\x1d\xeb\x6a\x88\xdb\x62\xa8\x91\xb0\xb8\x93\xbb\x00\xe4\x2a\x66\xb2\xf0\x13\xbd\xd0\xd2\x7d\x8e\x07\xcb\x35\xfc\x3e\x2c\x2b\x22\xf9\x3e\xcf\xd5\xea\xb7\x88\x61\x97\xca\x07\x3c\x2c\x5e\x68\x31\xd6\x5e\x2d\x0b\x8a\xa4\x08\x43\x8e\x49\x54\x2f\x05\xf4\x1c\x57\x6d\xf7\x0e\x3c\xaf\x5b\xb8\x22\x7d\x48\x30\x94\xae\x58"
        ) );
    ( "BrainpoolP256",
      `BrainpoolP256
        ( BrainpoolP256.Dh.secret_of_octets
            "\x47\x0d\x57\x70\x6c\x77\x06\xb6\x8a\x3f\x42\x3a\xea\xf4\xff\x7f\xdd\x02\x49\x4a\x10\xd3\xe3\x81\xc3\xc1\x1f\x72\x76\x80\x2c\xdc"
          |> Result.get_ok |> fst,
          "\x04\x4c\xee\x5e\x10\x72\xb3\x0d\x64\xf7\x0b\xf0\x19\x58\xe2\x2c\x04\x4a\x21\x27\xdd\xd7\x44\xce\x30\x60\xc1\x59\x90\xff\x0f\xe1\x14\x8c\x6e\xe5\x65\x59\x82\x9a\x5a\x84\xdd\x5c\x86\x46\xee\x0c\x43\xd0\xb7\xc5\x01\x81\xf2\x34\xec\x09\xeb\xa4\x3b\xc8\x6b\x16\x9e"
        ) );
    ( "BrainpoolP384",
      `BrainpoolP384
        ( BrainpoolP384.Dh.secret_of_octets
            "\x24\xdd\xf0\xfb\xb4\x1c\x28\x36\x5d\x30\x2d\xd9\xd2\x6f\xf9\xc3\x2c\x76\xc8\x5f\xa8\xb9\x13\x8a\x3e\xc6\x21\xd0\xca\xff\x6d\xe8\xa7\x24\xb4\x5d\x6f\xe0\xd9\x18\x00\x44\x24\x2b\x9f\x41\xc8\x4b"
          |> Result.get_ok |> fst,
          "\x04\x70\xff\xb3\x50\x17\x32\x56\xeb\x43\x7b\x14\x03\x65\x84\x23\x97\xeb\xaf\x36\x11\xb6\x38\x95\x96\xc1\xf1\x7c\x5f\xf5\xce\x52\x01\xf2\x4f\x69\x85\xb8\xfe\x08\x90\xdc\xae\x54\xb2\x60\x3d\xfb\x40\x87\x24\x2a\xaf\x7b\x2d\x95\xb3\x19\x9b\xfa\x03\xe8\xfc\xe5\x4e\xf6\x80\xb5\x71\x09\x84\x72\x74\xdb\x3b\x3a\x65\x51\x2b\x7f\x83\x22\x48\xe7\x0b\x10\x30\xe9\x5d\xb6\x42\x95\x89\x77\x5c\x33\x46"
        ) );
    ( "BrainpoolP512",
      `BrainpoolP512
        ( BrainpoolP512.Dh.secret_of_octets
            "\x62\x80\xeb\x95\x40\x5f\xa8\xc0\xe9\xd9\x70\x54\x73\x01\xbb\xef\xb1\x52\xc8\xc8\x11\x4a\xbc\x73\x0c\x89\xbf\x6d\xb3\xf7\xd9\x49\xfc\xfd\x7e\xbb\x82\xfd\x2d\xbd\x43\xd2\x8d\x47\xbf\x4e\xd9\x5d\xe9\x7b\xae\xd1\x9f\x7d\x08\x7c\xf3\x03\xd2\xb0\xcd\x41\x37\x67"
          |> Result.get_ok |> fst,
          "\x04\x8a\x73\xa6\x66\x05\xa5\xdb\x25\x2e\xf4\x18\xff\x2c\x43\x96\x9b\xd4\x12\x81\x87\xce\x43\x1c\x36\xa3\x3d\x3f\xf3\x03\x4c\xf8\x91\x0f\xb0\x02\x1c\xe8\x49\x72\x36\x21\x19\x9d\x0d\x7e\xa4\x80\x5f\x3c\xda\xb8\x2f\x6c\x90\x92\x57\x76\x2d\xa2\xa9\x7e\x26\x30\x5b\x07\x8c\x1f\xd7\x91\xfa\x95\x7e\x97\x5e\x30\xdf\x5b\x87\x60\x54\x75\x82\x67\x12\x9e\x49\x74\xa0\x83\x37\x2b\x0c\xe0\x71\x18\x0d\x05\xe1\x97\x8b\xd9\x0b\x84\x07\xc0\xa7\xff\x7f\x66\x51\xbd\x3f\xfc\xf1\xa5\x74\xdf\xe9\x5a\x2e\x8a\xf3\x86\x6c\xbb\x38\x5d\x21"
        ) );
  ]

let bm name f = (name, fun () -> f name)

let benchmarks =
  [
    bm "ecdsa-generate" (fun name ->
        count name
          (fun (_, x) ->
            match x with
            | `P256 _ -> P256.Dsa.generate () |> ignore
            | `P256k1 _ -> P256k1.Dsa.generate () |> ignore
            | `P384 _ -> P384.Dsa.generate () |> ignore
            | `P521 _ -> P521.Dsa.generate () |> ignore
            | `BrainpoolP256 _ -> BrainpoolP256.Dsa.generate () |> ignore
            | `BrainpoolP384 _ -> BrainpoolP384.Dsa.generate () |> ignore
            | `BrainpoolP512 _ -> BrainpoolP512.Dsa.generate () |> ignore
            | `P256k1_bip340 _ -> P256k1.Bip340.generate () |> ignore)
          fst ecdsas);
    bm "ecdsa-sign" (fun name ->
        count name
          (fun (_, x) ->
            match x with
            | `P256 (key, _) -> P256.Dsa.sign ~key msg_str_32
            | `P256k1 (key, _) -> P256k1.Dsa.sign ~key msg_str_32
            | `P384 (key, _) -> P384.Dsa.sign ~key msg_str_48
            | `P521 (key, _) -> P521.Dsa.sign ~key msg_str_65
            | `BrainpoolP256 (key, _) -> BrainpoolP256.Dsa.sign ~key msg_str_32
            | `BrainpoolP384 (key, _) -> BrainpoolP384.Dsa.sign ~key msg_str_48
            | `BrainpoolP512 (key, _) -> BrainpoolP512.Dsa.sign ~key msg_str_64
            | `P256k1_bip340 (key, _) ->
                P256k1.Bip340.sign ~key ~aux_rand:(String.make 32 '\000')
                  msg_str_32)
          fst ecdsas);
    bm "ecdsa-verify" (fun name ->
        count name
          (fun (_, x) ->
            match x with
            | `P256 (key, signature) ->
                P256.Dsa.(verify ~key:(pub_of_priv key) signature msg_str_32)
            | `P256k1 (key, signature) ->
                P256k1.Dsa.(verify ~key:(pub_of_priv key) signature msg_str_32)
            | `P384 (key, signature) ->
                P384.Dsa.(verify ~key:(pub_of_priv key) signature msg_str_48)
            | `P521 (key, signature) ->
                P521.Dsa.(verify ~key:(pub_of_priv key) signature msg_str_65)
            | `BrainpoolP256 (key, signature) ->
                BrainpoolP256.Dsa.(
                  verify ~key:(pub_of_priv key) signature msg_str_32)
            | `BrainpoolP384 (key, signature) ->
                BrainpoolP384.Dsa.(
                  verify ~key:(pub_of_priv key) signature msg_str_48)
            | `BrainpoolP512 (key, signature) ->
                BrainpoolP512.Dsa.(
                  verify ~key:(pub_of_priv key) signature msg_str_64)
            | `P256k1_bip340 (key, signature) ->
                P256k1.Bip340.(
                  verify ~key:(pub_of_priv key) signature msg_str_32))
          fst ecdsas);
    bm "ecdh-secret" (fun name ->
        count name
          (fun (_, x) ->
            match x with
            | `P256 _ -> P256.Dh.gen_key () |> ignore
            | `P256k1 _ -> P256k1.Dh.gen_key () |> ignore
            | `P384 _ -> P384.Dh.gen_key () |> ignore
            | `P521 _ -> P521.Dh.gen_key () |> ignore
            | `BrainpoolP256 _ -> BrainpoolP256.Dh.gen_key () |> ignore
            | `BrainpoolP384 _ -> BrainpoolP384.Dh.gen_key () |> ignore
            | `BrainpoolP512 _ -> BrainpoolP512.Dh.gen_key () |> ignore)
          fst ecdh_shares);
    bm "ecdh-share" (fun name ->
        count name
          (fun (_, x) ->
            match x with
            | `P256 (sec, share) ->
                P256.Dh.key_exchange sec share |> Result.get_ok |> ignore
            | `P256k1 (sec, share) ->
                P256k1.Dh.key_exchange sec share |> Result.get_ok |> ignore
            | `P384 (sec, share) ->
                P384.Dh.key_exchange sec share |> Result.get_ok |> ignore
            | `P521 (sec, share) ->
                P521.Dh.key_exchange sec share |> Result.get_ok |> ignore
            | `BrainpoolP256 (sec, share) ->
                BrainpoolP256.Dh.key_exchange sec share
                |> Result.get_ok |> ignore
            | `BrainpoolP384 (sec, share) ->
                BrainpoolP384.Dh.key_exchange sec share
                |> Result.get_ok |> ignore
            | `BrainpoolP512 (sec, share) ->
                BrainpoolP512.Dh.key_exchange sec share
                |> Result.get_ok |> ignore)
          fst ecdh_shares);
  ]

let help () =
  Printf.printf "available benchmarks:\n  ";
  List.iter (fun (n, _) -> Printf.printf "%s  " n) benchmarks;
  Printf.printf "\n%!"

let runv fs =
  Time.warmup ();
  List.iter (fun f -> f ()) fs

let () =
  let seed = "abcd" in
  let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
  Mirage_crypto_rng.set_default_generator g;
  match Array.to_list Sys.argv with
  | _ :: (_ :: _ as args) -> (
      try
        let fs =
          args
          |> List.map @@ fun n ->
             snd (benchmarks |> List.find @@ fun (n1, _) -> n = n1)
        in
        runv fs
      with Not_found -> help ())
  | _ -> help ()
