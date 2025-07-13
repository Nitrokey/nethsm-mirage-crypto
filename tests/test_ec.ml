open Nethsm_crypto
open Nethsm_crypto_nist
open Nethsm_crypto_secp256k1
open Nethsm_crypto_brainpool
open Test_common

module Testable = struct
  let ok_or_error =
    Alcotest.result Alcotest.unit (Alcotest.testable pp_error ( = ))
end

let pp_hex_le fmt buf =
  let n = String.length buf in
  let bbuf = Bytes.unsafe_of_string buf in
  for i = n - 1 downto 0 do
    let byte = Bytes.get_uint8 bbuf i in
    Format.fprintf fmt "%02x" byte
  done

let pp_result ppf = function
  | Ok cs -> pp_hex_le ppf cs
  | Error e -> Format.fprintf ppf "%a" pp_error e

let key_exchange =
  let test ~name d p ~expected =
    ( name,
      `Quick,
      fun () ->
        P256.Dh.key_exchange d p
        |> Format.asprintf "%a" pp_result
        |> Alcotest.check Alcotest.string __LOC__ expected )
  in
  let kp data =
    match P256.Dh.secret_of_octets data with
    | Ok (p, s) -> (p, s)
    | Error _ -> assert false
  in
  let d_a, p_a =
    kp
      (of_hex "200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  and d_b, p_b =
    kp
      (of_hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  in
  [
    test ~name:"b*A" d_b p_a
      ~expected:
        "2e3e4065a62a7f425aaf8aae3d158f367c733300b5002e0b62f4bc6260789e1b";
    test ~name:"a*B" d_a p_b
      ~expected:
        "2e3e4065a62a7f425aaf8aae3d158f367c733300b5002e0b62f4bc6260789e1b";
    test ~name:"a*A" d_a p_a
      ~expected:
        "2ea4e810837da217a5bfd05f01d12459eeda830b6e0dec7f8afa425c5b55c507";
    test ~name:"b*B" d_b p_b
      ~expected:
        "a7666bcc3818472194460f7df22d80a5886da0e1679eac930175ce1ff733c7ca";
  ]

let scalar_mult =
  let test ~n ~scalar ~point ~expected =
    let scalar =
      match P256.Dh.secret_of_octets scalar with
      | Ok (p, _) -> p
      | Error _ -> assert false
    in
    ( Printf.sprintf "Scalar mult (#%d)" n,
      `Quick,
      fun () ->
        P256.Dh.key_exchange scalar point
        |> Format.asprintf "%a" pp_result
        |> Alcotest.check Alcotest.string __LOC__ expected )
  in
  let point =
    of_hex
      "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
  in
  [
    test ~n:0
      ~scalar:
        (of_hex
           "0000000000000000000000000000000000000000000000000000000000000001")
      ~point
      ~expected:
        "96c298d84539a1f4a033eb2d817d0377f240a463e5e6bcf847422ce1f2d1176b";
    test ~n:1
      ~scalar:
        (of_hex
           "0000000000000000000000000000000000000000000000000000000000000002")
      ~point
      ~expected:
        "78996647fc480ba6351bf277e26989c0c31ab5040338528a7e4f038d187bf27c";
    test ~n:2
      ~scalar:
        (of_hex
           "0000000000000000000000000000000000000000000000000000000000000004")
      ~point
      ~expected:
        "5208036b44029350ef965578dbe21f03d02be69e65de2da0bb8fd032354a53e2";
    test ~n:3
      ~scalar:
        (of_hex
           "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346")
      ~point:
        (of_hex
           "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf")
      ~expected:
        "854271e19508bc935ab22b95cd2be13a0e78265f528b658b3219028b900d0253";
    test ~n:4
      ~scalar:
        (of_hex
           "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a")
      ~point:
        (of_hex
           "043cbc1b31b43f17dc200dd70c2944c04c6cb1b082820c234a300b05b7763844c74fde0a4ef93887469793270eb2ff148287da9265b0334f9e2609aac16e8ad503")
      ~expected:
        "ffffffffffffffffffffffffffffffff3022cfeeffffffffffffffffffffff7f";
    test ~n:5
      ~scalar:
        (of_hex
           "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48")
      ~point:
        (of_hex
           "04000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4")
      ~expected:
        "48e82c9b82c88cb9fc2a5cff9e7c41bc4255ff6bd3814538c9b130877c07e4cf";
  ]

let to_ok_or_error = function Ok _ -> Ok () | Error _ as e -> e

let point_validation =
  let test ~name ~x ~y ~expected =
    let scalar =
      match
        P256.Dh.secret_of_octets
          (of_hex
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      with
      | Ok (p, _) -> p
      | _ -> assert false
    in
    let point =
      let s04 = String.make 1 '\004' in
      s04 ^ x ^ y
    in
    ( name,
      `Quick,
      fun () ->
        P256.Dh.key_exchange scalar point
        |> to_ok_or_error
        |> Alcotest.check Testable.ok_or_error __LOC__ expected )
  in
  let zero = String.make 32 '\000' in
  let sb =
    of_hex "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
  in
  [
    test ~name:"Ok"
      ~x:
        (of_hex
           "62d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26")
      ~y:
        (of_hex
           "ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf")
      ~expected:(Ok ());
    test ~name:"P=0"
      ~x:
        (of_hex
           "0000000000000000000000000000000000000000000000000000000000000000")
      ~y:
        (of_hex
           "0000000000000000000000000000000000000000000000000000000000000000")
      ~expected:(Error `Not_on_curve);
    test ~name:"(0, sqrt(b))" ~x:zero ~y:sb ~expected:(Ok ());
    test ~name:"out of range"
      ~x:
        (of_hex
           "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
      ~y:sb ~expected:(Error `Invalid_range);
  ]

let scalar_validation =
  let ign_sec hex =
    match P256.Dh.secret_of_octets (of_hex hex) with
    | Ok _ -> Ok ()
    | Error _ as e -> e
  in
  [
    ( "0",
      `Quick,
      fun () ->
        Alcotest.check Testable.ok_or_error __LOC__ (Error `Invalid_range)
          (ign_sec
             "0000000000000000000000000000000000000000000000000000000000000000")
    );
    ( "1",
      `Quick,
      fun () ->
        Alcotest.check Testable.ok_or_error __LOC__ (Ok ())
          (ign_sec
             "0000000000000000000000000000000000000000000000000000000000000001")
    );
    ( "n-1",
      `Quick,
      fun () ->
        Alcotest.check Testable.ok_or_error __LOC__ (Ok ())
          (ign_sec
             "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550")
    );
    ( "n",
      `Quick,
      fun () ->
        Alcotest.check Testable.ok_or_error __LOC__ (Error `Invalid_range)
          (ign_sec
             "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    );
  ]

let ecdsa_gen () =
  let d =
    of_hex
      "C477F9F6 5C22CCE2 0657FAA5 B2D1D812 2336F851 A508A1ED 04E479C3 4985BF96"
  in
  let p =
    match
      P256.Dsa.pub_of_octets
        (of_hex
           {|04
                  B7E08AFD FE94BAD3 F1DC8C73 4798BA1C 62B3A0AD 1E9EA2A3 8201CD08 89BC7A19
                  3603F747 959DBF7A 4BB226E4 19287290 63ADC7AE 43529E61 B563BBC6 06CC5E09|})
    with
    | Ok a -> a
    | Error _ -> assert false
  in
  let pub =
    match P256.Dsa.priv_of_octets d with
    | Ok p -> P256.Dsa.pub_of_priv p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let pub_eq a b =
    String.equal (P256.Dsa.pub_to_octets a) (P256.Dsa.pub_to_octets b)
  in
  Alcotest.(check bool __LOC__ true (pub_eq pub p))

let ecdsa_sign () =
  let d =
    of_hex
      "C477F9F6 5C22CCE2 0657FAA5 B2D1D812 2336F851 A508A1ED 04E479C3 4985BF96"
  and k =
    of_hex
      "7A1A7E52 797FC8CA AA435D2A 4DACE391 58504BF2 04FBE19F 14DBB427 FAEE50AE"
  and e =
    of_hex
      "A41A41A1 2A799548 211C410C 65D8133A FDE34D28 BDD542E4 B680CF28 99C8A8C4"
  in
  let r =
    of_hex
      "2B42F576 D07F4165 FF65D1F3 B1500F81 E44C316F 1F0B3EF5 7325B69A CA46104F"
  and s =
    of_hex
      "DC42C212 2D6392CD 3E3A993A 89502A81 98C1886F E69D262C 4B329BDB 6B63FAF1"
  in
  let key =
    match P256.Dsa.priv_of_octets d with
    | Ok p -> p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let r', s' = P256.Dsa.sign ~key ~k e in
  Alcotest.(check bool __LOC__ true (String.equal r r' && String.equal s s'))

let ecdsa_verify () =
  let key =
    match
      P256.Dsa.pub_of_octets
        (of_hex
           {|04
                      B7E08AFD FE94BAD3 F1DC8C73 4798BA1C 62B3A0AD 1E9EA2A3 8201CD08 89BC7A19
                      3603F747 959DBF7A 4BB226E4 19287290 63ADC7AE 43529E61 B563BBC6 06CC5E09|})
    with
    | Ok a -> a
    | Error _ -> assert false
  and e =
    of_hex
      "A41A41A1 2A799548 211C410C 65D8133A FDE34D28 BDD542E4 B680CF28 99C8A8C4"
  and r =
    of_hex
      "2B42F576 D07F4165 FF65D1F3 B1500F81 E44C316F 1F0B3EF5 7325B69A CA46104F"
  and s =
    of_hex
      "DC42C212 2D6392CD 3E3A993A 89502A81 98C1886F E69D262C 4B329BDB 6B63FAF1"
  in
  Alcotest.(check bool __LOC__ true (P256.Dsa.verify ~key (r, s) e))

let ecdsa =
  [
    (* from https://csrc.nist.rip/groups/ST/toolkit/documents/Examples/ECDSA_Prime.pdf *)
    ("ECDSA gen", `Quick, ecdsa_gen);
    ("ECDSA sign", `Quick, ecdsa_sign);
    ("ECDSA verify", `Quick, ecdsa_verify);
  ]

let brainpoolp256_ecdsa_gen () =
  let d =
    of_hex "6f836168c0ba509e3a1a9ab9e512ffd4bb70a062e8be6b791c30037edd49f337"
  in
  let p =
    match
      BrainpoolP256.Dsa.pub_of_octets
        (of_hex
           {|04
                  5046988febf1cbe9f0d1b60e9a34f706a0ee9ba7ad58643e13c17c968af97fe3
                  99e111ea496bff192a417899a9f3e8422f6f46e7a7dab3bc675bebbf94eed9a4|})
    with
    | Ok a -> a
    | Error _ -> assert false
  in
  let pub =
    match BrainpoolP256.Dsa.priv_of_octets d with
    | Ok p -> BrainpoolP256.Dsa.pub_of_priv p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let pub_eq a b =
    String.equal
      (BrainpoolP256.Dsa.pub_to_octets a)
      (BrainpoolP256.Dsa.pub_to_octets b)
  in
  Alcotest.(check bool __LOC__ true (pub_eq pub p))

let brainpoolp256_ecdsa_sign () =
  let d =
    of_hex "77ef213686eb279680d57c50750404af064c55f7b21d7406a44ae5204aba1077"
  and k =
    of_hex "895f532869f2185d4c38bc66376a446bfb7aa3748510630c027491367df47fa8"
  and e =
    of_hex "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049"
  in
  let r =
    of_hex "2bd423fa2ea59677ffb58462131083cef9821ed77a51079fad2fad1d88023a83"
  and _s =
    of_hex "413fd3cc9abcf016d3ea635e26c80a199a13ae00c2c9af1f60d970231e9000a5"
  in
  let key =
    match BrainpoolP256.Dsa.priv_of_octets d with
    | Ok p -> p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let r', _s' = BrainpoolP256.Dsa.sign ~key ~k e in
  Alcotest.(check string __LOC__ r r')

let brainpoolp256_ecdsa_verify () =
  let key =
    match
      BrainpoolP256.Dsa.pub_of_octets
        (of_hex
           {|04
                      19e8be13f180c669aa31b31f931d80423f8a9d6c5adb80de93af2bd3010c14a5
                      7a004f2c2be9c53ac6bc4254472c8a91749512b38e2c06f710d1bbfede742afa|})
    with
    | Ok a -> a
    | Error _ -> assert false
  and e =
    of_hex "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049"
  and r =
    of_hex "3dab68bcf22882bdcc5ddec244f0b54119271570d80e467818c0de427a2c6962"
  and s =
    of_hex "84223af79041e0d7e21c1289aa108f9a4c77d69ce6c4cc7da22532570db95670"
  in
  Alcotest.(check bool __LOC__ true (BrainpoolP256.Dsa.verify ~key (r, s) e))

let brainpoolp256_ecdsa =
  [
    ("ECDSA gen", `Quick, brainpoolp256_ecdsa_gen);
    ("ECDSA sign", `Quick, brainpoolp256_ecdsa_sign);
    ("ECDSA verify", `Quick, brainpoolp256_ecdsa_verify);
  ]

let brainpoolp384_ecdsa_gen () =
  let d =
    of_hex
      "70b3653970f00be16919c4ac548693ad1f27a7d5db2e54b3660e61930abc7a24d8c0f5eb9896ce000c0b8491a1ced282"
  in
  let p =
    match
      BrainpoolP384.Dsa.pub_of_octets
        (of_hex
           {|04
                  796166fae3742405d0ba327cfc6b73232e046712f3f5623745c5d68292fef3cafacd79cbae8265fd0c13988d7774e1aa
                  04ae9f697f6bdf5cd3629f8cf44405010488f6f3ebf7ea88babaa7469643bb9e4ee11f70a5f4f3b80730d89a4e8847e6|})
    with
    | Ok a -> a
    | Error _ -> assert false
  in
  let pub =
    match BrainpoolP384.Dsa.priv_of_octets d with
    | Ok p -> BrainpoolP384.Dsa.pub_of_priv p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let pub_eq a b =
    String.equal
      (BrainpoolP384.Dsa.pub_to_octets a)
      (BrainpoolP384.Dsa.pub_to_octets b)
  in
  Alcotest.(check bool __LOC__ true (pub_eq pub p))

let brainpoolp384_ecdsa_sign () =
  let d =
    of_hex
      "2634a4c7ab5b2b3ef6c81ab4f0de9ec3fdce62ef1c0756ff3501adf4f0b118d5cc2ccf57175d093c57aee282e0a18c1d"
  and k =
    of_hex
      "6a47ae7d54e9507d2eaf31d06d6e4319bdfdf068c8b1c746c838b2ae5912ff3b5a19a0c457e8a2736fc0ee245d49d2fd"
  and e =
    of_hex
      "8f5e4d4e4972d73670383f94f727e58e683b6397b284c6493fab2754882f5e0847a359a67df5b6c91d3858a81e42e252"
  in
  let r =
    of_hex
      "72f0aa458f158a7a77954647d1f2926cf798885679506e49fb0ba6f8f786abeda0f8f41e2acf052d31cd19cf08464ced"
  and s =
    of_hex
      "83fda4ab4b4513562cd9815aba60c6d0daaed84e57a54907ec3c1c74dc6126b57b7e37504ebe6cbfe05b9a8ac763f42e"
  in
  let key =
    match BrainpoolP384.Dsa.priv_of_octets d with
    | Ok p -> p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let r', s' = BrainpoolP384.Dsa.sign ~key ~k e in
  Alcotest.(check bool __LOC__ true (String.equal r r' && String.equal s s'))

let brainpoolp384_ecdsa_verify () =
  let key =
    match
      BrainpoolP384.Dsa.pub_of_octets
        (of_hex
           {|04
                      83a26ae2ae4c241d101bc03f74aa1f78e8559633394788ac1e193fa3b5ec8d1f05e737b2e454e2375b018cf06ef9e9a4
                      57ab9b4414bf013e9f8b4e8c5801ee52eff820fb27ddf5d7ad1574944387d779cac830b402cfd5c207fe2053583af458|})
    with
    | Ok a -> a
    | Error _ -> assert false
  and e =
    of_hex
      "8f5e4d4e4972d73670383f94f727e58e683b6397b284c6493fab2754882f5e0847a359a67df5b6c91d3858a81e42e252"
  and r =
    of_hex
      "839abac0eb2609b4c35260e7be9f0a86ef752e5035bf7acda64a00c3ff90fcee7ddf02fd0356b4cd151427d0ecf2b6dd"
  and s =
    of_hex
      "3181eb62262eab42290333c85e64d6923a88048af95f8db8fe2d0dcccb22bd4e28a64120766b46bee610e60bed5ca5ee"
  in
  Alcotest.(check bool __LOC__ true (BrainpoolP384.Dsa.verify ~key (r, s) e))

let brainpoolp384_ecdsa =
  [
    ("ECDSA gen", `Quick, brainpoolp384_ecdsa_gen);
    ("ECDSA sign", `Quick, brainpoolp384_ecdsa_sign);
    ("ECDSA verify", `Quick, brainpoolp384_ecdsa_verify);
  ]

let brainpoolp512_ecdsa_gen () =
  let d =
    of_hex
      "89e7f8007b0e30d3b2df95b55463658fce1db365ad115fa5f73766a75f6f08b91982086a1eabfd9da4937a6e90e470c18e0f4b79981a31ae482ac908d5115b36"
  in
  let p =
    match
      BrainpoolP512.Dsa.pub_of_octets
        (of_hex
           {|04
                  59ac5d9e0575b8ab6bfa14de0c9b5b07d76ca2325fd8469d32b248314e8ebcc663c07ee2065ceb38cb784e26e09bdfc08dfeaa215967a168def9577162a1c1c4
                  000a6fb13d5a2ef437154f7c617b6396f00d5ba7fad5f23e33e6990167d72c775b61858f52801590e12551e8d35c4f998c10187c378e502866c8bb41f348bd59|})
    with
    | Ok a -> a
    | Error _ -> assert false
  in
  let pub =
    match BrainpoolP512.Dsa.priv_of_octets d with
    | Ok p -> BrainpoolP512.Dsa.pub_of_priv p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let pub_eq a b =
    String.equal
      (BrainpoolP512.Dsa.pub_to_octets a)
      (BrainpoolP512.Dsa.pub_to_octets b)
  in
  Alcotest.(check bool __LOC__ true (pub_eq pub p))

let brainpoolp512_ecdsa_sign () =
  let d =
    of_hex
      "463a29fcce4907dd20d8e44402948f23c2906f956a98a17db5e6e51aa6f0c10a7f49567800b6b548101ee79d921c311f89c8329f4d7dbca4853a06612dd5125b"
  and k =
    of_hex
      "5901efdb525257eb1afa30cd235bd9bc3b30806947e78dc1e6f7060042a0f283e8086078aa804af0036eac385cd8f45531d8a29f3da6a7fa5549f5275879f1da"
  and e =
    of_hex
      "39ca7ce9ecc69f696bf7d20bb23dd1521b641f806cc7a6b724aaa6cdbffb3a023ff98ae73225156b2c6c9ceddbfc16f5453e8fa49fc10e5d96a3885546a46ef4"
  in
  let r =
    of_hex
      "0104960d88d6fd09be52b8dbcc83af4e2a9bd82d4f7408408835022415ea72688bd416b4fec04d56abc5a966801f6c6fccb7223f990a11ca7c509d8f2ac3098d"
  and s =
    of_hex
      "40a80fbb9ac8e296c79f2e97a3f9b7a8bb181d3a8548ea72d817fa580a4ae23a5cca1c7501333f98d64fb08791aac1fbd2c791c2051d321e0925bbab8e49b268"
  in
  let key =
    match BrainpoolP512.Dsa.priv_of_octets d with
    | Ok p -> p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let r', s' = BrainpoolP512.Dsa.sign ~key ~k e in
  Alcotest.(check bool __LOC__ true (String.equal r r' && String.equal s s'))

let brainpoolp512_ecdsa_verify () =
  let key =
    match
      BrainpoolP512.Dsa.pub_of_octets
        (of_hex
           {|04
                      19cd31021886560ad25b61bb8dc60b3a3c4d80bee18cc1766692755457c4e0cf8bdc1461591006cc5be370987e2c99e3a0fd4c86979e25f15363e1566fa89343
                      23cee843f886d3e57b0f4752e83342666e3413e60411400bc4eb23e0a4ae1fbda9069c8b843c9c8f3217c126c5d09070e4288d5809640131c396294ad771ded1|})
    with
    | Ok a -> a
    | Error _ -> assert false
  and e =
    of_hex
      "39ca7ce9ecc69f696bf7d20bb23dd1521b641f806cc7a6b724aaa6cdbffb3a023ff98ae73225156b2c6c9ceddbfc16f5453e8fa49fc10e5d96a3885546a46ef4"
  and r =
    of_hex
      "60a96245d98dc4891068a775b2ddafc88fa25d287ae8b12498da5915ee78daed0d332139f10dd1a73726324a5683445605943b87dd0293ecc902fd28065954ff"
  and s =
    of_hex
      "558d15a54bac0596554fb3240e9d68f0da8ec03a652a9d039509de89e5c5f5480ee591317be6aaa2b413e8427692a98c14602747b92f7b35ed0416be2cdfe7c5"
  in
  Alcotest.(check bool __LOC__ true (BrainpoolP512.Dsa.verify ~key (r, s) e))

let brainpoolp512_ecdsa =
  [
    ("ECDSA gen", `Quick, brainpoolp512_ecdsa_gen);
    ("ECDSA sign", `Quick, brainpoolp512_ecdsa_sign);
    ("ECDSA verify", `Quick, brainpoolp512_ecdsa_verify);
  ]

let secp256k1_ecdsa_gen () =
  let d =
    of_hex "42202a98374f6dca439c0af88140e41f8eced3062682ec7f9fc8ac9ea83c7cb2"
  in
  let p =
    match
      P256k1.Dsa.pub_of_octets
        (of_hex
           {|04
                  131ca4e5811267fa90fc631d6298c2d7a4ecccc45cc60d378e0660b61f82fe8d
                  cf5acf8ed3e0bbf735308cc415604bd34ab8f7fc8b4a22741117a7fbc72a7949|})
    with
    | Ok a -> a
    | Error _ -> assert false
  in
  let pub =
    match P256k1.Dsa.priv_of_octets d with
    | Ok p -> P256k1.Dsa.pub_of_priv p
    | Error _ -> Alcotest.fail "couldn't decode private key"
  in
  let pub_eq a b =
    String.equal (P256k1.Dsa.pub_to_octets a) (P256k1.Dsa.pub_to_octets b)
  in
  Alcotest.(check bool __LOC__ true (pub_eq pub p))

let secp256k1_ecdsa_verify () =
  let key =
    match
      P256k1.Dsa.pub_of_octets
        (of_hex
           {|04
                      779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd
                      e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f|})
    with
    | Ok a -> a
    | Error _ -> assert false
  and e =
    of_hex "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a"
  and r =
    of_hex "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795"
  and s =
    of_hex "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"
  in
  Alcotest.(check bool __LOC__ true (P256k1.Dsa.verify ~key (r, s) e))

let secp256k1_ecdsa =
  [
    ("ECDSA gen", `Quick, secp256k1_ecdsa_gen);
    ("ECDSA verify", `Quick, secp256k1_ecdsa_verify);
  ]

let secp256k1_ecdsa_sign =
  let case ?k ~h ~d ~r ~s () =
    let msg = of_hex h in
    let key =
      match P256k1.Dsa.priv_of_octets (of_hex d) with
      | Ok p -> p
      | Error _ -> Alcotest.fail "couldn't decode private key"
    in
    let k = Option.map (fun x -> of_hex x) k in
    let r', s' = P256k1.Dsa.sign ~key ?k msg in
    Alcotest.(check string "r correct" (of_hex r) r');
    Alcotest.(check string "s correct" (of_hex s) s')
  in
  let cases =
    [
      case ~d:"ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f"
        ~h:"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a"
        ~k:"49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a"
        ~r:"241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795"
        ~s:"021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e";
      case ~d:"0000000000000000000000000000000000000000000000000000000000000001"
        ~h:"0000000000000000000000000000000000000000000000000000000000000001"
        ~r:"6673FFAD2147741F04772B6F921F0BA6AF0C1E77FC439E65C36DEDF4092E8898"
        ~s:"B3E568E9AD1F52577FEDF107FDA18F5EBB8E5C220BADF23532BF6FBCC67FB4B8";
      case ~d:"D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759"
        ~h:"3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F"
        ~k:"DC87789C4C1A09C97FF4DE72C0D0351F261F10A2B9009C80AEE70DDEC77201A0"
        ~r:"A5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089"
        ~s:"BC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB";
      case ~d:"292efd39a4e53efb580ba4ba3e5bb47d6e7463cddab04335aa061d554c74bcc8"
        ~h:"db72ce6fea09d442b4f31535df0a97f6c21d42be23e48b6bd088018cce75c3dd"
        ~k:"654035b5acae79fff464d77b114f93b1b84caec325fdf7f3f050cc659245bfaa"
        ~r:"9ae57e4e4eca88939152ee38a07860ae03cff51d84708eeceabc70d615b7d31b"
        ~s:"808cddd65562c77c81a1c8d45e229f53edf19864069f8d62c3c3fa1f8c8c3c66";
      case ~d:"0deea9b194ea6d4f1b5de6b5468a80e0478ae0f03f4fce59bafe51e35763388e"
        ~h:"a6442404392a831b481845c49d6009957ebd611bd366f4dd15f7578daef21678"
        ~k:"e3253150b94868a179e34f819ec42cf14eb367d1685ee528e51f1dd031eabb29"
        ~r:"5c5ab3fc0063da962440285f0df3a2cf031947920c990ff97b8a210a531d39a0"
        ~s:"b45a4aff7d60bbaa1602a81d5c2f09d3d651344cc6c08723fd40ffaf79ba1c6a";
      case ~d:"634ccc8392372f66e9086c540f868a9ce93d5452aa1e0e1a5448ed15f4252c85"
        ~h:"22a634e0114561e05c6e333e5bab22fbfe77e1691305fceae6697278a665447c"
        ~k:"4a49d24c7b41392f8fd90ec5b49bdb949048ee0f55ccb35753ea8a38c4a942fb"
        ~r:"c7700bcd35c0f82ca14c1c3d5a3b3b444a187593ebafcd5ec401f8a49b024553"
        ~s:"3dbd18cf865697dfa6733dd0676063b769a1fd94f2d2a3b92e2680d4291c6128";
      case ~d:"576314d4c6ad800d5726b0cdd0e6e9429568ff96ffbd83aea38f6c9a3e6409d3"
        ~h:"a168c68532a902215d7b3551bb1c39cf79df84d6bdc469b833bf72d4803d25d7"
        ~k:"2e6511edb60aa7966007b383fa6ad9d0e6a54620182f0269509116d3e5e8f5af"
        ~r:"41ee804ccacefd441972ca8d92c72c4b361c39eee5cb1f474de7f09d4b83f212"
        ~s:"1614e19bab04de9ef3658bf6702d599bb518f598a122e1df92160bd5584dd42b";
    ]
  in
  List.mapi (fun i c -> ("ECDSA sign " ^ string_of_int i, `Quick, c)) cases

let secp256k1_bip340_sign =
  let open P256k1.Bip340 in
  let secp256k1_bip340_gen () =
    let key, p = generate () in
    let pub = P256k1.Bip340.pub_of_priv key in
    Alcotest.(check string "generate" (pub_to_octets pub) (pub_to_octets p));
    let msg = "42" in
    let r, s = sign ~key msg in
    Alcotest.(check bool "verify" true (verify ~key:p (r, s) msg))
  in
  let case ~d ~x ~k ~h ~r ~s ~v () =
    let msg = of_hex h in
    let r, s = (of_hex r, of_hex s) in
    let pub =
      match pub_of_octets (of_hex x) with
      | Error _ -> Alcotest.fail "couldn't decode public key"
      | Ok x -> x
    in
    if d <> "" then (
      let key =
        match priv_of_octets (of_hex d) with
        | Ok p -> p
        | Error _ -> Alcotest.fail "couldn't decode private key"
      in
      let pub' = pub_to_octets (pub_of_priv key) in
      Alcotest.(check string "pub correct" (pub_to_octets pub) pub');
      let aux_rand = of_hex k in
      let r', s' = P256k1.Bip340.sign ~key ~aux_rand msg in
      Alcotest.(check string "r correct" r r');
      Alcotest.(check string "s correct" s s'));
    let verify = P256k1.Bip340.(verify ~key:pub (r, s) msg) in
    Alcotest.(check bool "verified" v verify)
  in
  (* test vectors from
     https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv *)
  let cases =
    [
      ( case
          ~d:"0000000000000000000000000000000000000000000000000000000000000003"
          ~x:"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
          ~k:"0000000000000000000000000000000000000000000000000000000000000000"
          ~h:"0000000000000000000000000000000000000000000000000000000000000000"
          ~r:"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
          ~s:"25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
          ~v:true,
        "" );
      ( case
          ~d:"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:"0000000000000000000000000000000000000000000000000000000000000001"
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
          ~s:"8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
          ~v:true,
        "" );
      ( case
          ~d:"C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
          ~x:"DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
          ~k:"C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"
          ~h:"7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"
          ~r:"5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
          ~s:"AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"
          ~v:true,
        "" );
      ( case
          ~d:"0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"
          ~x:"25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"
          ~k:"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
          ~h:"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
          ~r:"7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
          ~s:"97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"
          ~v:true,
        "test fails if msg is reduced modulo p or n" );
      ( case ~d:""
          ~x:"D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"
          ~k:""
          ~h:"4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"
          ~r:"00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63"
          ~s:"76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"
          ~v:true,
        "" );
      ( case ~d:""
          ~x:"EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
          ~s:"69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
          ~v:false,
        "public key not on the curve" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
          ~s:"3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"
          ~v:false,
        "has_even_y(R) is false" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F"
          ~s:"28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"
          ~v:false,
        "negated message" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
          ~s:"961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"
          ~v:false,
        "negated s value" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"0000000000000000000000000000000000000000000000000000000000000000"
          ~s:"123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051"
          ~v:false,
        "sG - eP is infinite. Test fails in single verification if \
         has_even_y(inf) is defined as true and x(inf) as 0" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"0000000000000000000000000000000000000000000000000000000000000001"
          ~s:"7615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"
          ~v:false,
        "sG - eP is infinite. Test fails in single verification if \
         has_even_y(inf) is defined as true and x(inf) as 1" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D"
          ~s:"69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
          ~v:false,
        "sig[0:32] is not an X coordinate on the curve" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
          ~s:"69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
          ~v:false,
        "sig[0:32] is equal to field size" );
      ( case ~d:""
          ~x:"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
          ~s:"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
          ~v:false,
        "sig[32:64] is equal to curve order" );
      ( case ~d:""
          ~x:"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
          ~k:""
          ~h:"243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          ~r:"6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
          ~s:"69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
          ~v:false,
        "public key is not a valid X coordinate because it exceeds the field \
         size" );
      ( case
          ~d:"0340034003400340034003400340034003400340034003400340034003400340"
          ~x:"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
          ~k:"0000000000000000000000000000000000000000000000000000000000000000"
          ~h:""
          ~r:"71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF"
          ~s:"6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"
          ~v:true,
        "message of size 0 (added 2022-12)" );
      ( case
          ~d:"0340034003400340034003400340034003400340034003400340034003400340"
          ~x:"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
          ~k:"0000000000000000000000000000000000000000000000000000000000000000"
          ~h:"11"
          ~r:"08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303"
          ~s:"EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF"
          ~v:true,
        "message of size 1 (added 2022-12)" );
      ( case
          ~d:"0340034003400340034003400340034003400340034003400340034003400340"
          ~x:"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
          ~k:"0000000000000000000000000000000000000000000000000000000000000000"
          ~h:"0102030405060708090A0B0C0D0E0F1011"
          ~r:"5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370"
          ~s:"C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5"
          ~v:true,
        "message of size 17 (added 2022-12)" );
      ( case
          ~d:"0340034003400340034003400340034003400340034003400340034003400340"
          ~x:"778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
          ~k:"0000000000000000000000000000000000000000000000000000000000000000"
          ~h:
            "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
          ~r:"403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8"
          ~s:"585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367"
          ~v:true,
        "message of size 100 (added 2022-12)" );
    ]
  in
  let l =
    List.mapi
      (fun i (c, n) ->
        ((if n = "" then "BIP-340 case " ^ string_of_int i else n), `Quick, c))
      cases
  in
  ("BIP-340 gen/sign/verify", `Quick, secp256k1_bip340_gen) :: l

let ecdsa_rfc6979_p256 =
  (* A.2.5 - P 256 *)
  let priv, pub =
    let data =
      of_hex "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
    in
    match P256.Dsa.priv_of_octets data with
    | Ok p -> (p, P256.Dsa.pub_of_priv p)
    | Error _ -> assert false
  in
  let pub_rfc () =
    let fst = String.make 1 '\004' in
    let ux =
      of_hex "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
    and uy =
      of_hex "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
    in
    match P256.Dsa.pub_of_octets (fst ^ ux ^ uy) with
    | Ok p ->
        let pub_eq =
          String.equal (P256.Dsa.pub_to_octets pub) (P256.Dsa.pub_to_octets p)
        in
        Alcotest.(check bool __LOC__ true pub_eq)
    | Error _ -> Alcotest.fail "bad public key"
  in
  let pub_key_compression () =
    let _, pub = P256.Dsa.generate () in
    let compressed = P256.Dsa.pub_to_octets ~compress:true pub in
    let decompressed = P256.Dsa.pub_of_octets compressed in
    let comparison =
      match decompressed with
      | Ok decompressed ->
          let p1 = P256.Dsa.pub_to_octets pub in
          let p2 = P256.Dsa.pub_to_octets decompressed in
          String.equal p1 p2
      | Error _ -> false
    in
    Alcotest.(check bool __LOC__ true comparison)
  in
  let case (type a) (hash : a Digestif.hash) ~message ~k ~r ~s () =
    let msg =
      let h = Digestif.(digest_string hash message |> to_raw_string hash) in
      String.sub h 0 (min (String.length h) 32)
    and k = of_hex k in
    let k' =
      let module H = (val Digestif.module_of hash) in
      let module K = P256.Dsa.K_gen (H) in
      K.generate ~key:priv msg
    in
    Alcotest.(check bool __LOC__ true (String.equal k k'));
    let sig_eq (r', s') =
      String.equal (of_hex r) r' && String.equal (of_hex s) s'
    in
    let sig' = P256.Dsa.sign ~key:priv ~k msg in
    Alcotest.(check bool __LOC__ true (sig_eq sig'))
  in
  let cases =
    [
      case Digestif.sha1 ~message:"sample"
        ~k:"882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4"
        ~r:"61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32"
        ~s:"6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB";
      case Digestif.sha224 ~message:"sample"
        ~k:"103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473"
        ~r:"53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F"
        ~s:"B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C";
      case Digestif.sha256 ~message:"sample"
        ~k:"A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"
        ~r:"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
        ~s:"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
      case Digestif.sha384 ~message:"sample"
        ~k:"09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4"
        ~r:"0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719"
        ~s:"4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954";
      case Digestif.sha512 ~message:"sample"
        ~k:"5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5"
        ~r:"8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00"
        ~s:"2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE";
      case Digestif.sha1 ~message:"test"
        ~k:"8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2E"
        ~r:"0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89"
        ~s:"01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1";
      case Digestif.sha224 ~message:"test"
        ~k:"669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7"
        ~r:"C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692"
        ~s:"C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D";
      case Digestif.sha256 ~message:"test"
        ~k:"D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0"
        ~r:"F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"
        ~s:"019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083";
      case Digestif.sha384 ~message:"test"
        ~k:"16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8"
        ~r:"83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6"
        ~s:"8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C";
      case Digestif.sha512 ~message:"test"
        ~k:"6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F"
        ~r:"461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04"
        ~s:"39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55";
    ]
  in
  ("public key matches", `Quick, pub_rfc)
  :: ("public key compression and decompression", `Quick, pub_key_compression)
  :: List.mapi
       (fun i c -> ("RFC 6979 A.2.5 " ^ string_of_int i, `Quick, c))
       cases

let ecdsa_rfc6979_p384 =
  (* A.2.6 - P 384 *)
  let priv, pub =
    let data =
      of_hex
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"
    in
    match P384.Dsa.priv_of_octets data with
    | Ok p -> (p, P384.Dsa.pub_of_priv p)
    | Error _ -> assert false
  in
  let pub_rfc () =
    let fst = String.make 1 '\004' in
    let ux =
      of_hex
        "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
    and uy =
      of_hex
        "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
    in
    match P384.Dsa.pub_of_octets (fst ^ ux ^ uy) with
    | Ok p ->
        let pub_eq =
          String.equal (P384.Dsa.pub_to_octets pub) (P384.Dsa.pub_to_octets p)
        in
        Alcotest.(check bool __LOC__ true pub_eq)
    | Error _ -> Alcotest.fail "bad public key"
  in
  let pub_key_compression () =
    let _, pub = P384.Dsa.generate () in
    let compressed = P384.Dsa.pub_to_octets ~compress:true pub in
    let decompressed = P384.Dsa.pub_of_octets compressed in
    let comparison =
      match decompressed with
      | Ok decompressed ->
          let p1 = P384.Dsa.pub_to_octets pub in
          let p2 = P384.Dsa.pub_to_octets decompressed in
          String.equal p1 p2
      | Error _ -> false
    in
    Alcotest.(check bool __LOC__ true comparison)
  in
  let case (type a) (hash : a Digestif.hash) ~message ~k ~r ~s () =
    let msg =
      let h = Digestif.(digest_string hash message |> to_raw_string hash) in
      String.sub h 0 (min (String.length h) 48)
    and k = of_hex k in
    let k' =
      let module H = (val Digestif.module_of hash) in
      let module K = P384.Dsa.K_gen (H) in
      K.generate ~key:priv msg
    in
    Alcotest.(check bool __LOC__ true (String.equal k k'));
    let sig_eq (r', s') =
      String.equal (of_hex r) r' && String.equal (of_hex s) s'
    in
    let sig' = P384.Dsa.sign ~key:priv ~k msg in
    Alcotest.(check bool __LOC__ true (sig_eq sig'))
  in
  let cases =
    [
      case Digestif.sha1 ~message:"sample"
        ~k:
          "4471EF7518BB2C7C20F62EAE1C387AD0C5E8E470995DB4ACF694466E6AB09663\n\
          \       0F29E5938D25106C3C340045A2DB01A7"
        ~r:
          "EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA3\n\
          \       7B9BA002899F6FDA3A4A9386790D4EB2"
        ~s:
          "A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF\n\
          \       26F49CA031D4857570CCB5CA4424A443";
      case Digestif.sha224 ~message:"sample"
        ~k:
          "A4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB\n\
          \       8083EE4E3C45B06A5899EA56C51B5879"
        ~r:
          "42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366\n\
          \       450F76EE3DE43F5A125333A6BE060122"
        ~s:
          "9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E483\n\
          \       4C082C03D83028EFBF93A3C23940CA8D";
      case Digestif.sha256 ~message:"sample"
        ~k:
          "180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E\n\
          \       375572342863C899F9F2EDF9747A9B60"
        ~r:
          "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33\n\
          \       BDE1E888E63355D92FA2B3C36D8FB2CD"
        ~s:
          "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEB\n\
          \       EFDC63ECCD1AC42EC0CB8668A4FA0AB0";
      case Digestif.sha384 ~message:"sample"
        ~k:
          "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA\n\
          \       2907E3E83BA95368623B8C4686915CF9"
        ~r:
          "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\n\
          \       81A648152E44ACF96E36DD1E80FABE46"
        ~s:
          "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F\n\
          \       A329C145786E679E7B82C71A38628AC8";
      case Digestif.sha512 ~message:"sample"
        ~k:
          "92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331\n\
          \       A4E966532593A52980D0E3AAA5E10EC3"
        ~r:
          "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799C\n\
          \       FE30F35CC900056D7C99CD7882433709"
        ~s:
          "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112\n\
          \       DC7CC3EF3446DEFCEB01A45C2667FDD5";
      case Digestif.sha1 ~message:"test"
        ~k:
          "66CC2C8F4D303FC962E5FF6A27BD79F84EC812DDAE58CF5243B64A4AD8094D47\n\
          \       EC3727F3A3C186C15054492E30698497"
        ~r:
          "4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F7789A8B8E43D0678\n\
          \       ACD9D29876DAF46638645F7F404B11C7"
        ~s:
          "D5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8C4B7186201A29916\n\
          \       95BA1C84541327E966FA7B50F7382282";
      case Digestif.sha224 ~message:"test"
        ~k:
          "18FA39DB95AA5F561F30FA3591DC59C0FA3653A80DAFFA0B48D1A4C6DFCBFF6E\n\
          \       3D33BE4DC5EB8886A8ECD093F2935726"
        ~r:
          "E8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE888FC5BF954B5E624\n\
          \       64A9A817C47FF78B8C11066B24080E72"
        ~s:
          "07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3286B2BD43FA8C614\n\
          \       1C53EA5ABEF0D8231077A04540A96B66";
      case Digestif.sha256 ~message:"test"
        ~k:
          "0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FA\n\
          \       A48DD070BA79921A3457ABFF2D630AD7"
        ~r:
          "6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559\n\
          \       F918EEDAF2293BE5B475CC8F0188636B"
        ~s:
          "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D\n\
          \       51AB373F9845C0514EEFB14024787265";
      case Digestif.sha384 ~message:"test"
        ~k:
          "015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092AD\n\
          \       A71F4A459BC0DA98ADB95837DB8312EA"
        ~r:
          "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB\n\
          \       0542A7F0812998DA8F1DD3CA3CF023DB"
        ~s:
          "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E0\n\
          \       6A739F040649A667BF3B828246BAA5A5";
      case Digestif.sha512 ~message:"test"
        ~k:
          "3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE\n\
          \       0E2CC8A136036DC4B9C00E6888F66B6C"
        ~r:
          "A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D0\n\
          \       6FB6495CD21B4B6E340FC236584FB277"
        ~s:
          "976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B22463\n\
          \       4A2092CD3792E0159AD9CEE37659C736";
    ]
  in
  ("public key matches", `Quick, pub_rfc)
  :: ("public key compression and decompression", `Quick, pub_key_compression)
  :: List.mapi
       (fun i c -> ("RFC 6979 A.2.6 " ^ string_of_int i, `Quick, c))
       cases

let ecdsa_rfc6979_p521 =
  (* A.2.7 - P 521 *)
  let of_h b = of_hex (String.make 1 '0' ^ b) in
  let priv, pub =
    let data =
      of_h
        "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C\n\
        \         \
         AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83\n\
        \         538"
    in
    match P521.Dsa.priv_of_octets data with
    | Ok p -> (p, P521.Dsa.pub_of_priv p)
    | Error _ -> assert false
  in
  let pub_rfc () =
    let fst = String.make 1 '\004' in
    let ux =
      of_h
        "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3\n\
        \         \
         71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502\n\
        \         3A4"
    and uy =
      of_h
        "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2\n\
        \         \
         8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF\n\
        \         CF5"
    in
    match P521.Dsa.pub_of_octets (fst ^ ux ^ uy) with
    | Ok p ->
        let pub_eq =
          String.equal (P521.Dsa.pub_to_octets pub) (P521.Dsa.pub_to_octets p)
        in
        Alcotest.(check bool __LOC__ true pub_eq)
    | Error _ -> Alcotest.fail "bad public key"
  in
  let pub_key_compression () =
    let _, pub = P521.Dsa.generate () in
    let compressed = P521.Dsa.pub_to_octets ~compress:true pub in
    let decompressed = P521.Dsa.pub_of_octets compressed in
    let comparison =
      match decompressed with
      | Ok decompressed ->
          let p1 = P521.Dsa.pub_to_octets pub in
          let p2 = P521.Dsa.pub_to_octets decompressed in
          String.equal p1 p2
      | Error _ -> false
    in
    Alcotest.(check bool __LOC__ true comparison)
  in
  let case (type a) (hash : a Digestif.hash) ~message ~k ~r ~s () =
    let msg = Digestif.(digest_string hash message |> to_raw_string hash)
    and k = of_h k in
    let k' =
      let module H = (val Digestif.module_of hash) in
      let module K = P521.Dsa.K_gen (H) in
      K.generate ~key:priv msg
    in
    Alcotest.(check bool __LOC__ true (String.equal k k'));
    let sig_eq (r', s') =
      String.equal (of_h r) r' && String.equal (of_h s) s'
    in
    let sig' = P521.Dsa.sign ~key:priv ~k msg in
    Alcotest.(check bool __LOC__ true (sig_eq sig'))
  in
  let cases =
    [
      case Digestif.sha1 ~message:"sample"
        ~k:
          "089C071B419E1C2820962321787258469511958E80582E95D8378E0C2CCDB3CB\n\
          \       \
           42BEDE42F50E3FA3C71F5A76724281D31D9C89F0F91FC1BE4918DB1C03A5838D\n\
          \       0F9"
        ~r:
          "0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910\n\
          \       \
           FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D\n\
          \       75D"
        ~s:
          "0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D\n\
          \       \
           5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5\n\
          \       D16";
      case Digestif.sha224 ~message:"sample"
        ~k:
          "121415EC2CD7726330A61F7F3FA5DE14BE9436019C4DB8CB4041F3B54CF31BE0\n\
          \       \
           493EE3F427FB906393D895A19C9523F3A1D54BB8702BD4AA9C99DAB2597B9211\n\
          \       3F3"
        ~r:
          "1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A3\n\
          \       \
           0715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2E\n\
          \       D2E"
        ~s:
          "050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17B\n\
          \       \
           A41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B\n\
          \       41F";
      case Digestif.sha256 ~message:"sample"
        ~k:
          "0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C3257576\n\
          \       \
           1793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E\n\
          \       1A0"
        ~r:
          "1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659\n\
          \       \
           D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E\n\
          \       1A7"
        ~s:
          "04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916\n\
          \       \
           E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7E\n\
          \       CFC";
      case Digestif.sha384 ~message:"sample"
        ~k:
          "1546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FF\n\
          \       \
           AD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4\n\
          \       211"
        ~r:
          "1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4\n\
          \       \
           B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67\n\
          \       451"
        ~s:
          "1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5\n\
          \       \
           FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65\n\
          \       D61";
      case Digestif.sha512 ~message:"sample"
        ~k:
          "1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F1019\n\
          \       \
           8B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBF\n\
          \       FD3"
        ~r:
          "0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1\n\
          \       \
           74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37\n\
          \       7FA"
        ~s:
          "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2\n\
          \       \
           82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A\n\
          \       67A";
      case Digestif.sha1 ~message:"test"
        ~k:
          "0BB9F2BF4FE1038CCF4DABD7139A56F6FD8BB1386561BD3C6A4FC818B20DF5DD\n\
          \       \
           BA80795A947107A1AB9D12DAA615B1ADE4F7A9DC05E8E6311150F47F5C57CE8B\n\
          \       222"
        ~r:
          "13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0\n\
          \       \
           693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0\n\
          \       367"
        ~s:
          "1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90\n\
          \       \
           F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC91679\n\
          \       7FF";
      case Digestif.sha224 ~message:"test"
        ~k:
          "040D09FCF3C8A5F62CF4FB223CBBB2B9937F6B0577C27020A99602C25A011369\n\
          \       \
           87E452988781484EDBBCF1C47E554E7FC901BC3085E5206D9F619CFF07E73D6F\n\
          \       706"
        ~r:
          "1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086\n\
          \       \
           BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE1\n\
          \       7FB"
        ~s:
          "177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5\n\
          \       \
           BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD51\n\
          \       9A4";
      case Digestif.sha256 ~message:"test"
        ~k:
          "01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E84384\n\
          \       \
           1AF09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909\n\
          \       258"
        ~r:
          "00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D807104\n\
          \       \
           2EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656\n\
          \       AA8"
        ~s:
          "0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9\n\
          \       \
           FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694\n\
          \       E86";
      case Digestif.sha384 ~message:"test"
        ~k:
          "1F1FC4A349A7DA9A9E116BFDD055DC08E78252FF8E23AC276AC88B1770AE0B5D\n\
          \       \
           CEB1ED14A4916B769A523CE1E90BA22846AF11DF8B300C38818F713DADD85DE0\n\
          \       C88"
        ~r:
          "14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C\n\
          \       \
           89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF60755\n\
          \       78C"
        ~s:
          "133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0E\n\
          \       \
           D94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B\n\
          \       979";
      case Digestif.sha512 ~message:"test"
        ~k:
          "16200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1\n\
          \       \
           B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC\n\
          \       56D"
        ~r:
          "13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10\n\
          \       \
           CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47E\n\
          \       E6D"
        ~s:
          "1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78\n\
          \       \
           A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4D\n\
          \       CE3";
    ]
  in
  ("public key matches", `Quick, pub_rfc)
  :: ("public key compression and decompression", `Quick, pub_key_compression)
  :: List.mapi
       (fun i c -> ("RFC 6979 A.2.7 " ^ string_of_int i, `Quick, c))
       cases

let p521_regression () =
  let key =
    of_hex
      "04 01 e4 f8 8a 40 3d fe  2f 65 a0 20 50 01 9b 87\n\
       86 2c 30 2f 64 58 de 68  63 ab 92 72 88 04 c6 20\n\
       7b 6f 9a 52 95 2d ff c7  80 df 50 44 b1 c4 91 e3\n\
       a7 65 39 e6 9c cf ed d2  2a eb 47 84 ea 0f 3d 05\n\
       dd 25 0e 00 95 6e 19 fb  7f b7 ce 47 5a 59 01 5f\n\
       35 33 fc 85 ac 34 1a b0  7a 67 86 e8 3e 31 fe 38\n\
       35 5c bb a1 b5 74 f4 47  a3 4c 0a f0 5f 6d 68 47\n\
       85 0f e9 79 74 23 e8 75  47 6e 2b e5 ea 1b 0a 36\n\
       b9 c3 94 ca b0"
  and data =
    of_hex
      "a8 98 57 b9 3f 58 02 c7  9a 37 e2 d7 89 d8 0b f4\n\
       2d 84 c2 24 7c 7f ff 5f  7b 65 c5 17 cf 79 7d 36\n\
       ff d3 9d 47 5e 68 90 57  f1 61 48 18 04 c3 fe ee\n\
       59 b2 15 2d 75 8b 9a 3c  52 60 96 5c 52 a8 55 9c"
  and sigr =
    of_hex
      "3a 2c 99 0b 61 a1 da 06  20 bf 6c fe 1f d3 f8 2a\n\
       cb f1 e5 0f 78 11 61 58  22 e4 a0 5f 18 81 8d 98\n\
       f8 7a ca 8b f8 f8 cc b8  95 f7 6f 03 54 1b 66 6e\n\
       cf c5 cb f1 7b 48 82 d2  c3 0e 0e 1b b4 ad e6 a4\n\
       5c"
  and sigs =
    of_hex
      "01 7b 8c 82 a5 aa 80 c5  ee 23 0f 91 55 89 a7 b0\n\
       3c 46 7f 56 ff b4 52 89  52 99 59 1e 5e b7 f2 c1\n\
       df f8 a0 4f d3 dd 1d f0  07 78 3a 2f 29 d6 61 61\n\
       55 dc 3b be 14 82 93 75  c2 0d be 7e ca 50 e4 3c\n\
       98 88"
  in
  match P521.Dsa.pub_of_octets key with
  | Ok key ->
      Alcotest.check Alcotest.bool "regression 1" true
        (P521.Dsa.verify ~key (sigr, sigs) data)
  | Error _ -> Alcotest.fail "regression failed"

let () =
  Mirage_crypto_rng_unix.use_default ();
  Alcotest.run "EC"
    [
      ("P256 Key exchange", key_exchange);
      ("P256 Low level scalar mult", scalar_mult);
      ("P256 Point validation", point_validation);
      ("P256 Scalar validation when generating", scalar_validation);
      ("ECDSA NIST", ecdsa);
      ("ECDSA RFC 6979 P256", ecdsa_rfc6979_p256);
      ("ECDSA RFC 6979 P384", ecdsa_rfc6979_p384);
      ("ECDSA RFC 6979 P521", ecdsa_rfc6979_p521);
      ("ECDSA P521 regression", [ ("regression1", `Quick, p521_regression) ]);
      ("secp256k1 ECDSA", secp256k1_ecdsa);
      ("secp256k1 ECDSA sign", secp256k1_ecdsa_sign);
      ("secp256k1 BIP-340", secp256k1_bip340_sign);
      ("brainpoolP256r1 ECDSA", brainpoolp256_ecdsa);
      ("brainpoolP384r1 ECDSA", brainpoolp384_ecdsa);
      ("brainpoolP512r1 ECDSA", brainpoolp512_ecdsa);
    ]
