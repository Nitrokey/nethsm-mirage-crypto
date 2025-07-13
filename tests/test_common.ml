let of_hex ?(skip_ws = true) s =
  let fold f acc str =
    let st = ref acc in
    String.iter (fun c -> st := f !st c) str;
    !st
  and digit c =
    match c with
    | '0' .. '9' -> int_of_char c - 0x30
    | 'A' .. 'F' -> int_of_char c - 0x41 + 10
    | 'a' .. 'f' -> int_of_char c - 0x61 + 10
    | _ -> invalid_arg "bad character"
  and is_space = function
    | ' ' | '\012' | '\n' | '\r' | '\t' -> true
    | _ -> false
  in
  let chars, leftover =
    fold
      (fun (chars, leftover) c ->
        if skip_ws && is_space c then (chars, leftover)
        else
          let c = digit c in
          match leftover with
          | None -> (chars, Some (c lsl 4))
          | Some c' -> ((c' lor c) :: chars, None))
      ([], None) s
  in
  let chars = List.rev chars in
  assert (leftover = None);
  String.init (List.length chars) (fun i -> char_of_int (List.nth chars i))
