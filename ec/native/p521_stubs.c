#include "mirage_crypto.h"

#ifdef ARCH_64BIT
#include "p521_64.h"
#define LIMBS 9
#define WORD uint64_t
#define WORDSIZE 64
#include "p521_tables_64.h"
#else
#include "p521_32.h"
#define LIMBS 17
#define WORD uint32_t
#define WORDSIZE 32
#include "p521_tables_32.h"
#endif

#define LEN_PRIME 521
#define CURVE_DESCRIPTION fiat_p521

#include "inversion_template.h"
#include "point_operations.h"

#include <caml/memory.h>

CAMLprim value mc_p521_sub(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_p521_sub((WORD*)Bytes_val(out), (const WORD*)String_val(a), (const WORD*)String_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_add(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_p521_add((WORD*)Bytes_val(out), (const WORD*)String_val(a), (const WORD*)String_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_mul(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_p521_mul((WORD*)Bytes_val(out), (const WORD*)String_val(a), (const WORD*)String_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_from_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p521_from_bytes((WORD*)Bytes_val(out), _st_uint8(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_to_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p521_to_bytes(Bytes_val(out), (const WORD*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_sqr(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p521_square((WORD*)Bytes_val(out), (const WORD*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_from_montgomery(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p521_from_montgomery((WORD*)Bytes_val(out), (const WORD*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_to_montgomery(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p521_to_montgomery((WORD*)Bytes_val(out), (const WORD*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_nz(value x)
{
	CAMLparam1(x);
	CAMLreturn(Val_bool(fe_nz((const WORD*)String_val(x))));
}

CAMLprim value mc_p521_set_one(value x)
{
	CAMLparam1(x);
        fiat_p521_set_one((WORD*)Bytes_val(x));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_inv(value out, value in)
{
	CAMLparam2(out, in);
	inversion((WORD*)Bytes_val(out), (const WORD*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_point_double(value out, value in)
{
	CAMLparam2(out, in);
	point_double(
		(WORD*)Bytes_val(Field(out, 0)),
		(WORD*)Bytes_val(Field(out, 1)),
		(WORD*)Bytes_val(Field(out, 2)),
		(const WORD*)String_val(Field(in, 0)),
		(const WORD*)String_val(Field(in, 1)),
		(const WORD*)String_val(Field(in, 2))
	);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_point_add(value out, value p, value q)
{
	CAMLparam3(out, p, q);
	point_add(
		(WORD*)Bytes_val(Field(out, 0)),
		(WORD*)Bytes_val(Field(out, 1)),
		(WORD*)Bytes_val(Field(out, 2)),
		(const WORD*)String_val(Field(p, 0)),
		(const WORD*)String_val(Field(p, 1)),
		(const WORD*)String_val(Field(p, 2)),
		0,
		(const WORD*)String_val(Field(q, 0)),
		(const WORD*)String_val(Field(q, 1)),
		(const WORD*)String_val(Field(q, 2))
	);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_select(value out, value bit, value t, value f)
{
	CAMLparam4(out, bit, t, f);
	fe_cmovznz(
		(WORD*)Bytes_val(out),
		Bool_val(bit),
		(const WORD*)String_val(f),
		(const WORD*)String_val(t)
	);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p521_scalar_mult_base(value out, value s)
{
    CAMLparam2(out, s);
    scalar_mult_base(
		(WORD *) Bytes_val(Field(out, 0)),
		(WORD *) Bytes_val(Field(out, 1)),
		(WORD *) Bytes_val(Field(out, 2)),
		_st_uint8(s),
		caml_string_length(s)
    );
    CAMLreturn(Val_unit);
}
