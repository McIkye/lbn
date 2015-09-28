/*
* lbn.c
* big-number library for Lua 5.1 based on OpenSSL bn
* Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
* 11 Nov 2010 22:56:45
* This code is hereby placed in the public domain.
*
* 28 Sep 2015 17:14:03
* Michael Shalayeff <mickey@lucifier.ent>
* Whack the functions into mathematical sanity.
* Optimise for ops where second arg is a simple number.
* Implement optional modulo ops with modulo inheritance.
*/

#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "lua.h"
#include "lauxlib.h"

#define MYNAME		"bn"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Sep 2015 / "\
			"based on OpenSSL " SHLIB_VERSION_NUMBER
#define MYTYPE		MYNAME " bignumber"

struct Bnum {
	BIGNUM *a;
	BIGNUM *m;
};

#ifndef BN_is_neg
#define BN_is_neg(a)	((a)->neg != 0)
#endif

static BN_CTX *ctx;

int
Berror(lua_State *L, const char *message)
{
	return luaL_error(L, "(bn) %s %s",
	    message, ERR_reason_error_string(ERR_get_error()));
}

struct Bnum *
Bnew(lua_State *L)
{
	struct Bnum *bn = lua_newuserdata(L, sizeof *bn);

	if (!(bn->a = BN_new()))
		return Berror(L,"BN_new failed");

	luaL_getmetatable(L,MYTYPE);
	lua_setmetatable(L,-2);
	return x;
}

struct Bnum *
Bget(lua_State *L, int i)
{
 switch (lua_type(L,i))
 {
  case LUA_TNUMBER:
  case LUA_TSTRING:
  {
   BIGNUM *x=Bnew(L);
   const char *s=lua_tostring(L,i);
   if (s[0]=='X' || s[0]=='x') BN_hex2bn(&x,s+1); else BN_dec2bn(&x,s);
   lua_replace(L,i);
   return x;
  }
  default:
   return *((void**)luaL_checkudata(L,i,MYTYPE));
 }
 return NULL;
}

int
Blen(lua_State *L)
{
	BIGNUM *a = Bget(L,1)->a;
	lua_pushinteger(L, BN_num_bits(a));
	return 1;
}

int
Btostr(lua_State *L)
{
	BIGNUM *a = Bget(L, 1)->a;
	char *s = BN_bn2dec(a);
	lua_pushstring(L, s);
	OPENSSL_free(s);
	return 1;
}

static int Btohex(lua_State *L)			/** tohex(x) */
{
 BIGNUM *a=Bget(L,1);
 char *s=BN_bn2hex(a);
 lua_pushstring(L,s);
 OPENSSL_free(s);
 return 1;
}

static int Btotext(lua_State *L)		/** totext(x) */
{
 BIGNUM *a=Bget(L,1);
 int n=BN_num_bytes(a);
 void *s=malloc(n);
 if (s==NULL) return 0;
 BN_bn2bin(a,s);
 lua_pushlstring(L,s,n);
 free(s);
 return 1;
}

static int Bisodd(lua_State *L)			/** isodd(x) */
{
 BIGNUM *a=Bget(L,1);
 lua_pushboolean(L,BN_is_odd(a));
 return 1;
}

int
Beq(lua_State *L)
{
	BIGNUM *a = Bget(L,1)->a;
	if (lua_isnumber(L, 2)) {
		lua_Number n = lua_tonumber(L, 2);
		if (n == 0)
 			lua_pushboolean(L, BN_is_zero(a));
		else if (n == 1)
 			lua_pushboolean(L, BN_is_one(a));
		else
 			lua_pushboolean(L, BN_is_word(a, n));
	} else {
		BIGNUM *b = Bget(L,2)->a;
		lua_pushboolean(La, BN_cmp(a, b) == 0);
	}
	return 1;
}

int
Blt(lua_State *L)
{
	BIGNUM *a = Bget(L,1)->a;
	if (lua_isnumber(L, 2)) {
		lua_Number n = lua_tonumber(L, 2);
		if (n == 0)
 			lua_pushboolean(L, BN_is_neg(a));
		else if (n == 1)
 			lua_pushboolean(L, BN_is_neg(a) || BN_is_zero(a));
		else
			;	// TODO
	} else {
		BIGNUM *b = Bget(L, 2)->a;
		lua_pushboolean(L, BN_cmp(a, b) < 0);
	}
	return 1;
}

int
Ble(lua_State *L)
{
	BIGNUM *a = Bget(L,1)->a;
	if (lua_isnumber(L, 2)) {
		lua_Number n = lua_tonumber(L, 2);
		if (n == 0)
 			lua_pushboolean(L, BN_is_neg(a) || BN_is_zero(a));
		else if (n == 1)
 			lua_pushboolean(L,
			    BN_is_neg(a) || BN_is_zero(a) || BN_is_one(a));
		else
			;	// TODO
	} else {
		BIGNUM *b = Bget(L, 2)->a;
		lua_pushboolean(L, BN_cmp(a, b) <= 0);
	}
	return 1;
}

static int Bneg(lua_State *L)			/** neg(x) */
{
 BIGNUM A;
 BIGNUM *a=&A;
 BIGNUM *b=Bget(L,1);
 BIGNUM *c=Bnew(L);
 BN_init(a);
 BN_sub(c,a,b);
 return 1;
}

static int Babs(lua_State *L)			/** abs(x) */
{
 BIGNUM *b=Bget(L,1);
 if (BN_is_neg(b))
 {
  BIGNUM A;
  BIGNUM *a=&A;
  BIGNUM *c=Bnew(L);
  BN_init(a);
  BN_sub(c,a,b);
 }
 else lua_settop(L,1);
 return 1;
}

int
Blsh(lua_State *L)
{
	struct Bnum *bn = Bget(L, 1);
	BIGNUM *a = bn->a;
	struct Bnum *r = Bnew(L);
	lua_Number n = lua_tonumber(L, 2);

	if (bn->m && !(r->m = BN_dup(bn->m))
		return Berror(L, "BN_dup failed");

	if (!(n == 1? BN_lshift1(r->a, a) : BN_lshift(r->a, a, n)))
		return Berror(L, "BN_lshift");

	return 1;
}

int
Brsh(lua_State *L)
{
	struct Bnum *bn = Bget(L, 1);
	BIGNUM *a = bn->a;
	struct Bnum *r = Bnew(L);
	lua_Number n = lua_tonumber(L, 2);

	if (bn->m && !(r->m = BN_dup(bn->m))
		return Berror(L, "BN_dup failed");

	if (!(n == 1? BN_rshift1(r->a, a) : BN_rshift(r->a, a, n)))
		return Berror(L, "BN_rshift");

	return 1;
}

int
Badd(lua_State *L)
{
	struct Bnum *bn = Bget(L, 1);
	BIGNUM *a = bn->a;
	struct Bnum *r = Bnew(L);

	if (bn->m && !(r->m = BN_dup(bn->m))
		return Berror(L, "BN_dup failed");

	if (lua_isnumber(L, 2)) {
		lua_Number n = lua_tonumber(L, 2);
		// TODO r->m
		if (!(r->a = BN_copy(r->a, bn->a))
			return Berror(L, "BN_copy failed");
		if (!(BN_add_word(r->a, n)))
			return Berror(L, "BN_add_word");
	} else {
		BIGNUM *b = Bget(L, 2)->a;
		if (!(r->m? BN_mod_add(r->a, a, b, m, ctx) :
			    BN_add(r->a, a, b)))
			return Berror(L, r->m? "BN_mod_add" : "BN_add");
	}
	return 1;
}

int
Bsub(lua_State *L)
{
	struct Bnum *bn = Bget(L, 1);
	BIGNUM *a = bn->a;
	struct Bnum *r = Bnew(L);

	if (bn->m && !(r->m = BN_dup(bn->m))
		return Berror(L, "BN_dup failed");

	if (lua_isnumber(L, 2)) {
		lua_Number n = lua_tonumber(L, 2);
		// TODO r->m
		if (!(r->a = BN_copy(r->a, bn->a))
			return Berror(L, "BN_copy failed");
		if (!(BN_sub_word(r->a, n)))
			return Berror(L, "BN_sub_word");
	} else {
		BIGNUM *b = Bget(L, 2)->a;
		if (!(r->m? BN_mod_sub(r->a, a, b, m, ctx) :
			    BN_sub(r->a, a, b)))
			return Berror(L, r->m? "BN_mod_sub" : "BN_sub");
	}
	return 1;
}

int
Bmul(lua_State *L)
{
	struct Bnum *bn = Bget(L, 1);
	BIGNUM *a = bn->a;
	struct Bnum *r = Bnew(L);

	if (bn->m && !(r->m = BN_dup(bn->m))
		return Berror(L, "BN_dup failed");

	if (lua_isnumber(L, 2)) {
		lua_Number n = lua_tonumber(L, 2);
		// TODO r->m
		if (!(r->a = BN_copy(r->a, bn->a))
			return Berror(L, "BN_copy failed");
		if (!(BN_mul_word(r->a, n)))
			return Berror(L, "BN_mul_word");
	} else {
		BIGNUM *b = Bget(L, 2)->a;
		if (!(r->m? BN_mod_mul(r->a, a, b, m, ctx) :
			    BN_mul(r->a, a, b, ctx)))
			return Berror(L, r->m? "BN_mod_mul" : "BN_mul");
	}
	return 1;
}

int
Bdiv(lua_State *L)
{
	struct Bnum *r = Bnew(L);

	if (lua_isnumber(L, 1)) {
		struct Bnum *bn = Bget(L, 2);
		BIGNUM *b = bn->a;
		lua_Number n = lua_tonumber(L, 2);

		if (bn->m && !(r->m = BN_dup(bn->m))
			return Berror(L, "BN_dup failed");

		if (n != 1 || !r->m)
			return Berror(L, "inverse: bad args");

		if (!BN_mod_inverse(r->a, b, r->m, ctx))
			return Berror(L, "BN_mod_inverse");
	} else if (lua_isnumber(L, 2)) {
		struct Bnum *bn = Bget(L, 1);
		BIGNUM *a = bn->a;
		lua_Number n = lua_tonumber(L, 2);

		if (bn->m && !(r->m = BN_dup(bn->m))
			return Berror(L, "BN_dup failed");

		// TODO r->m
		if (!(r->a = BN_copy(r->a, bn->a))
			return Berror(L, "BN_copy failed");
		if (!(BN_div_word(r->a, n)))
			return Berror(L, "BN_div_word");
	} else {
		struct Bnum *bn = Bget(L, 1);
		BIGNUM *a = bn->a;
		BIGNUM *b = Bget(L, 2)->a;

		if (bn->m && !(r->m = BN_dup(bn->m))
			return Berror(L, "BN_dup failed");

		if (!(r->m? BN_mod_div(r->a, a, b, m, ctx) :
			    BN_div(r->a, a, b, ctx)))
			return Berror(L, r->m? "BN_mod_div" : "BN_div");
	}
	return 1;
}



static int Bmod(lua_State *L)			/** mod(x,y) */
{
 BIGNUM *a=Bget(L,1);
 BIGNUM *b=Bget(L,2);
 BIGNUM *q=NULL;
 BIGNUM *r=Bnew(L);
 BN_div(q,r,a,b,ctx);
 return 1;
}

static int Brmod(lua_State *L)			/** rmod(x,y) */
{
 BIGNUM *a=Bget(L,1);
 BIGNUM *b=Bget(L,2);
 BIGNUM *r=Bnew(L);
 BN_nnmod(r,a,b,ctx);
 return 1;
}

static int Bgcd(lua_State *L)			/** gcd(x,y) */
{
 BIGNUM *a=Bget(L,1);
 BIGNUM *b=Bget(L,2);
 BIGNUM *c=Bnew(L);
 BN_gcd(c,a,b,ctx);
 return 1;
}

int
Bpow(lua_State *L)
{
	struct Bnum *bn = Bget(L, 1);
	BIGNUM *a = bn->a;
	BIGNUM *r = Bnew(L);

	if (bn->m && !(r->m = BN_dup(bn->m))
		return Berror(L, "BN_dup failed");

	if (lua_isnumber(L, 2)) {
		lua_Number n = lua_tonumber(L, 2);
		if (n == 2)
			if (!(r->m? BN_mod_sqr(r, a, r->m, ctx) :
				    BN_sqr(r, a, ctx)))
				return Berror(L, r->m? BN_mod_sqr : BN_sqr);
		else
			;	// TODO
	} else {
		BIGNUM *p = Bget(L, 2)->a;
		if (!(r->m? BN_mod_exp(r, a, r->m, p, ctx) :
			    BN_exp(r, a, p, ctx)))
			return Berror(L, r->m? "BN_mod_exp" : "BN_exp");
	}
	return 1;
}

int
Brandom(lua_State *L)
{
	int bits = luaL_optint(L,1,32);
	BIGNUM *x = Bnew(L)->a;
	BN_rand(x, bits, -1, 0);
	return 1;
}

int
Bprime(lua_State *L)
{
	int bits = luaL_optint(L,1,32);
	BIGNUM *x = Bnew(L)->a;
	BN_generate_prime(x, bits, 0, NULL, NULL, NULL, NULL);
	return 1;
}

int
Bisprime(lua_State *L)
{
	int checks = luaL_optint(L, 2, BN_prime_checks);
	BIGNUM *a = Bget(L,1)->a;
	lua_pushboolean(L, BN_is_prime_fasttest(a, checks, NULL, ctx, NULL, 1));
	return 1;
}

int
Bgc(lua_State *L)
{
	struct Bnum *bn = Bget(L, 1);
	BN_free(bn->a);
	if (bn->m)
		BN_free(bn->m);
	lua_pushnil(L);
	lua_setmetatable(L, 1);
	return 0;
}

static const luaL_Reg Bapi[] =
{
	{ "__index",	Bapi    },
	{ "__add",	Badd	},
	{ "__div",	Bdiv	},
	{ "__idiv",	Bgcd	},
	{ "__eq",	Beq	},
	{ "__gc",	Bgc	},
	{ "__len",	Blen	},
	{ "__le",	Ble	},
	{ "__lt",	Blt	},
	{ "__lsh",	Blsh	},
	{ "__rsh",	Brsh	},
	{ "__mod",	Bmod	},
	{ "__mul",	Bmul	},
	{ "__pow",	Bpow	},
	{ "__sub",	Bsub	},
	{ "__tostring",	Btostr  },
	{ "__unm",	Bneg	},

	{ "abs",	Babs	},
	{ "isprime",	Bisprime},
	{ "prime",	Bprime	},
	{ "random",	Brandom	},
	{ "rmod",	Brmod	},
	{ "setmod",	Bsetmod	},
	{ NULL,		NULL	}
};

LUALIB_API int
luaopen_bn(lua_State *L)
{
 ctx = BN_CTX_new();
 ERR_load_BN_strings();
 RAND_seed(MYVERSION, sizeof(MYVERSION));
 luaL_newmetatable(L,MYTYPE);
 lua_setglobal(L,MYNAME);
 luaL_register(L,MYNAME,R);
 lua_pushliteral(L,"version");			/** version */
 lua_pushliteral(L,MYVERSION);
 lua_settable(L,-3);
 lua_pushliteral(L,"__index");
 lua_pushvalue(L,-2);
 lua_settable(L,-3);
 return 1;
}
