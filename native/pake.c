/* TLS 2.0 RFC8492 EC-PWD primitive. Original implementation, project MIT license.
 *
 * OpenSSL public ABI only. The embedding application supplies function addresses
 * from ONE explicitly loaded OpenSSL library and its private OSSL_LIB_CTX. No
 * native library is discovered here and no OpenSSL internal structure is used.
 * Secret group arithmetic stays in OpenSSL. The first successful candidate is
 * selected without a password-dependent branch; every derivation performs at
 * least 41 iterations, blinds the residue test and uses constant-time modular
 * exponentiation. This is not a side-channel certification of every provider.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

typedef void BIGNUM;
typedef void BN_CTX;
typedef void EC_GROUP;
typedef void EC_POINT;

#define FUNCTIONS(X) \
 X(BN_CTX*,BN_CTX_secure_new_ex,(void*)) \
 X(void,BN_CTX_free,(BN_CTX*)) \
 X(void,BN_CTX_start,(BN_CTX*)) \
 X(BIGNUM*,BN_CTX_get,(BN_CTX*)) \
 X(void,BN_CTX_end,(BN_CTX*)) \
 X(BIGNUM*,BN_secure_new,(void)) \
 X(void,BN_clear_free,(BIGNUM*)) \
 X(void,BN_set_flags,(BIGNUM*,int)) \
 X(BIGNUM*,BN_bin2bn,(const unsigned char*,int,BIGNUM*)) \
 X(int,BN_bn2binpad,(const BIGNUM*,unsigned char*,int)) \
 X(int,BN_num_bits,(const BIGNUM*)) \
 X(int,BN_set_word,(BIGNUM*,uintptr_t)) \
 X(BIGNUM*,BN_copy,(BIGNUM*,const BIGNUM*)) \
 X(int,BN_cmp,(const BIGNUM*,const BIGNUM*)) \
 X(int,BN_is_bit_set,(const BIGNUM*,int)) \
 X(int,BN_add_word,(BIGNUM*,uintptr_t)) \
 X(int,BN_sub_word,(BIGNUM*,uintptr_t)) \
 X(int,BN_rshift,(BIGNUM*,const BIGNUM*,int)) \
 X(int,BN_nnmod,(BIGNUM*,const BIGNUM*,const BIGNUM*,BN_CTX*)) \
 X(int,BN_mod_mul,(BIGNUM*,const BIGNUM*,const BIGNUM*,const BIGNUM*,BN_CTX*)) \
 X(int,BN_mod_sqr,(BIGNUM*,const BIGNUM*,const BIGNUM*,BN_CTX*)) \
 X(int,BN_mod_add,(BIGNUM*,const BIGNUM*,const BIGNUM*,const BIGNUM*,BN_CTX*)) \
 X(int,BN_sub,(BIGNUM*,const BIGNUM*,const BIGNUM*)) \
 X(int,BN_mod_exp_mont_consttime,(BIGNUM*,const BIGNUM*,const BIGNUM*,const BIGNUM*,BN_CTX*,void*)) \
 X(int,BN_priv_rand_range_ex,(BIGNUM*,const BIGNUM*,unsigned int,BN_CTX*)) \
 X(EC_GROUP*,EC_GROUP_new_by_curve_name_ex,(void*,const char*,int)) \
 X(void,EC_GROUP_free,(EC_GROUP*)) \
 X(int,EC_GROUP_get_curve,(const EC_GROUP*,BIGNUM*,BIGNUM*,BIGNUM*,BN_CTX*)) \
 X(int,EC_GROUP_get_order,(const EC_GROUP*,BIGNUM*,BN_CTX*)) \
 X(int,EC_GROUP_get_cofactor,(const EC_GROUP*,BIGNUM*,BN_CTX*)) \
 X(EC_POINT*,EC_POINT_new,(const EC_GROUP*)) \
 X(void,EC_POINT_clear_free,(EC_POINT*)) \
 X(int,EC_POINT_set_affine_coordinates,(const EC_GROUP*,EC_POINT*,const BIGNUM*,const BIGNUM*,BN_CTX*)) \
 X(int,EC_POINT_get_affine_coordinates,(const EC_GROUP*,const EC_POINT*,BIGNUM*,BIGNUM*,BN_CTX*)) \
 X(int,EC_POINT_is_on_curve,(const EC_GROUP*,const EC_POINT*,BN_CTX*)) \
 X(int,EC_POINT_is_at_infinity,(const EC_GROUP*,const EC_POINT*)) \
 X(int,EC_POINT_mul,(const EC_GROUP*,EC_POINT*,const BIGNUM*,const EC_POINT*,const BIGNUM*,BN_CTX*)) \
 X(int,EC_POINT_add,(const EC_GROUP*,EC_POINT*,const EC_POINT*,const EC_POINT*,BN_CTX*)) \
 X(int,EC_POINT_invert,(const EC_GROUP*,EC_POINT*,BN_CTX*)) \
 X(unsigned char*,EVP_Q_mac,(void*,const char*,const char*,const char*,const void*,const void*,size_t,const unsigned char*,size_t,unsigned char*,size_t,size_t*)) \
 X(int,EVP_Q_digest,(void*,const char*,const char*,const void*,size_t,unsigned char*,size_t*)) \
 X(int,RAND_priv_bytes_ex,(void*,unsigned char*,size_t,unsigned int)) \
 X(void,OPENSSL_cleanse,(void*,size_t))

typedef struct {
#define DECL(ret,name,args) ret (*name) args;
 FUNCTIONS(DECL)
#undef DECL
} API;
static const char *names[] = {
#define NAME(ret,name,args) #name,
 FUNCTIONS(NAME)
#undef NAME
};
EXPORT const char *tls20_pwd_function_name(size_t index) {
 return index < sizeof(names)/sizeof(names[0]) ? names[index] : NULL;
}
EXPORT unsigned int tls20_pwd_abi(void) {
#ifdef TLS20_PWD_TESTING
 return 0x80000001u;
#else
 return 1;
#endif
}

typedef struct {
 API a; void *libctx; BN_CTX *ctx; EC_GROUP *group; EC_POINT *pe;
 BIGNUM *prime,*order,*private_value,*ff_element; size_t width,hashlen; const char *hash;
 unsigned char commitment[2*1024+4]; size_t commitment_length; int used;
} PWD;

static BIGNUM *tmp(PWD *s) {
 BIGNUM *r=s->a.BN_CTX_get(s->ctx);
 if (r) s->a.BN_set_flags(r,4); /* BN_FLG_CONSTTIME public flag. */
 return r;
}
static unsigned char choose(unsigned int yes,unsigned char a,unsigned char b) {
 volatile unsigned int mask=0u-(yes&1u);
 return (unsigned char)((mask&a)|(~mask&b));
}
static int random_nonzero(PWD *s,BIGNUM *r,const BIGNUM *range,const BIGNUM *zero) {
 do { if (!s->a.BN_priv_rand_range_ex(r,range,0,s->ctx)) return 0; }
 while (s->a.BN_cmp(r,zero)==0);
 return 1;
}
static int hmac_hash(PWD *s,const unsigned char *key,size_t keylen,
                     const unsigned char *data,size_t length,unsigned char *out) {
 size_t actual=0;
 return s->a.EVP_Q_mac(s->libctx,"HMAC","provider=default",s->hash,NULL,
                       key,keylen,data,length,out,s->hashlen,&actual)!=NULL && actual==s->hashlen;
}
static int expand(PWD *s,const unsigned char *seed,const unsigned char *context,
                  size_t length,unsigned char *out) {
 static const unsigned char label[]="tls20 TLS-PWD Hunting And Pecking";
 unsigned char info[128],input[193],last[48]; size_t ilen=0,done=0,previous=0; unsigned int counter=1;
 int ok=0;
 info[ilen++]=(unsigned char)(length>>8);info[ilen++]=(unsigned char)length;
 info[ilen++]=(unsigned char)(sizeof(label)-1);memcpy(info+ilen,label,sizeof(label)-1);ilen+=sizeof(label)-1;
 info[ilen++]=(unsigned char)s->hashlen;memcpy(info+ilen,context,s->hashlen);ilen+=s->hashlen;
 while (done<length) {
  memcpy(input,last,previous);memcpy(input+previous,info,ilen);input[previous+ilen]=(unsigned char)counter++;
  if (!hmac_hash(s,seed,s->hashlen,input,previous+ilen+1,last)) goto end;
  size_t take=length-done<s->hashlen?length-done:s->hashlen;
  memcpy(out+done,last,take);done+=take;previous=s->hashlen;
 }
 ok=1;
end:s->a.OPENSSL_cleanse(input,sizeof(input));s->a.OPENSSL_cleanse(last,sizeof(last));return ok;
}
static int rhs(PWD *s,BIGNUM *result,const BIGNUM *x,const BIGNUM *a,const BIGNUM *b,BIGNUM *scratch) {
 return s->a.BN_mod_sqr(result,x,s->prime,s->ctx) &&
        s->a.BN_mod_mul(result,result,x,s->prime,s->ctx) &&
        s->a.BN_mod_mul(scratch,a,x,s->prime,s->ctx) &&
        s->a.BN_mod_add(result,result,scratch,s->prime,s->ctx) &&
        s->a.BN_mod_add(result,result,b,s->prime,s->ctx);
}
static int derive_pe(PWD *s,const unsigned char *base,const unsigned char *random) {
 unsigned char input[99],seed[48],expanded[74],context[48],dummy[32],saved[66]={0};
 unsigned char encoded[66],qrbytes[66],qnrbytes[66],selector[66],zeros[48]={0};
 size_t actual=0;unsigned int found=0,parity=0;int ok=0;
 s->a.BN_CTX_start(s->ctx);
 BIGNUM *a=tmp(s),*b=tmp(s),*minus=tmp(s),*legendre=tmp(s),*sqrt_exp=tmp(s),*value=tmp(s);
 BIGNUM *cube=tmp(s),*scratch=tmp(s),*r=tmp(s),*qr=tmp(s),*qnr=tmp(s),*one=tmp(s),*zero=tmp(s),*y=tmp(s);
 if (!y || !s->a.BN_set_word(one,1) || !s->a.BN_set_word(zero,0) ||
     !s->a.EC_GROUP_get_curve(s->group,s->prime,a,b,s->ctx) ||
     !s->a.BN_copy(minus,s->prime) || !s->a.BN_sub_word(minus,1) ||
     !s->a.BN_rshift(legendre,minus,1) || !s->a.BN_copy(sqrt_exp,s->prime) ||
     !s->a.BN_add_word(sqrt_exp,1) || !s->a.BN_rshift(sqrt_exp,sqrt_exp,2)) goto end;
 /* Restrict to supported cofactor-one primes congruent to 3 mod 4. */
 if (!s->a.BN_is_bit_set(s->prime,0) || !s->a.BN_is_bit_set(s->prime,1)) goto end;
 if (!random_nonzero(s,qr,s->prime,zero) || !s->a.BN_mod_sqr(qr,qr,s->prime,s->ctx)) goto end;
 do {
  if (!random_nonzero(s,qnr,s->prime,zero) ||
      !s->a.BN_mod_exp_mont_consttime(scratch,qnr,legendre,s->prime,s->ctx,NULL)) goto end;
 } while (s->a.BN_cmp(scratch,minus)!=0);
 if (s->a.BN_bn2binpad(qr,qrbytes,(int)s->width)!=(int)s->width ||
     s->a.BN_bn2binpad(qnr,qnrbytes,(int)s->width)!=(int)s->width ||
     !s->a.EVP_Q_digest(s->libctx,s->hash,"provider=default",random,32,context,&actual) || actual!=s->hashlen ||
     s->a.BN_bn2binpad(s->prime,input+33,(int)s->width)!=(int)s->width ||
     !s->a.RAND_priv_bytes_ex(s->libctx,dummy,32,0)) goto end;
 int bits=s->a.BN_num_bits(s->prime)+64;size_t length=(size_t)(bits+7)/8;
 for (unsigned int counter=1;counter<=255 && (counter<=41 || !found);++counter) {
  for (size_t j=0;j<32;++j) input[j]=choose(found,dummy[j],base[j]);
  input[32]=(unsigned char)counter;
  if (!hmac_hash(s,zeros,s->hashlen,input,33+s->width,seed) ||
      !expand(s,seed,context,length,expanded) || !s->a.BN_bin2bn(expanded,(int)length,value) ||
      !s->a.BN_rshift(value,value,(int)(8*length)-bits) ||
      !s->a.BN_nnmod(value,value,minus,s->ctx) || !s->a.BN_add_word(value,1) ||
      !rhs(s,cube,value,a,b,scratch) || !random_nonzero(s,r,s->prime,zero)) goto end;
  unsigned int coin=(unsigned int)s->a.BN_is_bit_set(r,0);
  for (size_t j=0;j<s->width;++j) selector[j]=choose(coin,qrbytes[j],qnrbytes[j]);
  if (!s->a.BN_bin2bn(selector,(int)s->width,y) ||
      !s->a.BN_mod_sqr(r,r,s->prime,s->ctx) || !s->a.BN_mod_mul(scratch,cube,r,s->prime,s->ctx) ||
      !s->a.BN_mod_mul(scratch,scratch,y,s->prime,s->ctx) ||
      !s->a.BN_mod_exp_mont_consttime(scratch,scratch,legendre,s->prime,s->ctx,NULL) ||
      s->a.BN_bn2binpad(value,encoded,(int)s->width)!=(int)s->width) goto end;
  unsigned int valid=((s->a.BN_cmp(scratch,one)==0)&coin)|((s->a.BN_cmp(scratch,minus)==0)&(coin^1u));
  unsigned int take=valid&(found^1u);
  for (size_t j=0;j<s->width;++j) saved[j]=choose(take,encoded[j],saved[j]);
  parity=choose(take,seed[s->hashlen-1]&1u,(unsigned char)parity);found|=valid;
 }
 if (!found || !s->a.BN_bin2bn(saved,(int)s->width,value) || !rhs(s,cube,value,a,b,scratch) ||
     !s->a.BN_mod_exp_mont_consttime(y,cube,sqrt_exp,s->prime,s->ctx,NULL) ||
     !s->a.BN_sub(scratch,s->prime,y) ||
     s->a.BN_bn2binpad(y,encoded,(int)s->width)!=(int)s->width ||
     s->a.BN_bn2binpad(scratch,selector,(int)s->width)!=(int)s->width) goto end;
 unsigned int flip=parity^((unsigned int)encoded[s->width-1]&1u);
 for (size_t j=0;j<s->width;++j) encoded[j]=choose(flip,selector[j],encoded[j]);
 if (!s->a.BN_bin2bn(encoded,(int)s->width,y) ||
     !s->a.EC_POINT_set_affine_coordinates(s->group,s->pe,value,y,s->ctx)) goto end;
 ok=1;
end:
 s->a.OPENSSL_cleanse(input,sizeof(input));s->a.OPENSSL_cleanse(seed,sizeof(seed));
 s->a.OPENSSL_cleanse(expanded,sizeof(expanded));s->a.OPENSSL_cleanse(dummy,sizeof(dummy));
 s->a.OPENSSL_cleanse(saved,sizeof(saved));s->a.OPENSSL_cleanse(encoded,sizeof(encoded));
 s->a.OPENSSL_cleanse(selector,sizeof(selector));s->a.BN_CTX_end(s->ctx);return ok;
}

EXPORT void tls20_pwd_free(PWD *s) {
 if (!s) return;
 s->a.BN_clear_free(s->private_value);s->a.BN_clear_free(s->order);s->a.BN_clear_free(s->prime);s->a.BN_clear_free(s->ff_element);
 s->a.EC_POINT_clear_free(s->pe);s->a.EC_GROUP_free(s->group);s->a.BN_CTX_free(s->ctx);
 s->a.OPENSSL_cleanse(s,sizeof(*s));free(s);
}
EXPORT PWD *tls20_pwd_new(void *const *functions,size_t count,void *libctx,int nid,
                         const unsigned char *base,const unsigned char *random,unsigned int hashbits) {
 if (!functions || count!=sizeof(names)/sizeof(names[0]) || !base || !random || !libctx ||
     (hashbits!=256 && hashbits!=384)) return NULL;
 PWD *s=(PWD*)calloc(1,sizeof(*s));if (!s) return NULL;
 size_t index=0;
#define ASSIGN(ret,name,args) s->a.name=(ret (*) args)functions[index++];if (!s->a.name) {free(s);return NULL;}
 FUNCTIONS(ASSIGN)
#undef ASSIGN
 s->libctx=libctx;s->hashlen=hashbits/8;s->hash=hashbits==256?"SHA256":"SHA384";
 s->ctx=s->a.BN_CTX_secure_new_ex(libctx);s->group=s->a.EC_GROUP_new_by_curve_name_ex(libctx,"provider=default",nid);
 s->prime=s->a.BN_secure_new();s->order=s->a.BN_secure_new();s->private_value=s->a.BN_secure_new();
 if (!s->ctx || !s->group || !s->prime || !s->order || !s->private_value) goto failure;
 s->a.BN_set_flags(s->private_value,4);s->pe=s->a.EC_POINT_new(s->group);
 if (!s->pe || !s->a.EC_GROUP_get_curve(s->group,s->prime,NULL,NULL,s->ctx) ||
     !s->a.EC_GROUP_get_order(s->group,s->order,s->ctx)) goto failure;
 s->width=(size_t)(s->a.BN_num_bits(s->prime)+7)/8;
 if (s->width<32 || s->width>66) goto failure;
 s->a.BN_CTX_start(s->ctx);BIGNUM *cofactor=tmp(s),*one=tmp(s);
 int valid=one && s->a.BN_set_word(one,1) && s->a.EC_GROUP_get_cofactor(s->group,cofactor,s->ctx) && s->a.BN_cmp(cofactor,one)==0;
 s->a.BN_CTX_end(s->ctx);
 if (!valid || !derive_pe(s,base,random)) goto failure;
 return s;
failure:tls20_pwd_free(s);return NULL;
}
EXPORT int tls20_pwd_commit(PWD *s,unsigned char *output,size_t capacity) {
 if (!s || !output || s->ff_element || s->used || s->commitment_length || capacity<3*s->width+1) return 0;
 s->a.BN_CTX_start(s->ctx);BIGNUM *mask=tmp(s),*scalar=tmp(s),*x=tmp(s),*y=tmp(s),*one=tmp(s),*zero=tmp(s);
 EC_POINT *element=s->a.EC_POINT_new(s->group);int ok=0;
 if (!zero || !element || !s->a.BN_set_word(one,1) || !s->a.BN_set_word(zero,0)) goto end;
 do {
  if (!random_nonzero(s,s->private_value,s->order,zero) || !random_nonzero(s,mask,s->order,zero) ||
      !s->a.BN_mod_add(scalar,s->private_value,mask,s->order,s->ctx)) goto end;
 } while (s->a.BN_cmp(scalar,one)<=0);
 if (!s->a.EC_POINT_mul(s->group,element,NULL,s->pe,mask,s->ctx) ||
     !s->a.EC_POINT_invert(s->group,element,s->ctx) ||
     !s->a.EC_POINT_get_affine_coordinates(s->group,element,x,y,s->ctx) ||
     s->a.BN_bn2binpad(x,s->commitment,(int)s->width)!=(int)s->width ||
     s->a.BN_bn2binpad(y,s->commitment+s->width,(int)s->width)!=(int)s->width ||
     s->a.BN_bn2binpad(scalar,s->commitment+2*s->width+1,(int)s->width)!=(int)s->width) goto end;
 s->commitment[2*s->width]=(unsigned char)s->width;s->commitment_length=3*s->width+1;
 memcpy(output,s->commitment,s->commitment_length);ok=(int)s->commitment_length;
end:s->a.EC_POINT_clear_free(element);s->a.BN_CTX_end(s->ctx);return ok;
}
EXPORT int tls20_pwd_finish(PWD *s,const unsigned char *peer,size_t length,unsigned char *secret,size_t capacity) {
 if (!s || !secret || s->ff_element || s->used || !s->commitment_length || !peer || length<2*s->width+2 ||
     length!=2*s->width+1+peer[2*s->width] || peer[2*s->width]>s->width || capacity<s->width) return 0;
 s->used=1;s->a.BN_CTX_start(s->ctx);
 BIGNUM *x=tmp(s),*y=tmp(s),*scalar=tmp(s),*one=tmp(s),*zero=tmp(s);
 EC_POINT *element=s->a.EC_POINT_new(s->group),*shared=s->a.EC_POINT_new(s->group);int ok=0;
 if (!zero || !element || !shared || !s->a.BN_set_word(one,1) || !s->a.BN_set_word(zero,0) ||
     !s->a.BN_bin2bn(peer,(int)s->width,x) || !s->a.BN_bin2bn(peer+s->width,(int)s->width,y) ||
     !s->a.BN_bin2bn(peer+2*s->width+1,peer[2*s->width],scalar)) goto end;
 if (s->a.BN_cmp(x,zero)<=0 || s->a.BN_cmp(y,zero)<=0 ||
     s->a.BN_cmp(x,s->prime)>=0 || s->a.BN_cmp(y,s->prime)>=0 ||
     s->a.BN_cmp(scalar,one)<=0 || s->a.BN_cmp(scalar,s->order)>=0) goto end;
 unsigned char canonical_scalar[66];
 if (s->a.BN_bn2binpad(scalar,canonical_scalar,(int)s->width)!=(int)s->width) goto end;
 if (memcmp(peer,s->commitment,2*s->width)==0 &&
     memcmp(canonical_scalar,s->commitment+2*s->width+1,s->width)==0) goto end;
 if (!s->a.EC_POINT_set_affine_coordinates(s->group,element,x,y,s->ctx) ||
     s->a.EC_POINT_is_on_curve(s->group,element,s->ctx)!=1 ||
     s->a.EC_POINT_is_at_infinity(s->group,element)!=0 ||
     !s->a.EC_POINT_mul(s->group,shared,NULL,s->pe,scalar,s->ctx) ||
     !s->a.EC_POINT_add(s->group,shared,shared,element,s->ctx) ||
     s->a.EC_POINT_is_at_infinity(s->group,shared)!=0 ||
     !s->a.EC_POINT_mul(s->group,shared,NULL,shared,s->private_value,s->ctx) ||
     s->a.EC_POINT_is_at_infinity(s->group,shared)!=0 ||
     !s->a.EC_POINT_get_affine_coordinates(s->group,shared,x,NULL,s->ctx) ||
     s->a.BN_bn2binpad(x,secret,(int)s->width)!=(int)s->width) goto end;
 ok=(int)s->width;
end:s->a.BN_clear_free(s->private_value);s->private_value=NULL;
 s->a.EC_POINT_clear_free(element);s->a.EC_POINT_clear_free(shared);s->a.BN_CTX_end(s->ctx);return ok;
}

/* Fixed RFC7919 safe-prime FFC profile. The wrapper accepts only the registered
 * public primes; arbitrary attacker-supplied parameters never reach this API.
 * All password-dependent modular operations remain native and use flagged BN.
 */
static int derive_ff_pe(PWD *s,const unsigned char *base,const unsigned char *random) {
 unsigned char input[1057],seed[48],expanded[1032],context[48],dummy[32],saved[1024]={0},encoded[1024],zeros[48]={0};
 size_t actual=0;unsigned int found=0;int ok=0;
 s->a.BN_CTX_start(s->ctx);
 BIGNUM *minus=tmp(s),*value=tmp(s),*candidate=tmp(s),*one=tmp(s);
 if (!one || !s->a.BN_set_word(one,1) || !s->a.BN_copy(minus,s->prime) || !s->a.BN_sub_word(minus,1) ||
     !s->a.EVP_Q_digest(s->libctx,s->hash,"provider=default",random,32,context,&actual) || actual!=s->hashlen ||
     s->a.BN_bn2binpad(s->prime,input+33,(int)s->width)!=(int)s->width ||
     !s->a.RAND_priv_bytes_ex(s->libctx,dummy,32,0)) goto end;
 int bits=s->a.BN_num_bits(s->prime)+64;size_t length=(size_t)(bits+7)/8;
 for (unsigned int counter=1;counter<=255 && (counter<=41 || !found);++counter) {
  for (size_t j=0;j<32;++j) input[j]=choose(found,dummy[j],base[j]);
  input[32]=(unsigned char)counter;
  if (!hmac_hash(s,zeros,s->hashlen,input,33+s->width,seed) || !expand(s,seed,context,length,expanded) ||
      !s->a.BN_bin2bn(expanded,(int)length,value) || !s->a.BN_rshift(value,value,(int)(8*length)-bits) ||
      !s->a.BN_nnmod(value,value,minus,s->ctx) || !s->a.BN_add_word(value,1) ||
      !s->a.BN_mod_sqr(candidate,value,s->prime,s->ctx) ||
      s->a.BN_bn2binpad(candidate,encoded,(int)s->width)!=(int)s->width) goto end;
  unsigned int valid=s->a.BN_cmp(candidate,one)>0,take=valid&(found^1u);
  for (size_t j=0;j<s->width;++j) saved[j]=choose(take,encoded[j],saved[j]);
  found|=valid;
 }
 if (!found || !s->a.BN_bin2bn(saved,(int)s->width,s->ff_element)) goto end;
 ok=1;
end:s->a.OPENSSL_cleanse(input,sizeof(input));s->a.OPENSSL_cleanse(seed,sizeof(seed));
 s->a.OPENSSL_cleanse(expanded,sizeof(expanded));s->a.OPENSSL_cleanse(dummy,sizeof(dummy));
 s->a.OPENSSL_cleanse(saved,sizeof(saved));s->a.OPENSSL_cleanse(encoded,sizeof(encoded));
 s->a.BN_CTX_end(s->ctx);return ok;
}
EXPORT PWD *tls20_pwd_ff_new(void *const *functions,size_t count,void *libctx,const unsigned char *prime,size_t width,
                            const unsigned char *base,const unsigned char *random,unsigned int hashbits) {
 if (!functions || count!=sizeof(names)/sizeof(names[0]) || !prime || !base || !random || !libctx ||
     (hashbits!=256 && hashbits!=384) || (width!=256 && width!=384 && width!=512 && width!=768 && width!=1024)) return NULL;
 PWD *s=(PWD*)calloc(1,sizeof(*s));if (!s) return NULL;
 size_t index=0;
#define ASSIGN(ret,name,args) s->a.name=(ret (*) args)functions[index++];if (!s->a.name) {free(s);return NULL;}
 FUNCTIONS(ASSIGN)
#undef ASSIGN
 s->libctx=libctx;s->width=width;s->hashlen=hashbits/8;s->hash=hashbits==256?"SHA256":"SHA384";
 s->ctx=s->a.BN_CTX_secure_new_ex(libctx);s->prime=s->a.BN_secure_new();s->order=s->a.BN_secure_new();
 s->private_value=s->a.BN_secure_new();s->ff_element=s->a.BN_secure_new();
 if (!s->ctx || !s->prime || !s->order || !s->private_value || !s->ff_element ||
     !s->a.BN_bin2bn(prime,(int)width,s->prime) || !s->a.BN_copy(s->order,s->prime) ||
     !s->a.BN_sub_word(s->order,1) || !s->a.BN_rshift(s->order,s->order,1)) goto failure;
 s->a.BN_set_flags(s->private_value,4);s->a.BN_set_flags(s->ff_element,4);
 if (!derive_ff_pe(s,base,random)) goto failure;
 return s;
failure:tls20_pwd_free(s);return NULL;
}
EXPORT int tls20_pwd_ff_commit(PWD *s,unsigned char *output,size_t capacity) {
 if (!s || !output || !s->ff_element || s->used || s->commitment_length || capacity<2*s->width+2) return 0;
 s->a.BN_CTX_start(s->ctx);
 BIGNUM *mask=tmp(s),*scalar=tmp(s),*inverse=tmp(s),*element=tmp(s),*one=tmp(s),*zero=tmp(s);int ok=0;
 if (!zero || !s->a.BN_set_word(one,1) || !s->a.BN_set_word(zero,0)) goto end;
 do {
  if (!random_nonzero(s,s->private_value,s->order,zero) || !random_nonzero(s,mask,s->order,zero) ||
      !s->a.BN_mod_add(scalar,s->private_value,mask,s->order,s->ctx)) goto end;
 } while (s->a.BN_cmp(scalar,one)<=0);
 if (!s->a.BN_sub(inverse,s->order,mask) ||
     !s->a.BN_mod_exp_mont_consttime(element,s->ff_element,inverse,s->prime,s->ctx,NULL) ||
     s->a.BN_bn2binpad(element,s->commitment,(int)s->width)!=(int)s->width ||
     s->a.BN_bn2binpad(scalar,s->commitment+s->width+2,(int)s->width)!=(int)s->width) goto end;
 s->commitment[s->width]=(unsigned char)(s->width>>8);
 s->commitment[s->width+1]=(unsigned char)s->width;
 s->commitment_length=2*s->width+2;memcpy(output,s->commitment,s->commitment_length);ok=(int)s->commitment_length;
end:s->a.BN_CTX_end(s->ctx);return ok;
}
EXPORT int tls20_pwd_ff_finish(PWD *s,const unsigned char *peer,size_t length,unsigned char *secret,size_t capacity) {
 if (!s || !secret || !s->ff_element || s->used || !s->commitment_length || !peer || length<s->width+3 || capacity<s->width) return 0;
 size_t scalarlen=((size_t)peer[s->width]<<8)|peer[s->width+1];
 if (!scalarlen || scalarlen>s->width || length!=s->width+scalarlen+2) return 0;
 s->used=1;s->a.BN_CTX_start(s->ctx);
 BIGNUM *element=tmp(s),*scalar=tmp(s),*check=tmp(s),*shared=tmp(s),*minus=tmp(s),*one=tmp(s);int ok=0;
 unsigned char canonical[2048];
 if (!one || !s->a.BN_set_word(one,1) || !s->a.BN_copy(minus,s->prime) || !s->a.BN_sub_word(minus,1) ||
     !s->a.BN_bin2bn(peer,(int)s->width,element) || !s->a.BN_bin2bn(peer+s->width+2,(int)scalarlen,scalar)) goto end;
 if (s->a.BN_cmp(scalar,one)<=0 || s->a.BN_cmp(scalar,s->order)>=0 ||
     s->a.BN_cmp(element,one)<=0 || s->a.BN_cmp(element,minus)>=0 ||
     !s->a.BN_mod_exp_mont_consttime(check,element,s->order,s->prime,s->ctx,NULL) || s->a.BN_cmp(check,one)!=0 ||
     s->a.BN_bn2binpad(element,canonical,(int)s->width)!=(int)s->width ||
     s->a.BN_bn2binpad(scalar,canonical+s->width,(int)s->width)!=(int)s->width) goto end;
 if (memcmp(canonical,s->commitment,s->width)==0 && memcmp(canonical+s->width,s->commitment+s->width+2,s->width)==0) goto end;
 if (!s->a.BN_mod_exp_mont_consttime(shared,s->ff_element,scalar,s->prime,s->ctx,NULL) ||
     !s->a.BN_mod_mul(shared,shared,element,s->prime,s->ctx) || s->a.BN_cmp(shared,one)<=0 ||
     !s->a.BN_mod_exp_mont_consttime(shared,shared,s->private_value,s->prime,s->ctx,NULL) || s->a.BN_cmp(shared,one)<=0 ||
     s->a.BN_bn2binpad(shared,secret,(int)s->width)!=(int)s->width) goto end;
 ok=(int)s->width;
end:s->a.BN_clear_free(s->private_value);s->private_value=NULL;
 s->a.OPENSSL_cleanse(canonical,sizeof(canonical));s->a.BN_CTX_end(s->ctx);return ok;
}

#ifdef TLS20_PWD_TESTING
/* Only for independently specified public fixtures; absent in ordinary builds. */
EXPORT int tls20_pwd_test_element(PWD *s,unsigned char *out,size_t capacity) {
 if (s && s->ff_element) {
  if (capacity<s->width) return 0;
  return s->a.BN_bn2binpad(s->ff_element,out,(int)s->width);
 }
 if (!s || capacity<2*s->width) return 0;
 s->a.BN_CTX_start(s->ctx);BIGNUM *x=tmp(s),*y=tmp(s);int ok=0;
 if (y && s->a.EC_POINT_get_affine_coordinates(s->group,s->pe,x,y,s->ctx) &&
     s->a.BN_bn2binpad(x,out,(int)s->width)==(int)s->width &&
     s->a.BN_bn2binpad(y,out+s->width,(int)s->width)==(int)s->width) ok=(int)(2*s->width);
 s->a.BN_CTX_end(s->ctx);return ok;
}
#endif
