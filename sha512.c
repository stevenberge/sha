/** Endianness testing and definitions */
#define TestEndianness(variable) {int i=1; variable=PCT_BIG_ENDIAN;\
        if (*((char*)&i)==1) variable=PCT_LITTLE_ENDIAN;}
#define PCT_LITTLE_ENDIAN 1
#define PCT_BIG_ENDIAN 0
/** Some useful types */
#ifndef Py_LL
#define Py_LL(x) x##LL
#endif
#ifndef Py_ULL
#define Py_ULL(x) Py_LL(x##U)
#endif
typedef unsigned char SHA_BYTE;
typedef unsigned int SHA_INT32; /** 32-bit integer */
#define PY_LONG_LONG long long
typedef unsigned PY_LONG_LONG SHA_INT64;        /** 64-bit integer */

/** The SHA block size and message digest sizes, in bytes */
#define SHA512_BLOCKSIZE   128
#define SHA512_DIGESTSIZE  64

/** The structure for storing SHA info */
typedef struct {
//    PyObject_HEAD
    SHA_INT64 digest[8];                /** Message digest */
    SHA_INT32 count_lo, count_hi;       /** 64-bit bit count */
    SHA_BYTE data[SHA512_BLOCKSIZE];       /** SHA data buffer */
    int Endianness;
    int local;                          /** unprocessed amount in data */
    int digestsize;
} SHAobject;

/** When run on a little-endian CPU we need to perform byte reversal on an
   array of longwords. */
static void longReverse(SHA_INT64 *buffer, int byteCount, int Endianness)
{
    SHA_INT64 value;

    if ( Endianness == PCT_BIG_ENDIAN )
        return;

    byteCount /= sizeof(*buffer);
    while (byteCount--) {
        value = *buffer;

                ((unsigned char*)buffer)[0] = (unsigned char)(value >> 56) & 0xff;
                ((unsigned char*)buffer)[1] = (unsigned char)(value >> 48) & 0xff;
                ((unsigned char*)buffer)[2] = (unsigned char)(value >> 40) & 0xff;
                ((unsigned char*)buffer)[3] = (unsigned char)(value >> 32) & 0xff;
                ((unsigned char*)buffer)[4] = (unsigned char)(value >> 24) & 0xff;
                ((unsigned char*)buffer)[5] = (unsigned char)(value >> 16) & 0xff;
                ((unsigned char*)buffer)[6] = (unsigned char)(value >>  8) & 0xff;
                ((unsigned char*)buffer)[7] = (unsigned char)(value      ) & 0xff;

                buffer++;
    }
}

static void SHAcopy(SHAobject *src, SHAobject *dest)
{
    dest->Endianness = src->Endianness;
    dest->local = src->local;
    dest->digestsize = src->digestsize;
    dest->count_lo = src->count_lo;
    dest->count_hi = src->count_hi;
    memcpy(dest->digest, src->digest, sizeof(src->digest));
    memcpy(dest->data, src->data, sizeof(src->data));
}


/** SHA512 by Tom St Denis */

/** Various logical functions */
#define ROR64(x, y) \
    ( ((((x) & Py_ULL(0xFFFFFFFFFFFFFFFF))>>((unsigned PY_LONG_LONG)(y) & 63)) | \
      ((x)<<((unsigned PY_LONG_LONG)(64-((y) & 63))))) & Py_ULL(0xFFFFFFFFFFFFFFFF))
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         ROR64((x),(n))
#define R(x, n)         (((x) & Py_ULL(0xFFFFFFFFFFFFFFFF)) >> ((unsigned PY_LONG_LONG)n))
#define Sigma0(x)       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x)       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x)       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x)       (S(x, 19) ^ S(x, 61) ^ R(x, 6))


static void
sha512_transform(SHAobject *sha_info)
{
    int i;
    SHA_INT64 S[8], W[80], t0, t1;

    memcpy(W, sha_info->data, sizeof(sha_info->data));
    longReverse(W, (int)sizeof(sha_info->data), sha_info->Endianness);

    for (i = 16; i < 80; ++i) {
                W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }
    for (i = 0; i < 8; ++i) {
        S[i] = sha_info->digest[i];
    }

    /** Compress */
#define RND(a,b,c,d,e,f,g,h,i,ki)                    \
     t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
     t1 = Sigma0(a) + Maj(a, b, c);                  \
     d += t0;                                        \
     h  = t0 + t1;

    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,Py_ULL(0x428a2f98d728ae22));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,Py_ULL(0x7137449123ef65cd));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,Py_ULL(0xb5c0fbcfec4d3b2f));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,Py_ULL(0xe9b5dba58189dbbc));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,Py_ULL(0x3956c25bf348b538));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,Py_ULL(0x59f111f1b605d019));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,Py_ULL(0x923f82a4af194f9b));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,Py_ULL(0xab1c5ed5da6d8118));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,Py_ULL(0xd807aa98a3030242));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,Py_ULL(0x12835b0145706fbe));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,Py_ULL(0x243185be4ee4b28c));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,Py_ULL(0x550c7dc3d5ffb4e2));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,Py_ULL(0x72be5d74f27b896f));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,Py_ULL(0x80deb1fe3b1696b1));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,Py_ULL(0x9bdc06a725c71235));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,Py_ULL(0xc19bf174cf692694));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,Py_ULL(0xe49b69c19ef14ad2));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,Py_ULL(0xefbe4786384f25e3));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,Py_ULL(0x0fc19dc68b8cd5b5));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,Py_ULL(0x240ca1cc77ac9c65));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,Py_ULL(0x2de92c6f592b0275));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,Py_ULL(0x4a7484aa6ea6e483));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,Py_ULL(0x5cb0a9dcbd41fbd4));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,Py_ULL(0x76f988da831153b5));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,Py_ULL(0x983e5152ee66dfab));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,Py_ULL(0xa831c66d2db43210));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,Py_ULL(0xb00327c898fb213f));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,Py_ULL(0xbf597fc7beef0ee4));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,Py_ULL(0xc6e00bf33da88fc2));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,Py_ULL(0xd5a79147930aa725));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,Py_ULL(0x06ca6351e003826f));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,Py_ULL(0x142929670a0e6e70));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,Py_ULL(0x27b70a8546d22ffc));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,Py_ULL(0x2e1b21385c26c926));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,Py_ULL(0x4d2c6dfc5ac42aed));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,Py_ULL(0x53380d139d95b3df));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,Py_ULL(0x650a73548baf63de));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,Py_ULL(0x766a0abb3c77b2a8));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,Py_ULL(0x81c2c92e47edaee6));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,Py_ULL(0x92722c851482353b));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,Py_ULL(0xa2bfe8a14cf10364));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,Py_ULL(0xa81a664bbc423001));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,Py_ULL(0xc24b8b70d0f89791));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,Py_ULL(0xc76c51a30654be30));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,Py_ULL(0xd192e819d6ef5218));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,Py_ULL(0xd69906245565a910));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,Py_ULL(0xf40e35855771202a));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,Py_ULL(0x106aa07032bbd1b8));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,Py_ULL(0x19a4c116b8d2d0c8));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,Py_ULL(0x1e376c085141ab53));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,Py_ULL(0x2748774cdf8eeb99));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,Py_ULL(0x34b0bcb5e19b48a8));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,Py_ULL(0x391c0cb3c5c95a63));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,Py_ULL(0x4ed8aa4ae3418acb));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,Py_ULL(0x5b9cca4f7763e373));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,Py_ULL(0x682e6ff3d6b2b8a3));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,Py_ULL(0x748f82ee5defb2fc));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,Py_ULL(0x78a5636f43172f60));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,Py_ULL(0x84c87814a1f0ab72));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,Py_ULL(0x8cc702081a6439ec));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,Py_ULL(0x90befffa23631e28));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,Py_ULL(0xa4506cebde82bde9));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,Py_ULL(0xbef9a3f7b2c67915));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,Py_ULL(0xc67178f2e372532b));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],64,Py_ULL(0xca273eceea26619c));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],65,Py_ULL(0xd186b8c721c0c207));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],66,Py_ULL(0xeada7dd6cde0eb1e));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],67,Py_ULL(0xf57d4f7fee6ed178));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],68,Py_ULL(0x06f067aa72176fba));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],69,Py_ULL(0x0a637dc5a2c898a6));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],70,Py_ULL(0x113f9804bef90dae));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],71,Py_ULL(0x1b710b35131c471b));
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],72,Py_ULL(0x28db77f523047d84));
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],73,Py_ULL(0x32caab7b40c72493));
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],74,Py_ULL(0x3c9ebe0a15c9bebc));
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],75,Py_ULL(0x431d67c49c100d4c));
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],76,Py_ULL(0x4cc5d4becb3e42b6));
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],77,Py_ULL(0x597f299cfc657e2a));
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],78,Py_ULL(0x5fcb6fab3ad6faec));
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],79,Py_ULL(0x6c44198c4a475817));

#undef RND

    /** feedback */
    for (i = 0; i < 8; i++) {
        sha_info->digest[i] = sha_info->digest[i] + S[i];
    }

}



/** initialize the SHA digest */

static void
sha512_init(SHAobject *sha_info)
{
    TestEndianness(sha_info->Endianness)
    sha_info->digest[0] = Py_ULL(0x6a09e667f3bcc908);
    sha_info->digest[1] = Py_ULL(0xbb67ae8584caa73b);
    sha_info->digest[2] = Py_ULL(0x3c6ef372fe94f82b);
    sha_info->digest[3] = Py_ULL(0xa54ff53a5f1d36f1);
    sha_info->digest[4] = Py_ULL(0x510e527fade682d1);
    sha_info->digest[5] = Py_ULL(0x9b05688c2b3e6c1f);
    sha_info->digest[6] = Py_ULL(0x1f83d9abfb41bd6b);
    sha_info->digest[7] = Py_ULL(0x5be0cd19137e2179);
    sha_info->count_lo = 0L;
    sha_info->count_hi = 0L;
    sha_info->local = 0;
    sha_info->digestsize = 64;
}

static void
sha384_init(SHAobject *sha_info)
{
    TestEndianness(sha_info->Endianness)
    sha_info->digest[0] = Py_ULL(0xcbbb9d5dc1059ed8);
    sha_info->digest[1] = Py_ULL(0x629a292a367cd507);
    sha_info->digest[2] = Py_ULL(0x9159015a3070dd17);
    sha_info->digest[3] = Py_ULL(0x152fecd8f70e5939);
    sha_info->digest[4] = Py_ULL(0x67332667ffc00b31);
    sha_info->digest[5] = Py_ULL(0x8eb44a8768581511);
    sha_info->digest[6] = Py_ULL(0xdb0c2e0d64f98fa7);
    sha_info->digest[7] = Py_ULL(0x47b5481dbefa4fa4);
    sha_info->count_lo = 0L;
    sha_info->count_hi = 0L;
    sha_info->local = 0;
    sha_info->digestsize = 48;
}


/** update the SHA digest */

static void
sha512_update(SHAobject *sha_info, SHA_BYTE *buffer, int count)
{
    int i;
    SHA_INT32 clo;

    clo = sha_info->count_lo + ((SHA_INT32) count << 3);
    if (clo < sha_info->count_lo) {
        ++sha_info->count_hi;
    }
    sha_info->count_lo = clo;
    sha_info->count_hi += (SHA_INT32) count >> 29;
    if (sha_info->local) {
        i = SHA512_BLOCKSIZE - sha_info->local;
        if (i > count) {
            i = count;
        }
        memcpy(((SHA_BYTE *) sha_info->data) + sha_info->local, buffer, i);
        count -= i;
        buffer += i;
        sha_info->local += i;
        if (sha_info->local == SHA512_BLOCKSIZE) {
            sha512_transform(sha_info);
        }
        else {
            return;
        }
    }
    while (count >= SHA512_BLOCKSIZE) {
        memcpy(sha_info->data, buffer, SHA512_BLOCKSIZE);
        buffer += SHA512_BLOCKSIZE;
        count -= SHA512_BLOCKSIZE;
        sha512_transform(sha_info);
    }
    memcpy(sha_info->data, buffer, count);
    sha_info->local = count;
}

/** finish computing the SHA digest */

static void
sha512_final(unsigned char digest[SHA512_DIGESTSIZE], SHAobject *sha_info)
{
    int count;
    SHA_INT32 lo_bit_count, hi_bit_count;

    lo_bit_count = sha_info->count_lo;
    hi_bit_count = sha_info->count_hi;
    count = (int) ((lo_bit_count >> 3) & 0x7f);
    ((SHA_BYTE *) sha_info->data)[count++] = 0x80;
    if (count > SHA512_BLOCKSIZE - 16) {
        memset(((SHA_BYTE *) sha_info->data) + count, 0,
               SHA512_BLOCKSIZE - count);
        sha512_transform(sha_info);
        memset((SHA_BYTE *) sha_info->data, 0, SHA512_BLOCKSIZE - 16);
    }
    else {
        memset(((SHA_BYTE *) sha_info->data) + count, 0,
               SHA512_BLOCKSIZE - 16 - count);
    }

    /** GJS: note that we add the hi/lo in big-endian. sha512_transform will
       swap these values into host-order. */
    sha_info->data[112] = 0;
    sha_info->data[113] = 0;
    sha_info->data[114] = 0;
    sha_info->data[115] = 0;
    sha_info->data[116] = 0;
    sha_info->data[117] = 0;
    sha_info->data[118] = 0;
    sha_info->data[119] = 0;
    sha_info->data[120] = (hi_bit_count >> 24) & 0xff;
    sha_info->data[121] = (hi_bit_count >> 16) & 0xff;
    sha_info->data[122] = (hi_bit_count >>  8) & 0xff;
    sha_info->data[123] = (hi_bit_count >>  0) & 0xff;
    sha_info->data[124] = (lo_bit_count >> 24) & 0xff;
    sha_info->data[125] = (lo_bit_count >> 16) & 0xff;
    sha_info->data[126] = (lo_bit_count >>  8) & 0xff;
    sha_info->data[127] = (lo_bit_count >>  0) & 0xff;
    sha512_transform(sha_info);
    digest[ 0] = (unsigned char) ((sha_info->digest[0] >> 56) & 0xff);
    digest[ 1] = (unsigned char) ((sha_info->digest[0] >> 48) & 0xff);
    digest[ 2] = (unsigned char) ((sha_info->digest[0] >> 40) & 0xff);
    digest[ 3] = (unsigned char) ((sha_info->digest[0] >> 32) & 0xff);
    digest[ 4] = (unsigned char) ((sha_info->digest[0] >> 24) & 0xff);
    digest[ 5] = (unsigned char) ((sha_info->digest[0] >> 16) & 0xff);
    digest[ 6] = (unsigned char) ((sha_info->digest[0] >>  8) & 0xff);
    digest[ 7] = (unsigned char) ((sha_info->digest[0]      ) & 0xff);
    digest[ 8] = (unsigned char) ((sha_info->digest[1] >> 56) & 0xff);
    digest[ 9] = (unsigned char) ((sha_info->digest[1] >> 48) & 0xff);
    digest[10] = (unsigned char) ((sha_info->digest[1] >> 40) & 0xff);
    digest[11] = (unsigned char) ((sha_info->digest[1] >> 32) & 0xff);
    digest[12] = (unsigned char) ((sha_info->digest[1] >> 24) & 0xff);
    digest[13] = (unsigned char) ((sha_info->digest[1] >> 16) & 0xff);
    digest[14] = (unsigned char) ((sha_info->digest[1] >>  8) & 0xff);
    digest[15] = (unsigned char) ((sha_info->digest[1]      ) & 0xff);
    digest[16] = (unsigned char) ((sha_info->digest[2] >> 56) & 0xff);
    digest[17] = (unsigned char) ((sha_info->digest[2] >> 48) & 0xff);
    digest[18] = (unsigned char) ((sha_info->digest[2] >> 40) & 0xff);
    digest[19] = (unsigned char) ((sha_info->digest[2] >> 32) & 0xff);
    digest[20] = (unsigned char) ((sha_info->digest[2] >> 24) & 0xff);
    digest[21] = (unsigned char) ((sha_info->digest[2] >> 16) & 0xff);
    digest[22] = (unsigned char) ((sha_info->digest[2] >>  8) & 0xff);
    digest[23] = (unsigned char) ((sha_info->digest[2]      ) & 0xff);
    digest[24] = (unsigned char) ((sha_info->digest[3] >> 56) & 0xff);
    digest[25] = (unsigned char) ((sha_info->digest[3] >> 48) & 0xff);
    digest[26] = (unsigned char) ((sha_info->digest[3] >> 40) & 0xff);
    digest[27] = (unsigned char) ((sha_info->digest[3] >> 32) & 0xff);
    digest[28] = (unsigned char) ((sha_info->digest[3] >> 24) & 0xff);
    digest[29] = (unsigned char) ((sha_info->digest[3] >> 16) & 0xff);
    digest[30] = (unsigned char) ((sha_info->digest[3] >>  8) & 0xff);
    digest[31] = (unsigned char) ((sha_info->digest[3]      ) & 0xff);
    digest[32] = (unsigned char) ((sha_info->digest[4] >> 56) & 0xff);
    digest[33] = (unsigned char) ((sha_info->digest[4] >> 48) & 0xff);
    digest[34] = (unsigned char) ((sha_info->digest[4] >> 40) & 0xff);
    digest[35] = (unsigned char) ((sha_info->digest[4] >> 32) & 0xff);
    digest[36] = (unsigned char) ((sha_info->digest[4] >> 24) & 0xff);
    digest[37] = (unsigned char) ((sha_info->digest[4] >> 16) & 0xff);
    digest[38] = (unsigned char) ((sha_info->digest[4] >>  8) & 0xff);
    digest[39] = (unsigned char) ((sha_info->digest[4]      ) & 0xff);
    digest[40] = (unsigned char) ((sha_info->digest[5] >> 56) & 0xff);
    digest[41] = (unsigned char) ((sha_info->digest[5] >> 48) & 0xff);
    digest[42] = (unsigned char) ((sha_info->digest[5] >> 40) & 0xff);
    digest[43] = (unsigned char) ((sha_info->digest[5] >> 32) & 0xff);
    digest[44] = (unsigned char) ((sha_info->digest[5] >> 24) & 0xff);
    digest[45] = (unsigned char) ((sha_info->digest[5] >> 16) & 0xff);
    digest[46] = (unsigned char) ((sha_info->digest[5] >>  8) & 0xff);
    digest[47] = (unsigned char) ((sha_info->digest[5]      ) & 0xff);
    digest[48] = (unsigned char) ((sha_info->digest[6] >> 56) & 0xff);
    digest[49] = (unsigned char) ((sha_info->digest[6] >> 48) & 0xff);
    digest[50] = (unsigned char) ((sha_info->digest[6] >> 40) & 0xff);
    digest[51] = (unsigned char) ((sha_info->digest[6] >> 32) & 0xff);
    digest[52] = (unsigned char) ((sha_info->digest[6] >> 24) & 0xff);
    digest[53] = (unsigned char) ((sha_info->digest[6] >> 16) & 0xff);
    digest[54] = (unsigned char) ((sha_info->digest[6] >>  8) & 0xff);
    digest[55] = (unsigned char) ((sha_info->digest[6]      ) & 0xff);
    digest[56] = (unsigned char) ((sha_info->digest[7] >> 56) & 0xff);
    digest[57] = (unsigned char) ((sha_info->digest[7] >> 48) & 0xff);
    digest[58] = (unsigned char) ((sha_info->digest[7] >> 40) & 0xff);
    digest[59] = (unsigned char) ((sha_info->digest[7] >> 32) & 0xff);
    digest[60] = (unsigned char) ((sha_info->digest[7] >> 24) & 0xff);
    digest[61] = (unsigned char) ((sha_info->digest[7] >> 16) & 0xff);
    digest[62] = (unsigned char) ((sha_info->digest[7] >>  8) & 0xff);
    digest[63] = (unsigned char) ((sha_info->digest[7]      ) & 0xff);
}

/**
 * End of copied SHA code.
 *
 * ------------------------------------------------------------------------
 */
void  getDigest_512(void *digest,void *input,int len){
    SHAobject mysha;
    sha512_init(&mysha);
    sha512_update(&mysha,input,len);
    sha512_final(digest,&mysha);
}
int main(){
    char digest[SHA512_DIGESTSIZE];
    char msg[2000];
    printf("please input a string:");
    scanf("%s",msg);
    printf("your input is:%s\n",msg);
    getDigest_512(digest,msg,strlen(msg));
    printf("your sha512 digest:\n");
    int i;for(i=0;i<SHA512_DIGESTSIZE;i++) printf("%02x",((unsigned char*)(digest))[i]);
    printf("\n");
    return 0;
}

