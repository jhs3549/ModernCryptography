#include<assert.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include"aes.h"

#define MUL2(a) (a<<1)^(a&0x80?0x1b:0)
#define MUL3(a) MUL2(a)^a
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^a
#define MULB(a) (MUL8(a))^(MUL2(a))^a
#define MULD(a) (MUL8(a))^(MUL4(a))^a
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

u8 mul(u8 a, u8 b)
{
	u8 r = 0;
	u8 tmp = b;
	u32 i = 0;
	for (i = 0; i < 8; i++)
	{
		if (a & 1)
			r ^= tmp;
		tmp = MUL2(tmp);
		a >>= 1;
	}
	return r;
}
u8 inv(u8 a)
{
	u8 r = a;

	r = mul(r, r);
	r = mul(r, a);
	r = mul(r, r);
	r = mul(r, a);
	r = mul(r, r);
	r = mul(r, a);
	r = mul(r, r);
	r = mul(r, a);
	r = mul(r, r);
	r = mul(r, a);
	r = mul(r, r);
	r = mul(r, a);
	r = mul(r, r);
	
	return r;
}

void SubBytes(u8 S[])
{
	S[0] = Sbox[S[0]]; S[1] = Sbox[S[1]]; S[2] = Sbox[S[2]]; S[3] = Sbox[S[3]];
	S[4] = Sbox[S[4]]; S[5] = Sbox[S[5]]; S[6] = Sbox[S[6]]; S[7] = Sbox[S[7]];
	S[8] = Sbox[S[8]]; S[9] = Sbox[S[9]]; S[10] = Sbox[S[10]]; S[11] = Sbox[S[11]];
	S[12] = Sbox[S[12]]; S[13] = Sbox[S[13]]; S[14] = Sbox[S[14]]; S[15] = Sbox[S[15]];
}
void ShiftRows(u8 S[])
{
	u8 tmp;
	tmp = S[1]; S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = tmp;
	tmp = S[2]; S[2] = S[10]; S[10] = tmp; tmp = S[6]; S[6] = S[14]; S[14] = tmp;
	tmp = S[15]; S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = tmp;
}
void MixColumns(u8 S[])
{
	u8 tmp[16];
	for (int i = 0; i < 4; i++)
	{
		tmp[i * 4 + 0] = MUL2(S[i * 4 + 0]) ^ MUL3(S[i * 4 + 1]) ^ S[i * 4 + 2] ^ S[i * 4 + 3];
		tmp[i * 4 + 1] = S[i * 4 + 0] ^ MUL2(S[i * 4 + 1]) ^ MUL3(S[i * 4 + 2]) ^ S[i * 4 + 3];
		tmp[i * 4 + 2] = S[i * 4 + 0] ^ S[i * 4 + 1] ^ MUL2(S[i * 4 + 2]) ^ MUL3(S[i * 4 + 3]);
		tmp[i * 4 + 3] = MUL3(S[i * 4 + 0]) ^ S[i * 4 + 1] ^ S[i * 4 + 2] ^ MUL2(S[i * 4 + 3]);
	}
	S[0] = tmp[0]; S[1] = tmp[1]; S[2] = tmp[2]; S[3] = tmp[3];
	S[4] = tmp[4]; S[5] = tmp[5]; S[6] = tmp[6]; S[7] = tmp[7];
	S[8] = tmp[8]; S[9] = tmp[9]; S[10] = tmp[10]; S[11] = tmp[11];
	S[12] = tmp[12]; S[13] = tmp[13]; S[14] = tmp[14]; S[15] = tmp[15];
}
void AddRoundKey(u8 S[], u8 RK[])
{
	S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
	S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
	S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
	S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
}

u32 u4byte_in(u8* x) 
{
	return ((x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]);
}
void u4byte_out(u8* x, u32 y)
{
	x[0] = (y >> 24) & 0xFF;
	x[1] = (y >> 16) & 0xFF;
	x[2] = (y >> 8) & 0xFF;
	x[3] = y & 0xFF;
}
void AES_KeyWordToByte(u32 w[], u8 RK[])
{
	for (int i = 0; i < 44; i++)
	{
		u4byte_out(RK + i * 4, w[i]);
	}
}
u32 Rcons[10] = { 0x01000000,0x02000000,0x04000000,0x08000000, 0x10000000, 
				0x20000000, 0x40000000,0x80000000, 0x1b000000, 0x36000000 };
#define RotWord(T) ((T<<8) | (T>>24))
#define SubWord(T)								\
	((u32)Sbox[(u8)(T >> 24) & 0xFF] << 24)		\
	| ((u32)Sbox[(u8)(T >> 16) & 0xFF] << 16)	\
	| ((u32)Sbox[(u8)(T >> 8) & 0xFF] << 8)		\
	| ((u32)Sbox[(u8)T & 0xFF])					
void RoundkeyGeneration128(u8 MK[], u8 RK[])
{
	u32 w[44];
	w[0] = u4byte_in(MK + 0);
	w[1] = u4byte_in(MK + 4);
	w[2] = u4byte_in(MK + 8);
	w[3] = u4byte_in(MK + 12);

	for (int i = 0; i < 10; i++)
	{
		u32 T = w[i * 4 + 3];
		T = RotWord(T);
		T = SubWord(T);
		T ^= Rcons[i];

		w[i * 4 + 4] = w[i * 4 + 0] ^ T;
		w[i * 4 + 5] = w[i * 4 + 4] ^ w[i * 4 + 1];
		w[i * 4 + 6] = w[i * 4 + 5] ^ w[i * 4 + 2];
		w[i * 4 + 7] = w[i * 4 + 6] ^ w[i * 4 + 3];
	}

	AES_KeyWordToByte(w, RK);
}
void RoundkeyGeneration128_Optimization(u8 MK[], u32 W[])
{
	W[0] = u4byte_in(MK + 0);
	W[1] = u4byte_in(MK + 4);
	W[2] = u4byte_in(MK + 8);
	W[3] = u4byte_in(MK + 12);

	for (int i = 0; i < 10; i++)
	{
		u32 T = W[i * 4 + 3];
		T = RotWord(T);
		T = SubWord(T);
		T ^= Rcons[i];

		W[i * 4 + 4] = W[i * 4 + 0] ^ T;
		W[i * 4 + 5] = W[i * 4 + 4] ^ W[i * 4 + 1];
		W[i * 4 + 6] = W[i * 4 + 5] ^ W[i * 4 + 2];
		W[i * 4 + 7] = W[i * 4 + 6] ^ W[i * 4 + 3];
	}
}

void AES_KeySchedule(u8 MK[], u8 RK[], int keysize)
{
	if (keysize == 128) RoundkeyGeneration128(MK, RK);
	//if (keysize == 192) RoundkeyGeneration192(MK, RK);
	//if (keysize == 256) RoundkeyGeneration256(MK, RK);
}
void AES_KeySchedule_Optimization(u8 MK[], u32 W[], int keysize)
{
	if (keysize == 128) RoundkeyGeneration128_Optimization(MK, W);
	//if (keysize == 192) RoundkeyGeneration192_Optimization(MK, W);
	//if (keysize == 256) RoundkeyGeneration256_Optimization(MK, W);
}

void AES_ENC(u8 PT[], u8 RK[], u8 CT[], int keysize)
{
	int Nr = keysize / 32 + 6;
	int i;
	u8 tmp[16]; 
	tmp[0] = PT[0];	tmp[1] = PT[1];	tmp[2] = PT[2];	tmp[3] = PT[3];
	tmp[4] = PT[4];	tmp[5] = PT[5];	tmp[6] = PT[6];	tmp[7] = PT[7];
	tmp[8] = PT[8];	tmp[9] = PT[9];	tmp[10] = PT[10]; tmp[11] = PT[11];
	tmp[12] = PT[12]; tmp[13] = PT[13]; tmp[14] = PT[14]; tmp[15] = PT[15];

	AddRoundKey(tmp, RK);

	for (i = 0; i < Nr - 1; i++)
	{
		SubBytes(tmp);
		ShiftRows(tmp);
		MixColumns(tmp);
		AddRoundKey(tmp, RK + 16 * (i + 1));
	}

	SubBytes(tmp);
	ShiftRows(tmp);
	AddRoundKey(tmp, RK + 16 * (i + 1));

	CT[0] = tmp[0]; CT[1] = tmp[1]; CT[2] = tmp[2]; CT[3] = tmp[3];	
	CT[4] = tmp[4]; CT[5] = tmp[5]; CT[6] = tmp[6]; CT[7] = tmp[7];
	CT[8] = tmp[8]; CT[9] = tmp[9]; CT[10] = tmp[10]; CT[11] = tmp[11];
	CT[12] = tmp[12]; CT[13] = tmp[13]; CT[14] = tmp[14]; CT[15] = tmp[15];
}
void AES_ENC_Optimization(u8 PT[], u32 W[], u8 CT[], int keysize)
{
	int Nr = keysize / 32 + 6;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = u4byte_in(PT + 0) ^ W[0];
	s1 = u4byte_in(PT + 4) ^ W[1];
	s2 = u4byte_in(PT + 8) ^ W[2];
	s3 = u4byte_in(PT + 12) ^ W[3];

	t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[4];
	t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[5];
	t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[6];
	t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[7];

	s0 = Te0[(t0 >> 24) & 0xff] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[8];
	s1 = Te0[(t1 >> 24) & 0xff] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[9];
	s2 = Te0[(t2 >> 24) & 0xff] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[10];
	s3 = Te0[(t3 >> 24) & 0xff] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[11];

	t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[12];
	t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[13];
	t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[14];
	t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[15];

	s0 = Te0[(t0 >> 24) & 0xff] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[16];
	s1 = Te0[(t1 >> 24) & 0xff] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[17];
	s2 = Te0[(t2 >> 24) & 0xff] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[18];
	s3 = Te0[(t3 >> 24) & 0xff] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[19];

	t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[20];
	t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[21];
	t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[22];
	t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[23];

	s0 = Te0[(t0 >> 24) & 0xff] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[24];
	s1 = Te0[(t1 >> 24) & 0xff] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[25];
	s2 = Te0[(t2 >> 24) & 0xff] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[26];
	s3 = Te0[(t3 >> 24) & 0xff] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[27];

	t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[28];
	t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[29];
	t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[30];
	t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[31];

	s0 = Te0[(t0 >> 24) & 0xff] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[32];
	s1 = Te0[(t1 >> 24) & 0xff] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[33];
	s2 = Te0[(t2 >> 24) & 0xff] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[34];
	s3 = Te0[(t3 >> 24) & 0xff] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[35];

	if (Nr == 10)
	{
		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		s0 = (Te2[(t0 >> 24)] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t3) & 0xff] & 0x000000ff) ^ W[40];
		s1 = (Te2[(t1 >> 24)] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t0) & 0xff] & 0x000000ff) ^ W[41];
		s2 = (Te2[(t2 >> 24)] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t1) & 0xff] & 0x000000ff) ^ W[42];
		s3 = (Te2[(t3 >> 24)] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t2) & 0xff] & 0x000000ff) ^ W[43];
	}
	else if (Nr == 12)
	{
		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		s0 = Te0[(t0 >> 24) & 0xff] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
		s1 = Te0[(t1 >> 24) & 0xff] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
		s2 = Te0[(t2 >> 24) & 0xff] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
		s3 = Te0[(t3 >> 24) & 0xff] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];

		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

		s0 = (Te2[(t0 >> 24)] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t3) & 0xff] & 0x000000ff) ^ W[48];
		s1 = (Te2[(t1 >> 24)] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t0) & 0xff] & 0x000000ff) ^ W[49];
		s2 = (Te2[(t2 >> 24)] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t1) & 0xff] & 0x000000ff) ^ W[50];
		s3 = (Te2[(t3 >> 24)] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t2) & 0xff] & 0x000000ff) ^ W[51];
	}
	else if (Nr == 14)
	{
		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		s0 = Te0[(t0 >> 24) & 0xff] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
		s1 = Te0[(t1 >> 24) & 0xff] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
		s2 = Te0[(t2 >> 24) & 0xff] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
		s3 = Te0[(t3 >> 24) & 0xff] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];

		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

		s0 = Te0[(t0 >> 24) & 0xff] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[48];
		s1 = Te0[(t1 >> 24) & 0xff] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[49];
		s2 = Te0[(t2 >> 24) & 0xff] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[50];
		s3 = Te0[(t3 >> 24) & 0xff] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[51];

		t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[52];
		t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[53];
		t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[54];
		t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[55];

		s0 = (Te2[(t0 >> 24)] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t3) & 0xff] & 0x000000ff) ^ W[56];
		s1 = (Te2[(t1 >> 24)] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t0) & 0xff] & 0x000000ff) ^ W[57];
		s2 = (Te2[(t2 >> 24)] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t1) & 0xff] & 0x000000ff) ^ W[58];
		s3 = (Te2[(t3 >> 24)] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[(t2) & 0xff] & 0x000000ff) ^ W[59];
	}

	u4byte_out(CT + 0, s0);
	u4byte_out(CT + 4, s1);
	u4byte_out(CT + 8, s2);
	u4byte_out(CT + 12, s3);
}

void XOR16Bytes(u8 S[], u8 RK[])
{
	S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
	S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
	S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
	S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
}
void ECB_Encryption(char* inputfile, char* outputfile, u32 W[])
{
	FILE* rfp, * wfp;
	u32 DataLen, i;
	u8* inputbuf, * outputbuf, r;

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL)
		perror("fopen_s failed!\n");

	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);

	r = DataLen % 16;
	r = 16 - r;

	inputbuf = (u8*)calloc(DataLen + r, sizeof(u8));
	outputbuf = (u8*)calloc(DataLen + r, sizeof(u8));

	fread(inputbuf, 1, DataLen, rfp);
	fclose(rfp);
	memset(inputbuf + DataLen, r, r);

	for (i = 0; i < (DataLen + r) / 16; i++)
	{
		AES_ENC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
	}

	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL)
		perror("fopen_s failed!\n");
	fwrite(outputbuf, 1, DataLen + r, wfp);
	fclose(wfp);
}
void CBC_Encryption(char* inputfile, char* outputfile, u32 W[])
{
	FILE* rfp, * wfp;
	u32 DataLen, i;
	u8* inputbuf, * outputbuf, r;
	u8 IV[16] = { 0x00, };

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL)
		perror("fopen_s failed!\n");

	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);

	r = DataLen % 16;
	r = 16 - r;

	inputbuf = (u8*)calloc(DataLen + r, sizeof(u8));
	outputbuf = (u8*)calloc(DataLen + r, sizeof(u8));

	fread(inputbuf, 1, DataLen, rfp);
	fclose(rfp);
	memset(inputbuf + DataLen, r, r);

	XOR16Bytes(inputbuf, IV);
	AES_ENC_Optimization(inputbuf, W, outputbuf, 128);
	for (i = 1; i < (DataLen + r) / 16; i++)
	{
		XOR16Bytes(inputbuf + 16 * i, outputbuf + 16 * (i - 1));
		AES_ENC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
	}

	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL)
		perror("fopen_s failed!\n");
	fwrite(outputbuf, 1, DataLen + r, wfp);
	fclose(wfp);
}

static int hex2bytes(const char *hex, unsigned char *out, size_t outlen) 
{
    size_t n = 0;
    int hi, lo;
    #define HEXVAL(c) ((c)>='0'&&(c)<='9'?(c)-'0':(c)>='a'&&(c)<='f'?(c)-'a'+10:(c)>='A'&&(c)<='F'?(c)-'A'+10:-1)
    while (hex[0] && hex[1]) 
	{
        hi = HEXVAL(hex[0]); lo = HEXVAL(hex[1]);
        if (hi < 0 || lo < 0 || n >= outlen) return -1;
        out[n++] = (unsigned char)((hi<<4)|lo);
        hex += 2;
    }
    return (int)n;
}

static int load_key_from_file(const char *path, unsigned char *out, size_t need) 
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t n = fread(out, 1, need, fp);
    fclose(fp);
    return (n == need) ? 0 : -1;
}

static int get_key_from_args(int argc, char **argv, unsigned char *MK, int *keysize_bits) 
{
    const char *hex = NULL, *file = NULL, *envname = "AES_KEY", *envv = NULL;
    *keysize_bits = 128;         

    for (int i = 1; i < argc; ++i) 
	{
        if (strcmp(argv[i], "--key-hex") == 0 && i+1 < argc) hex = argv[++i];
        else if (strcmp(argv[i], "--key-file") == 0 && i+1 < argc) file = argv[++i];
        else if (strcmp(argv[i], "--key-env") == 0 && i+1 < argc) envname = argv[++i];
        else if (strcmp(argv[i], "--keysize") == 0 && i+1 < argc) *keysize_bits = atoi(argv[++i]); 
    }
    if (hex) 
	{
        int need = (*keysize_bits==256?32:(*keysize_bits==192?24:16));
        int n = hex2bytes(hex, MK, (size_t)need);
        return (n == need) ? 0 : -1;
    }
    if (file) 
	{
        size_t need = (size_t)(*keysize_bits==256?32:(*keysize_bits==192?24:16));
        return load_key_from_file(file, MK, need);
    }
    envv = getenv(envname);
    if (envv && *envv) 
	{
        int need = (*keysize_bits==256?32:(*keysize_bits==192?24:16));
        int n = hex2bytes(envv, MK, (size_t)need);
        return (n == need) ? 0 : -1;
    }
    return -1;
}

static void print_usage_enc(void) 
{
    fprintf(stderr,
      "Usage:\n"
      "  aes_enc ecb <in> <out> [--key-hex HEX | --key-file KEYBIN | --key-env VAR] [--keysize 128|192|256]\n"
      "  aes_enc cbc <in> <out> [same key options]\n");
}

int main(int argc, char* argv[])
{
    unsigned char MK[32] = {0};  
    unsigned int W[60];         
    int keysize = 128;         
    if (argc < 4) { print_usage_enc(); return 1; }

    if (get_key_from_args(argc, argv, MK, &keysize) != 0) 
	{
        fprintf(stderr, "[ERR] key is required. Provide --key-hex / --key-file / --key-env\n");
        print_usage_enc();
        return 2;
    }

    AES_KeySchedule_Optimization(MK, W, keysize);

    if (strcmp(argv[1], "ecb") == 0) 
	{
        ECB_Encryption(argv[2], argv[3], W);
    } 
	else if (strcmp(argv[1], "cbc") == 0) 
	{
        CBC_Encryption(argv[2], argv[3], W);
    } 
	else 
	{
        fprintf(stderr, "[ERR] unknown mode '%s'\n", argv[1]);
        print_usage_enc();
        return 3;
    }
    return 0;
}