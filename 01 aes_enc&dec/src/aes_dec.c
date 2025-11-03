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

void invSubBytes(u8 S[]) // ���� �� ����Ʈ�� invSbox�� �־ ��ü
{
	S[0] = invSbox[S[0]]; S[1] = invSbox[S[1]]; S[2] = invSbox[S[2]]; S[3] = invSbox[S[3]];
	S[4] = invSbox[S[4]]; S[5] = invSbox[S[5]]; S[6] = invSbox[S[6]]; S[7] = invSbox[S[7]];
	S[8] = invSbox[S[8]]; S[9] = invSbox[S[9]]; S[10] = invSbox[S[10]]; S[11] = invSbox[S[11]];
	S[12] = invSbox[S[12]]; S[13] = invSbox[S[13]]; S[14] = invSbox[S[14]]; S[15] = invSbox[S[15]];
}
void invShiftRows(u8 S[])
{
	u8 tmp;
	tmp = S[13]; S[13] = S[9]; S[9] = S[5]; S[5] = S[1]; S[1] = tmp;
	tmp = S[6]; S[6] = S[14]; S[14] = tmp; tmp = S[2]; S[2] = S[10]; S[10] = tmp;
	tmp = S[3]; S[3] = S[7]; S[7] = S[11]; S[11] = S[15]; S[15] = tmp;
}
void invMixColumns(u8 S[]) // ����� �������� ���� �״�� ����
{
	u8 tmp[16];
	for (int i = 0; i < 4; i++) // for�� �ѹ����� 1word�� �����Ͽ� �� 4ȸ �ݺ�
	{
		tmp[i * 4 + 0] = MULE(S[i * 4 + 0]) ^ MULB(S[i * 4 + 1]) ^ MULD(S[i * 4 + 2]) ^ MUL9(S[i * 4 + 3]);
		tmp[i * 4 + 1] = MUL9(S[i * 4 + 0]) ^ MULE(S[i * 4 + 1]) ^ MULB(S[i * 4 + 2]) ^ MULD(S[i * 4 + 3]);
		tmp[i * 4 + 2] = MULD(S[i * 4 + 0]) ^ MUL9(S[i * 4 + 1]) ^ MULE(S[i * 4 + 2]) ^ MULB(S[i * 4 + 3]);
		tmp[i * 4 + 3] = MULB(S[i * 4 + 0]) ^ MULD(S[i * 4 + 1]) ^ MUL9(S[i * 4 + 2]) ^ MULE(S[i * 4 + 3]);
	}
	S[0] = tmp[0]; S[1] = tmp[1]; S[2] = tmp[2]; S[3] = tmp[3];
	S[4] = tmp[4]; S[5] = tmp[5]; S[6] = tmp[6]; S[7] = tmp[7];
	S[8] = tmp[8]; S[9] = tmp[9]; S[10] = tmp[10]; S[11] = tmp[11];
	S[12] = tmp[12]; S[13] = tmp[13]; S[14] = tmp[14]; S[15] = tmp[15];
}
void invAddRoundKey(u8 S[], u8 RK[]) // ����Ű�� XOR����
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
void RoundkeyGeneration128_Optimization(u8 MK[], u32 W[]) // ����Ű �����Լ� ����ȭ�ڵ�
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
	// �������� Word -> Byte ����
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

void AES_DEC(u8 CT[], u8 RK[], u8 PT[], int keysize)
{
	int Nr = keysize / 32 + 6; // ���� �� ���
	int i;
	u8 tmp[16]; // ���ڷ� ���� ��ȣ���� tmp�� �־��ֱ�
	tmp[0] = CT[0];	tmp[1] = CT[1];	tmp[2] = CT[2];	tmp[3] = CT[3];
	tmp[4] = CT[4];	tmp[5] = CT[5];	tmp[6] = CT[6];	tmp[7] = CT[7];
	tmp[8] = CT[8];	tmp[9] = CT[9];	tmp[10] = CT[10]; tmp[11] = CT[11];
	tmp[12] = CT[12]; tmp[13] = CT[13]; tmp[14] = CT[14]; tmp[15] = CT[15];

	// ��ȣȭ�� Nr ����
	invAddRoundKey(tmp, RK + Nr * 16);
	invShiftRows(tmp);
	invSubBytes(tmp);

	// ��ȣȭ�� Nr-1 ���� ~ 1 ���� (�ݺ��� �� Nr-1ȸ �ݺ�)
	for (i = 0; i < Nr - 1; i++)
	{
		invAddRoundKey(tmp, RK + 16 * (Nr - 1 - i));
		invMixColumns(tmp);
		invShiftRows(tmp);
		invSubBytes(tmp);
	}

	// ��ȣȭ�� 0 ����
	invAddRoundKey(tmp, RK);

	PT[0] = tmp[0]; PT[1] = tmp[1]; PT[2] = tmp[2]; PT[3] = tmp[3];
	PT[4] = tmp[4]; PT[5] = tmp[5]; PT[6] = tmp[6]; PT[7] = tmp[7];
	PT[8] = tmp[8]; PT[9] = tmp[9]; PT[10] = tmp[10]; PT[11] = tmp[11];
	PT[12] = tmp[12]; PT[13] = tmp[13]; PT[14] = tmp[14]; PT[15] = tmp[15];
}
void AES_DEC_Optimization(u8 CT[], u32 W[], u8 PT[], int keysize)
{
	int Nr = keysize / 32 + 6;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
	
	// (��ȣȭ����) Round 0 (��ȣȭ������������ AddRoundKey)
	s0 = u4byte_in(CT + 0) ^ W[Nr * 4 + 0];
	s1 = u4byte_in(CT + 4) ^ W[Nr * 4 + 1];
	s2 = u4byte_in(CT + 8) ^ W[Nr * 4 + 2];
	s3 = u4byte_in(CT + 12) ^ W[Nr * 4 + 3];

	// (��ȣȭ����) Round 1 ~ Round Nr-2 (invSbox -> invShiiftRows -> invMixColumns -> invAddRoundKey)
	for (int i = 0; i <= Nr - 4; i += 2) // 128bit(10����)���� 2�� ���徿 4�� �ݺ��Ͽ� �� 8�� ���� ���� 
	{
		// ��ȣȭ���� 1,3,5,7
		t0 = invTe0[(s0 >> 24) & 0xff] ^ invTe1[(s3 >> 16) & 0xff] ^ invTe2[(s2 >> 8) & 0xff] ^ invTe3[(s1) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 1) * 4] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 1) * 4] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 1) * 4] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 1) * 4]) & 0xff]];
		t1 = invTe0[(s1 >> 24) & 0xff] ^ invTe1[(s0 >> 16) & 0xff] ^ invTe2[(s3 >> 8) & 0xff] ^ invTe3[(s2) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 1) * 4 + 1] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 1) * 4 + 1] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 1) * 4 + 1] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 1) * 4 + 1]) & 0xff]];
		t2 = invTe0[(s2 >> 24) & 0xff] ^ invTe1[(s1 >> 16) & 0xff] ^ invTe2[(s0 >> 8) & 0xff] ^ invTe3[(s3) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 1) * 4 + 2] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 1) * 4 + 2] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 1) * 4 + 2] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 1) * 4 + 2]) & 0xff]];
		t3 = invTe0[(s3 >> 24) & 0xff] ^ invTe1[(s2 >> 16) & 0xff] ^ invTe2[(s1 >> 8) & 0xff] ^ invTe3[(s0) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 1) * 4 + 3] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 1) * 4 + 3] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 1) * 4 + 3] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 1) * 4 + 3]) & 0xff]];
		
		// ��ȣȭ���� 2,4,6,8
		s0 = invTe0[(t0 >> 24) & 0xff] ^ invTe1[(t3 >> 16) & 0xff] ^ invTe2[(t2 >> 8) & 0xff] ^ invTe3[(t1) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 2) * 4] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 2) * 4] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 2) * 4] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 2) * 4]) & 0xff]];
		s1 = invTe0[(t1 >> 24) & 0xff] ^ invTe1[(t0 >> 16) & 0xff] ^ invTe2[(t3 >> 8) & 0xff] ^ invTe3[(t2) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 2) * 4 + 1] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 2) * 4 + 1] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 2) * 4 + 1] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 2) * 4 + 1]) & 0xff]];
		s2 = invTe0[(t2 >> 24) & 0xff] ^ invTe1[(t1 >> 16) & 0xff] ^ invTe2[(t0 >> 8) & 0xff] ^ invTe3[(t3) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 2) * 4 + 2] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 2) * 4 + 2] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 2) * 4 + 2] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 2) * 4 + 2]) & 0xff]];
		s3 = invTe0[(t3 >> 24) & 0xff] ^ invTe1[(t2 >> 16) & 0xff] ^ invTe2[(t1 >> 8) & 0xff] ^ invTe3[(t0) & 0xff] 
			^ invTe0[Sbox[(W[(Nr - i - 2) * 4 + 3] >> 24) & 0xff]] ^ invTe1[Sbox[(W[(Nr - i - 2) * 4 + 3] >> 16) & 0xff]] 
			^ invTe2[Sbox[(W[(Nr - i - 2) * 4 + 3] >> 8) & 0xff]] ^ invTe3[Sbox[(W[(Nr - i - 2) * 4 + 3]) & 0xff]];
	}

	// (��ȣȭ����) Round Nr-1 (invSbox -> invShiiftRows -> invMixColumns -> invAddRoundKey)
	t0 = invTe0[(s0 >> 24) & 0xff] ^ invTe1[(s3 >> 16) & 0xff] ^ invTe2[(s2 >> 8) & 0xff] ^ invTe3[(s1) & 0xff] 
		^ invTe0[Sbox[(W[4] >> 24) & 0xff]] ^ invTe1[Sbox[(W[4] >> 16) & 0xff]] ^ invTe2[Sbox[(W[4] >> 8) & 0xff]] ^ invTe3[Sbox[(W[4]) & 0xff]];
	t1 = invTe0[(s1 >> 24) & 0xff] ^ invTe1[(s0 >> 16) & 0xff] ^ invTe2[(s3 >> 8) & 0xff] ^ invTe3[(s2) & 0xff] 
		^ invTe0[Sbox[(W[5] >> 24) & 0xff]] ^ invTe1[Sbox[(W[5] >> 16) & 0xff]] ^ invTe2[Sbox[(W[5] >> 8) & 0xff]] ^ invTe3[Sbox[(W[5]) & 0xff]];
	t2 = invTe0[(s2 >> 24) & 0xff] ^ invTe1[(s1 >> 16) & 0xff] ^ invTe2[(s0 >> 8) & 0xff] ^ invTe3[(s3) & 0xff] 
		^ invTe0[Sbox[(W[6] >> 24) & 0xff]] ^ invTe1[Sbox[(W[6] >> 16) & 0xff]] ^ invTe2[Sbox[(W[6] >> 8) & 0xff]] ^ invTe3[Sbox[(W[6]) & 0xff]];
	t3 = invTe0[(s3 >> 24) & 0xff] ^ invTe1[(s2 >> 16) & 0xff] ^ invTe2[(s1 >> 8) & 0xff] ^ invTe3[(s0) & 0xff] 
		^ invTe0[Sbox[(W[7] >> 24) & 0xff]] ^ invTe1[Sbox[(W[7] >> 16) & 0xff]] ^ invTe2[Sbox[(W[7] >> 8) & 0xff]] ^ invTe3[Sbox[(W[7]) & 0xff]];


	// (��ȣȭ����) Round Nr - Version 1 (invShiftRows -> invSbox -> invAddRoundKey) (���� ����ʹ� �޸� invTe���̺��� ������� ����)
	s0 = ((u32)invSbox[(t0 >> 24) & 0xff] << 24) ^ ((u32)invSbox[(t3 >> 16) & 0xff] << 16) ^ ((u32)invSbox[(t2 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(t1) & 0xff]) ^ W[0];
	s1 = ((u32)invSbox[(t1 >> 24) & 0xff] << 24) ^ ((u32)invSbox[(t0 >> 16) & 0xff] << 16) ^ ((u32)invSbox[(t3 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(t2) & 0xff]) ^ W[1];
	s2 = ((u32)invSbox[(t2 >> 24) & 0xff] << 24) ^ ((u32)invSbox[(t1 >> 16) & 0xff] << 16) ^ ((u32)invSbox[(t0 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(t3) & 0xff]) ^ W[2];
	s3 = ((u32)invSbox[(t3 >> 24) & 0xff] << 24) ^ ((u32)invSbox[(t2 >> 16) & 0xff] << 16) ^ ((u32)invSbox[(t1 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(t0) & 0xff]) ^ W[3];
	

	// (��ȣȭ����) Round Nr - Version 2 (invSbox -> invShiftRows -> invAddRoundKey) (���� ����ó�� invTe���̺��� �����) 
	s0 = (invTe0[t0 >> 24] ^ invTe1[t0 >> 24] ^ invTe2[t0 >> 24] ^ invTe3[t0 >> 24]) & 0xff000000 
		^ (invTe0[(t3 >> 16) & 0xff] ^ invTe1[(t3 >> 16) & 0xff] ^ invTe2[(t3 >> 16) & 0xff] ^ invTe3[(t3 >> 16) & 0xff]) & 0xff0000 
		^ (invTe0[(t2 >> 8) & 0xff] ^ invTe1[(t2 >> 8) & 0xff] ^ invTe2[(t2 >> 8) & 0xff] ^ invTe3[(t2 >> 8) & 0xff]) & 0xff00 
		^ (invTe0[t1 & 0xff] ^ invTe1[t1 & 0xff] ^ invTe2[t1 & 0xff] ^ invTe3[t1 & 0xff]) & 0xff ^ W[0];
	s1 = (invTe0[t1 >> 24] ^ invTe1[t1 >> 24] ^ invTe2[t1 >> 24] ^ invTe3[t1 >> 24]) & 0xff000000 
		^ (invTe0[(t0 >> 16) & 0xff] ^ invTe1[(t0 >> 16) & 0xff] ^ invTe2[(t0 >> 16) & 0xff] ^ invTe3[(t0 >> 16) & 0xff]) & 0xff0000 
		^ (invTe0[(t3 >> 8) & 0xff] ^ invTe1[(t3 >> 8) & 0xff] ^ invTe2[(t3 >> 8) & 0xff] ^ invTe3[(t3 >> 8) & 0xff]) & 0xff00 
		^ (invTe0[t2 & 0xff] ^ invTe1[t2 & 0xff] ^ invTe2[t2 & 0xff] ^ invTe3[t2 & 0xff]) & 0xff ^ W[1];
	s2 = (invTe0[t2 >> 24] ^ invTe1[t2 >> 24] ^ invTe2[t2 >> 24] ^ invTe3[t2 >> 24]) & 0xff000000 
		^ (invTe0[(t1 >> 16) & 0xff] ^ invTe1[(t1 >> 16) & 0xff] ^ invTe2[(t1 >> 16) & 0xff] ^ invTe3[(t1 >> 16) & 0xff]) & 0xff0000 
		^ (invTe0[(t0 >> 8) & 0xff] ^ invTe1[(t0 >> 8) & 0xff] ^ invTe2[(t0 >> 8) & 0xff] ^ invTe3[(t0 >> 8) & 0xff]) & 0xff00 
		^ (invTe0[t3 & 0xff] ^ invTe1[t3 & 0xff] ^ invTe2[t3 & 0xff] ^ invTe3[t3 & 0xff]) & 0xff ^ W[2];
	s3 = (invTe0[t3 >> 24] ^ invTe1[t3 >> 24] ^ invTe2[t3 >> 24] ^ invTe3[t3 >> 24]) & 0xff000000 
		^ (invTe0[(t2 >> 16) & 0xff] ^ invTe1[(t2 >> 16) & 0xff] ^ invTe2[(t2 >> 16) & 0xff] ^ invTe3[(t2 >> 16) & 0xff]) & 0xff0000 
		^ (invTe0[(t1 >> 8) & 0xff] ^ invTe1[(t1 >> 8) & 0xff] ^ invTe2[(t1 >> 8) & 0xff] ^ invTe3[(t1 >> 8) & 0xff]) & 0xff00 
		^ (invTe0[t0 & 0xff] ^ invTe1[t0 & 0xff] ^ invTe2[t0 & 0xff] ^ invTe3[t0 & 0xff]) & 0xff ^ W[3];
	
	u4byte_out(PT, s0);
	u4byte_out(PT + 4, s1);
	u4byte_out(PT + 8, s2);
	u4byte_out(PT + 12, s3);
}

void invXOR16Bytes(u8 S[], u8 RK[]) // S ^ RK = S
{
	S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
	S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
	S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
	S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
}
void ECB_Decryption(char* inputfile, char* outputfile, u32 W[], int keysize)
{
	FILE* rfp, * wfp;
	u8* inputbuf, * outputbuf;
	u32 DataLen, i;

	fopen_s(&rfp, inputfile, "rb");
	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);
	inputbuf = (u8*)calloc(DataLen, sizeof(u8));
	outputbuf = (u8*)calloc(DataLen, sizeof(u8));
	fread(inputbuf, sizeof(u8), DataLen, rfp);
	fclose(rfp);

	for (i = 0; i < DataLen / 16; i++)
	{
		AES_DEC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, keysize);
	}

	fopen_s(&wfp, outputfile, "wb");
	fwrite(outputbuf, sizeof(u8), DataLen - *(outputbuf + DataLen - 1), wfp);
	fclose(wfp);
}
void CBC_Decryption(char* inputfile, char* outputfile, u32 W[], int keysize)
{
	FILE* rfp, * wfp;
	u8* inputbuf, * outputbuf;
	int DataLen, i;
	u8 IV[16] = { 0x00, };

	fopen_s(&rfp, inputfile, "rb");
	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);
	inputbuf = (u8*)calloc(DataLen, sizeof(u8));
	outputbuf = (u8*)calloc(DataLen, sizeof(u8));
	fread(inputbuf, sizeof(u8), DataLen, rfp);
	fclose(rfp);

	for (i = 0; i < DataLen / 16 - 1; i++)
	{
		AES_DEC_Optimization(inputbuf + DataLen - 16 * (i + 1), W, outputbuf + DataLen - 16 * (i + 1), keysize);
		invXOR16Bytes(outputbuf + DataLen - 16 * (i + 1), inputbuf + DataLen - 16 * (i + 2));
	}
	AES_DEC_Optimization(inputbuf, W, outputbuf, keysize);
	invXOR16Bytes(outputbuf, IV);

	fopen_s(&wfp, outputfile, "wb");
	fwrite(outputbuf, sizeof(u8), DataLen - (u32) * (outputbuf + DataLen - 1), wfp);
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

static void print_usage_dec(void) 
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
    if (argc < 4) { print_usage_dec(); return 1; }

    if (get_key_from_args(argc, argv, MK, &keysize) != 0) 
	{
        fprintf(stderr, "[ERR] key is required. Provide --key-hex / --key-file / --key-env\n");
        print_usage_dec();
        return 2;
    }

    AES_KeySchedule_Optimization(MK, W, keysize);

    if (strcmp(argv[1], "ecb") == 0) 
	{
        ECB_Decryption(argv[2], argv[3], W, keysize);
    } 
	else if (strcmp(argv[1], "cbc") == 0) 
	{
        CBC_Decryption(argv[2], argv[3], W, keysize);
    } 
	else 
	{
        fprintf(stderr, "[ERR] unknown mode '%s'\n", argv[1]);
        print_usage_dec();
        return 3;
    }
    return 0;
}
