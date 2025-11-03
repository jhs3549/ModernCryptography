// TestAppDll.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int Sbox[16] = {0xE, 0x3, 0x0, 0x7, 0x2, 0xC, 0xF, 0xB, 0x5, 0xA, 0x6, 0x9, 0x8, 0x1, 0x4, 0xD};
int InverseSbox[16] = {0x2, 0xD, 0x4, 0x1, 0xE, 0x8, 0xA, 0x3, 0xC, 0xB, 0x9, 0x7, 0x5, 0xF, 0x0, 0x6};

extern "C" __declspec(dllexport) void Substitution(int* p, int* c)
{
	*c = (Sbox[(*p>>12 & 0xf)]<<12) | (Sbox[(*p>>8 & 0xf)]<<8) | (Sbox[(*p>>4  & 0xf)]<<4 ) | (Sbox[(*p    & 0xf)]   ) ;
}

extern "C" __declspec(dllexport) void Permutation(int* p, int* c)
{
	*c = ((*p>>15 & 1)<<15) | ((*p>>11 & 1)<<14) | ((*p>>7  & 1)<<13) | ((*p>>3  & 1)<<12) |
		((*p>>14 & 1)<<11) | ((*p>>10 & 1)<<10) | ((*p>>6  & 1)<<9 ) | ((*p>>2  & 1)<<8 ) |
		((*p>>13 & 1)<<7 ) | ((*p>>9  & 1)<<6 ) | ((*p>>5  & 1)<<5 ) | ((*p>>1  & 1)<<4 ) |
		((*p>>12 & 1)<<3 ) | ((*p>>8  & 1)<<2 ) | ((*p>>4  & 1)<<1 ) | ((*p     & 1)    ) ;
}

extern "C" __declspec(dllexport) void Substitution_Inverse(int* p, int* c)
{
	*c = (InverseSbox[(*p>>12 & 0xf)]<<12) | (InverseSbox[(*p>>8 & 0xf)]<<8) | 
		 (InverseSbox[(*p>>4  & 0xf)]<<4 ) | (InverseSbox[(*p    & 0xf)]   ) ;
}

extern "C" __declspec(dllimport) void Substitution(int* p, int* c);
extern "C" __declspec(dllimport) void Substitution_Inverse(int* p, int* c);
extern "C" __declspec(dllimport) void Permutation(int* p, int* c);
extern "C" __declspec(dllimport) void Encryption(int P, int* C);

int main(int argc, char* argv[])
{
	int Plaintext, Ciphertext; // 평문과 암호문
	int InputMasking = 0x200, OutputMasking = 0x80; // 경로의 입력마스킹과 최종 출력마스킹
	int Masked_Plaintext, Masked_Ciphertext; // 마스킹으로 걸러낸 평문과 암호문(&연산)
	int Inversed_Ciphertext; // 마지막 두 라운드를 복호화한 암호문
	int BitCount = 0, result = 0; // 몇개 비트를 xor했는지 확인용 & xor한 결과 저장용
	int KeyCount[16] = { 0, }; // 추측한 16개 키 각각의 count값 저장

	// 사용한 평문의 개수는 경로와 무관하게 0x8000개로 지정하였음
	for (Plaintext = 0; Plaintext < 0x8000; Plaintext++) 
	{
		Encryption(Plaintext, &Ciphertext);
		Ciphertext ^= 0xAA71; // 마지막라운드키 xor
		Substitution_Inverse(&Ciphertext, &Ciphertext); // 마지막라운드 S박스 역연산
		Permutation(&Ciphertext, &Ciphertext); // Permutation의 역연산은 Permutation

		// 16개 키 추측 후 경로와 일치하면 키의 count값 ++
		for (int Permutated_Key = 0; Permutated_Key < 16; Permutated_Key++)
		{
			Inversed_Ciphertext = Ciphertext ^ (Permutated_Key * 0x10);
			Substitution_Inverse(&Inversed_Ciphertext, &Inversed_Ciphertext);
			Masked_Plaintext = Plaintext & InputMasking;
			Masked_Ciphertext = Inversed_Ciphertext & OutputMasking;
			while (BitCount < 16)
			{
				result ^= (Masked_Plaintext & 0x1);
				Masked_Plaintext >>= 1;
				BitCount++;
			}
			while (BitCount < 32)
			{
				result ^= (Masked_Ciphertext & 0x1);
				Masked_Ciphertext >>= 1;
				BitCount++;
			}
			if (result == 0)
				KeyCount[Permutated_Key]++;
			result = 0; BitCount = 0;
		}
	}

	// 키의 count값 출력
	for (int i = 0; i < 16; i++)
		printf("[%X] %5d  ", i, (KeyCount[i] - 0x4000));
	printf("\n");

	return 0;
}