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
	int Plaintext, Ciphertext; // 입력차분에 대한 평문쌍
	int Plaintext_, Ciphertext_; // 평문쌍에 대응하는 암호문쌍
	int c1_inverse, c2_inverse; // 마지막라운드 복호화한 암호문쌍
	int result[0x8000] = { 0, }; // 경로와 일치하는 평문 리스트
	int count[16] = { 0, }; // 추측한 키로 복호화한 후 경로가 일치하는 평문쌍의 개수
	int count2 = 0; // 1차 추출 후 실제로 차분이 존재해야 할 곳에만 존재하는 쌍의 개수

	// 평문쌍 생성 & 1차 추출
	for (int i = 0; i < 0x8000; i++)
	{
		Plaintext = i;
		Plaintext_ = Plaintext ^ 0x5000;
		Encryption(Plaintext, &Ciphertext);
		Encryption(Plaintext_, &Ciphertext_);
		if (((Ciphertext ^ Ciphertext_)&0x0fff)==0)
		{
			result[i]++;
			count2++;
		}
	}

	// 1차 추출 결과 확인
	printf("출력차분이 경로와 맞는 암호문쌍의 개수는 %d개입니다. \n", count2);

	// 복호화 & 2차 추출
	for (int key = 0; key < 16; key++)
	{
		for (int i = 0; i < 0x8000; i++)
		{
			if (result[i] == 1)
			{
				Plaintext = i;
				Plaintext_ = i ^ 0x5000;
				Encryption(Plaintext, &Ciphertext);
				Encryption(Plaintext_, &Ciphertext_);
				Ciphertext = Ciphertext ^ (key * 0x1000);
				Substitution_Inverse(&Ciphertext, &c1_inverse);
				Ciphertext_ = Ciphertext_ ^ (key * 0x1000);
				Substitution_Inverse(&Ciphertext_, &c2_inverse);
				if ((c1_inverse ^ c2_inverse) == 0xc000)
					count[key]++;
			}
		}
	}

	// 추측한 키에 대한 count값 출력
	for (int s = 0; s < 16; s++)
		printf("[%d] %d ", s, count[s]);
	printf("\n");

	return 0;
}