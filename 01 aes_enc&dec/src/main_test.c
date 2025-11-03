#include <stdio.h>
#include <string.h>
#include "aes.h"

typedef unsigned char u8;
typedef unsigned int  u32;

extern void AES_KeySchedule_Optimization(u8 MK[], u32 W[], int keysize);
extern void ECB_Encryption(char* inputfile, char* outputfile, u32 W[]);
extern void ECB_Decryption(char* inputfile, char* outputfile, u32 W[], int keysize);

static const char *K_HEX = "000102030405060708090A0B0C0D0E0F";
static const unsigned char PT[16] = 
{
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
};
static const unsigned char CT_EXPECT[16] = 
{
  0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A
};

static int hex2bytes(const char *hex, unsigned char *out, size_t outlen) 
{
    size_t n=0; int hi,lo;
    #define HEXVAL(c) ((c)>='0'&&(c)<='9'?(c)-'0':(c)>='a'&&(c)<='f'?(c)-'a'+10:(c)>='A'&&(c)<='F'?(c)-'A'+10:-1)
    while(hex[0]&&hex[1]) 
    { 
        hi=HEXVAL(hex[0]); 
        lo=HEXVAL(hex[1]); 
        if(hi<0||lo<0||n>=outlen)
            return -1; 
        out[n++]=(unsigned char)((hi<<4)|lo); 
        hex+=2; 
    }
    return (int)n;
}

int main(void) 
{
    unsigned char MK[16]={0};
    unsigned int  W[60];
    if (hex2bytes(K_HEX, MK, sizeof(MK)) != 16) { fprintf(stderr,"hex2bytes fail\n"); return 1; }
    AES_KeySchedule_Optimization(MK, W, 128);

    FILE *fp = fopen("pt.bin","wb"); fwrite(PT,1,16,fp); fclose(fp);

    ECB_Encryption("pt.bin","ct.bin", W);
    ECB_Decryption("ct.bin","rt.bin", W, 128);

    unsigned char buf[16]={0};
    fp = fopen("ct.bin","rb"); fread(buf,1,16,fp); fclose(fp);
    if (memcmp(buf, CT_EXPECT, 16) != 0) { printf("Cipher mismatch\n"); return 2; }

    unsigned char buf2[16]={0};
    fp = fopen("rt.bin","rb"); fread(buf2,1,16,fp); fclose(fp);
    if (memcmp(buf2, PT, 16) != 0) { printf("Decrypt mismatch\n"); return 3; }

    printf("AES-128 ECB test passed\n");
    return 0;
}
