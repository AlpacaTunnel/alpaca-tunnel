#include <stdlib.h>
#include <string.h>

#include "aes.h"

static void SetNbNkNr(int key_len, int *Nb, int *Nk, int *Nr);
static void KeyExpansion(const byte *cipher_key, int Nk, int Nr, byte w[4][60]);
static void AddRoundKey(int round, byte State[4][4], byte w[4][60]);
static void MixColumns(byte State[4][4]);
static void InvMixColumns(byte State[4][4]);
static void ShiftRows(byte State[4][4]);
static void InvShiftRows(byte State[4][4]);
static void SubBytes(byte State[4][4]);
static void InvSubBytes(byte State[4][4]);
static byte* SubWord(byte* word);
static byte* RotWord(byte* word);
static byte gfmultby01(byte b);
static byte gfmultby02(byte b);
static byte gfmultby03(byte b);
static byte gfmultby09(byte b);
static byte gfmultby0b(byte b);
static byte gfmultby0d(byte b);
static byte gfmultby0e(byte b);

static const byte Sbox[16][16]=
{
    // populate the Sbox matrix
    /*      0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/ {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    /*1*/ {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    /*2*/ {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    /*3*/ {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    /*4*/ {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    /*5*/ {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    /*6*/ {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    /*7*/ {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    /*8*/ {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    /*9*/ {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    /*a*/ {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    /*b*/ {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    /*c*/ {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    /*d*/ {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    /*e*/ {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    /*f*/ {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

static const byte InvSbox[16][16]=
{
    // populate the InvSbox matrix
    /*      0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/ {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    /*1*/ {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    /*2*/ {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    /*3*/ {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    /*4*/ {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    /*5*/ {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    /*6*/ {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    /*7*/ {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    /*8*/ {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    /*9*/ {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    /*a*/ {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    /*b*/ {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    /*c*/ {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    /*d*/ {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    /*e*/ {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    /*f*/ {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};

static const byte Rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void SetNbNkNr(int key_len, int *Nb, int *Nk, int *Nr)
{
    *Nb=4;
    if(key_len==128)
    {
        *Nk=4;    //4*4字节，128位密钥，10轮加密
        *Nr=10;
    }
    else if(key_len==192)
    {
        *Nk=6;    //6*4字节，192位密钥，12轮加密
        *Nr=12;
    }
    else    //default 256
    {
        *Nk=8;    //8*4字节，256位密钥，14轮加密
        *Nr=14;
    }
}

void KeyExpansion(const byte *cipher_key, int Nk, int Nr, byte w[4][60])
{
    //把cipher_key的所有字符复制到w中
    int row, i;
    for(i=0;i<4;i++)
        for(row=0;row<Nk;row++)
            w[i][row] = cipher_key[Nk*i+row];
    byte temp[4];
    for(row=Nk;row<4*(Nr+1);row++)
    {
        for(i=0;i<4;i++)
            temp[i]=w[i][row-1];    //当前列的前一列  

        if(row%Nk==0)        //逢nk时，对当前列的前一列作特殊处理
        {
            RotWord(temp);    //先移位，再代换，最后和轮常量异或
            SubWord(temp);
            temp[0] = temp[0] ^ Rcon[row/Nk-1];   
        }
        else if ( (Nk > 6) && (row % Nk == 4) )    //256位密钥，额外扩展
            SubWord(temp);

        for(i=0;i<4;i++)
            w[i][row] = w[i][row-Nk] ^ temp[i];
    }
}

byte *RotWord(byte* word)
{
    byte temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
    return word;
}

byte *SubWord(byte* word)
{
    int j;
    for(j=0;j<4;j++)
        word[j] = Sbox[word[j] >> 4][word[j] & 0x0f]; 
    return word;
}

void AddRoundKey(int round, byte State[4][4], byte w[4][60])
{
    int i,j;  //i行 j列
    for(j=0;j<4;j++)
        for(i=0;i<4;i++)
            State[i][j] ^= w[i][round*4+j];  
}

void SubBytes(byte State[4][4])
{
    int i,j;
    for(j=0;j<4;j++)
        for(i=0;i<4;i++)
            State[i][j] = Sbox[State[i][j]>>4][State[i][j]&0x0f];
}

void InvSubBytes(byte State[4][4])
{
    int i,j;
    for(j=0;j<4;j++)
        for(i=0;i<4;i++)
            State[i][j] = InvSbox[State[i][j]>>4][State[i][j]&0x0f];
}

void ShiftRows(byte State[4][4])
{
    byte temp, tmp2, j;

    //第1行左移1位
    temp = State[1][0];
    for(j=0;j<3;j++)
        State[1][j] = State[1][j+1];
    State[1][3] = temp;

    //第2行左移2位
    temp = State[2][0];
    tmp2 = State[2][1];
    State[2][0] = State[2][2];
    State[2][1] = State[2][3];
    State[2][2] = temp;
    State[2][3] = tmp2;

    //第3行左移3位
    temp = State[3][3];
    for(j=3;j>0;j--)
        State[3][j] = State[3][j-1];
    State[3][0] = temp;
}

void InvShiftRows(byte State[4][4])
{
    byte temp, tmp2, j;

    //第3行右移3位
    temp = State[3][0];
    for(j=0;j<3;j++)
        State[3][j] = State[3][j+1];
    State[3][3] = temp;

    //第2行右移2位
    temp = State[2][0];
    tmp2 = State[2][1];
    State[2][0] = State[2][2];
    State[2][1] = State[2][3];
    State[2][2] = temp;
    State[2][3] = tmp2;

    //第1行右移1位
    temp = State[1][3];
    for(j=3;j>0;j--)
        State[1][j] = State[1][j-1];
    State[1][0] = temp;
}

void MixColumns(byte State[4][4])        
{
    byte temp[4*4];    
    int j;                      //2 3 1 1  列混淆矩阵
    memcpy(temp, State, 16);    //1 2 3 1
                                //1 1 2 3 
    for(j=0;j<4;j++)            //3 1 1 2
    {                           
        State[0][j] = gfmultby02(temp[0+j]) ^ gfmultby03(temp[4*1+j]) ^
            gfmultby01(temp[4*2+j]) ^ gfmultby01(temp[4*3+j]);
        State[1][j] = gfmultby01(temp[0+j]) ^ gfmultby02(temp[4*1+j]) ^
            gfmultby03(temp[4*2+j]) ^ gfmultby01(temp[4*3+j]);
        State[2][j] = gfmultby01(temp[0+j]) ^ gfmultby01(temp[4*1+j]) ^
            gfmultby02(temp[4*2+j]) ^ gfmultby03(temp[4*3+j]);
        State[3][j] = gfmultby03(temp[0+j]) ^ gfmultby01(temp[4*1+j]) ^
            gfmultby01(temp[4*2+j]) ^ gfmultby02(temp[4*3+j]);
    }
}

void InvMixColumns(byte State[4][4])
{
    byte temp[4*4];              
    int j;                       //0e 0b 0d 09   逆变换矩阵
    memcpy(temp, State, 16);     //09 0e 0b 0d
                                 //0d 09 0e 0b                     
    for (j = 0; j < 4; j++)      //0b 0d 09 0e
    {
        State[0][j] = gfmultby0e(temp[j]) ^ gfmultby0b(temp[4+j]) ^
            gfmultby0d(temp[4*2+j]) ^ gfmultby09(temp[4*3+j]);
        State[1][j] = gfmultby09(temp[j]) ^ gfmultby0e(temp[4+j]) ^
            gfmultby0b(temp[4*2+j]) ^ gfmultby0d(temp[4*3+j]);
        State[2][j] = gfmultby0d(temp[j]) ^ gfmultby09(temp[4+j]) ^
            gfmultby0e(temp[4*2+j]) ^ gfmultby0b(temp[4*3+j]);
        State[3][j] = gfmultby0b(temp[j]) ^ gfmultby0d(temp[4+j]) ^
            gfmultby09(temp[4*2+j]) ^ gfmultby0e(temp[4*3+j]);
    }
}

byte gfmultby01(byte b)
{
    return b;
}

byte gfmultby02(byte b)
{
    if(b < 0x80)
        return b << 1;
    else
        return (b << 1) ^ (0x1b);
}

byte gfmultby03(byte b)
{
    return  gfmultby02(b) ^ b;
}

byte gfmultby09(byte b)
{
    return gfmultby02(gfmultby02(gfmultby02(b))) ^ b;
}

byte gfmultby0b(byte b)
{
    return gfmultby02(gfmultby02(gfmultby02(b))) ^ gfmultby02(b) ^ b;
}

byte gfmultby0d(byte b)
{
    return gfmultby02(gfmultby02(gfmultby02(b))) ^
        gfmultby02(gfmultby02(b)) ^ (b);
}

byte gfmultby0e(byte b)
{
    return gfmultby02(gfmultby02(gfmultby02(b))) ^
        gfmultby02(gfmultby02(b)) ^gfmultby02(b);
}

int encrypt(byte cipher_text[AES_TEXT_LEN], const byte plain_text[AES_TEXT_LEN], const byte *cipher_key, int key_len)
{
    int Nb;    // block size in 32-bit words.  Always 4 for AES.  (128 bits).
    int Nk;    // key size in 32-bit words.  4, 6, 8.  (128, 192, 256 bits).
    int Nr;    // number of rounds. 10, 12, 14.
    byte State[4][4];
    byte w[4][60]; 

    SetNbNkNr(key_len, &Nb, &Nk, &Nr);        //设置密钥块数，轮数 
    KeyExpansion(cipher_key, Nk, Nr, w);    //密钥扩展，必须提前做的初始化

    memcpy(State, plain_text, AES_TEXT_LEN);
    AddRoundKey(0, State, w);            //轮密钥加

    int round;
    for (round = 1; round <= (Nr - 1); round++)    // main round loop
    {
        SubBytes(State);        //字节代换
        ShiftRows(State);        //行移位
        MixColumns(State);        //列混淆
        AddRoundKey(round, State, w);    //轮密钥加
    }

    SubBytes(State);            //字节代换
    ShiftRows(State);            //行移位
    AddRoundKey(Nr, State, w);        //轮密钥加

    // cipher_text = state
    memcpy(cipher_text, State, AES_TEXT_LEN);
    return 0;
}

int decrypt(byte plain_text[AES_TEXT_LEN], const byte cipher_text[AES_TEXT_LEN], const byte *cipher_key, int key_len)
{
    int Nb;    // block size in 32-bit words.  Always 4 for AES.  (128 bits).
    int Nk;    // key size in 32-bit words.  4, 6, 8.  (128, 192, 256 bits).
    int Nr;    // number of rounds. 10, 12, 14.
    byte State[4][4];
    byte w[4][60]; 

    SetNbNkNr(key_len, &Nb, &Nk, &Nr);        //设置密钥块数，轮数 
    KeyExpansion(cipher_key, Nk, Nr, w);    //密钥扩展，必须提前做的初始化

    memcpy(State, cipher_text, AES_TEXT_LEN);
    AddRoundKey(Nr, State, w);

    int round;
    for (round = Nr-1; round >= 1; round--)  // main round loop
    {
        InvShiftRows(State);
        InvSubBytes(State);
        AddRoundKey(round, State, w);
        InvMixColumns(State);
    }

    InvShiftRows(State);
    InvSubBytes(State);
    AddRoundKey(0, State, w);

    // cipher_text = state
    memcpy(plain_text, State, AES_TEXT_LEN);
    return 0;
}

