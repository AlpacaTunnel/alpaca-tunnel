#ifndef AES_H_
#define AES_H_

#define AES_TEXT_LEN (4*4)
typedef unsigned char byte;

//key_len must be 128, 192 or 256 bits
int encrypt(byte cipher_text[AES_TEXT_LEN], const byte plain_text[AES_TEXT_LEN], const byte *cipher_key, int key_len);
int decrypt(byte plain_text[AES_TEXT_LEN], const byte cipher_text[AES_TEXT_LEN], const byte *cipher_key, int key_len);

#endif
