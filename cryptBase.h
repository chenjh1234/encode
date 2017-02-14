#ifndef CRYPTBASE_H
#define CRYPTBASE_H

#include <stdio.h>  
//#include <uuid.h>
#include <openssl/evp.h>  
//#include <crypto/evp/evp_locl.h>  
#include <openssl/rand.h>  
#include <openssl/rsa.h>  
#include <openssl/pem.h>  
#include <string.h>
#include <openssl/x509v3.h>  
#include <openssl/err.h>  
#include <iostream>

using namespace std;
   
#ifdef WIN32  
#else   // non-win32 system  
#define PUBLIC_KEY_FILE "mypub.key"  
#define PRIVATE_KEY_FILE "mypri.key"   
#endif  
// encrypt: 
#define MYPASSWD "123"
#define DATA_LEN 32
#define EVP_MAX_KEY_LENGHT 64
#define ENCRYPT_BLOCK 1000

// encode:
#define   ENCODE_BASE64 0
#define   ENCODE_HEX 1
// key encrypt:
#define BUFSIZE0  110 // ras input block:
#define BUFSIZE1 2048 // rsa len:
#define BUFSIZE  1024
#define RSA_KEY_LENGTH 1024  
static const char rnd_seed[] = "string to make the random number generator initialized";  


class cryptBase
{
public:
    cryptBase();
    ~cryptBase();

// asymmetry encrypt:  
    // all things is binary not string;
    //pub --->pri
    int lenOfEncryptP(int len);
    int lenOfDecryptP(int len);
    int encryptPub(char *pubKeyFile, char *inBuf, int inLen, char *outBuf);
    int decryptPri(char *priKeyFile, char *inBuf, int inLen, char *outBuf);
    // pri--->pub
    int encryptPri(char *priKeyFile, char *inBuf, int inLen, char *outBuf);
    int decryptPub(char *pubKeyFile, char *inBuf, int inLen, char *outBuf);

    int encryptPubChar(char *pubKeyChar, char *inBuf, int inLen, char *outBuf);
    int decryptPubChar(char *pubKeyChar, char *inBuf, int inLen, char *outBuf);
//sign, verify:
    // pri---->pub
    // binary:
    /// length of sign output
    int lenOfSign(int len){return lenOfEncryptP(len);};
    int sign(char* keyFile,char* plainText, char* cipherText)  ;//cipherText is a binary, not a string, len = 128 ,if plainText <101;
    bool verifySign(char* pubFile, char* cipherText,  int cipherTextLen,char* plainText)  ;
    bool verifySignPubChar(char* pubChar, char* cipherText,  int cipherTextLen,char* plainText)  ;

    // string;
    /// length of sign hex output
    int lenOfSignHex(int len){return 2*lenOfSign(len);};
    int  signHex(char* keyFile,char* plainText, char* cipherText) ;//cipherText is a string of  len = 256 if plainText <101;
    bool verifyHex(char* pubFile, char* cipherText, char* plainText) ;
    bool verifyHexPubChar(char* pubChar, char* cipherText, char* plainText) ;
// symmetry encrypt:
    int encrypt(char *inBuf, int inLen, char *outBuf); 
    int decrypt(char *inBuf, int inLen, char *outBuf); 
                                                                   //
    int encrypt(char *inBuf, int inLen, char *outBuf,char *passwd);// passwd is a string;
    int decrypt(char *inBuf, int inLen, char *outBuf,char *passwd);// passwd is a string;

    int cipher(char *inBuf, int inLen, char *outBuf,char *passwd,int mode);//mode 1:encrypt,0:decrypt,used by up two
    int encrypt1(char *inBuf, int inLen, char *outBuf,char *passwd); // limited length;

// keyfile:
    int rsaCreateKeyFiles(const char * prikey, const char *pubKey);
    int rsaCreateKeyFiles();

//encode:
    // encodeBase64:
    int encodeBase64(const char * input, int length,char *bufOut);// with newline;
    int decodeBase64(char * input, char *bufOut);
    // original: 
    char * encodeBase64(const char * input, int length, bool with_new_line = true)  ;//it will create mem space ,dont forget free it after used.
    char * decodeBase64(char * input, int length, bool with_new_line = true) ;// limited string,retrun len is better for binary;
    /// no newline: EVP function
    int  base64Encode(const char *encoded, int encodedLength, char *decoded) ;       
    int  base64Decode(const char *encoded, int encodedLength, char *decoded) ;  
    // encodeHex:
    /// for pure binary,can process any thing
    int encodeHex(const char *buf, int len,  char * str);
    int  decodeHex( char *hexbuf, char *retBuf);//not yet
    // string limited,
    string  hex2Bin(string _in) ; 
    string  bin2Hex(string _in) ;
// digest:
    int  digest(const char *orig, int lenOrig, char *out);
//uuid:
    string uuid();// get from cmd = genuuid in linux;
    string uuid1();// start frome the same,
    int uuid1(char *buf);


/// old version:
    int encryptPubkey(char * pubKeyFile,char *inBuf,int lenIn,char *outBuf) ;
    int decryptPrikey(char * priKeyFile,char *inBuf,int inLen,char *outBuf) ;
// called by interface:
    int encryptPubkey(RSA *key, char *inBuf, int inLen, char *outBuf );
    int decryptPrikey(RSA *key, char *inBuf, int inLen, char *outBuf );
/// encrypt:  mode 0:public,1:private
    int encryptPkey(int mode ,RSA *key, char *inBuf,int inlen,char *outBuf);
/// decrypt: mode 0:rivate,1:public
    int decryptPkey(int mode ,RSA *key, char *inBuf,int inlen,char *outBuf);

//a keys:

    int prikeySavetoFile(RSA *rsa, const char *filename);
    int pubkeySavetoFile(RSA *rsa, const char *filename);
    RSA* pubkeyGetfromFile(RSA *rsa, const char *filename);
    RSA* prikeyGetfromFile(RSA *rsa, const char *filename);

    RSA *getRsaPubFromFile(char *pubKeyFile);
    RSA *getRsaPriFromFile(char *priKeyFile);
    RSA *getRsaPubFromChar(char *pubKeyChar);
    const EVP_CIPHER *evp_cipher; 

#if 0  //evp:
    int createKeyFiles(const char *pub_keyfile, const char *pri_keyfile, const unsigned char *passwd, int passwd_len); 
    EVP_PKEY* openPublicKey(const char *keyfile);
    EVP_PKEY* openPrivateKey(const char *keyfile, const unsigned char *passwd);
    //pub encrypt:
    int rsaKeyEncrypt(EVP_PKEY *key, const unsigned char *orig_data, size_t orig_data_len,unsigned char *enc_data, size_t &enc_data_len) ;
    int rsaKeyDecrypt(EVP_PKEY *key, const unsigned char *enc_data, size_t enc_data_len,   unsigned char *orig_data, size_t &orig_data_len) ;
#endif

};


#endif

