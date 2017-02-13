#include "cryptBase.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "testG.h"
#if 0
char * Base64Encode(const char * input, int length, bool with_new_line = true)  
{  
    BIO * bmem = NULL;  
    BIO * b64 = NULL;  
    BUF_MEM * bptr = NULL;  
  
    b64 = BIO_new(BIO_f_base64());  
    if(!with_new_line) {  
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
    }  
    bmem = BIO_new(BIO_s_mem());  
    b64 = BIO_push(b64, bmem);  
    BIO_write(b64, input, length);  
    BIO_flush(b64);  
    BIO_get_mem_ptr(b64, &bptr);  
  
    char * buff = (char *)malloc(bptr->length + 1);  
    memcpy(buff, bptr->data, bptr->length);  
    buff[bptr->length] = 0;  
  
    BIO_free_all(b64);  
  
    return buff;  
}  
  
char * Base64Decode(char * input, int length, bool with_new_line = true)  
{  
    BIO * b64 = NULL;  
    BIO * bmem = NULL;  
    char * buffer = (char *)malloc(length);  
    memset(buffer, 0, length);  
  
    b64 = BIO_new(BIO_f_base64());  
    if(!with_new_line) {  
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
    }  
    bmem = BIO_new_mem_buf(input, length);  
    bmem = BIO_push(b64, bmem);  
    BIO_read(bmem, buffer, length);  
  
    BIO_free_all(bmem);  
  
    return buffer;  
}  

void tt()
{
    string enc_input = "1234567";
    char * enc_output = Base64Encode(enc_input.c_str(), enc_input.length());  
    cout << "Base64 Encoded:" << endl << "~" << enc_output << "~" << endl << endl;  
  
    string dec_input = enc_output;  
    char * dec_output = Base64Decode((char *)dec_input.c_str(), dec_input.length());  
    cout << "Base64 Decoded:" << endl << "~" << dec_output << "~" << endl << endl;  
}

# endif
void mytest(string mytest)
{
   initUnit(mytest);
   int i;
   i = 10;
   REM("i == 10,remark of the test:"); //option
   //cout << "line = " << __LINE__<<__FUNCTION__ << endl;
   EQ(i, 10);
   EQ(i, 11);
   endUnit();
}
 
void testBase64(string mytest)
{
    initUnit(mytest);

    string str;
    cryptBase cr;
    char ch[] = "1234567";
    char *buf,*buf1;
    int len;
    buf = NULL;
    buf1= NULL;
    buf = cr.encodeBase64((char *)ch,strlen(ch));
    len = strlen(buf);
    NEQ(buf,NULL);
    str = "1234567,encodeBase64:" + STR(len) + "=!" + buf+"!";
    PR(str);
 
    buf1 = cr.decodeBase64((char *)buf, strlen(buf) );
    len = strlen(buf1);

    NEQ(buf,NULL);
    str = " ,decodeBase64:" + STR(len) + "=!" + buf1+"!";
    PR(str);

    delete buf;
    delete buf1;
// base64Encode:
     
    char test[] = "hello";  
    char result[1000] = {0};  

    len = cr.base64Encode(test, strlen(test), result)  ;
    GT(len,0);
    str = "hello,base64Encode" + STR(len) + "=!" + result+"!";
    PR(str);  

    char org[1000] = {0};    
    len = cr.base64Decode(result, strlen(result), org);  
    GT(len,0);
    str = "base64Decode:" + STR(len) + "=!" + org+"!";
    PR(str);   
// base64encode new interface:

    len = cr.encodeBase64(test, strlen(test), result)  ;
    GT(len,0);
    str = "hello,encodeBase64" + STR(len) + "=!" + result+"!";
    PR(str);  
    
    len = cr.decodeBase64(result, org);  
    EQ(len,strlen(test));
    str = "hello,decodeBase64" + STR(len) + "=!" + org+"!";
    PR(str);   

    endUnit();
}
void testHex(string mytest)
{
    initUnit(mytest);

    string str,str1;
    cryptBase cr;
    char ch[] = "1234567";
    char *buf,*buf1;
    int len;
    buf = new char[100];
    buf1 = new char[101];
    len = cr.encodeHex((char *)ch,strlen(ch),buf);
    REM("1234567,encodeHex:"); //option
    str = "1234567,encodeHex:" + STR(len) + "=!" + buf+"!";
    PR(str);
    GT(len,0);
    len = cr.decodeHex((char *)buf,buf1);
    REM("1234567,decodeHex:"); 
    str = ch;
    str1 = buf1;
    PR(str);
    PR(str1);
    EQ(str,str1); 


    delete buf;
    delete buf1;
    //
    string sin = "1234567";
    string sout,sout1;
    sout = cr.bin2Hex(sin);
    str = "1234567,bin2Hex:" + STR((int)sout.length()) + "=!" + sout+"!";
    PR(str);
    sout1 = cr.hex2Bin(sout);
    str = "hex2Bin:" + STR((int)sout1.length()) + "=!" + sout1+"!";
    PR(str);
    EQ(sin,sout1);

    endUnit();
}
void testDigest(string mytest)
{
    initUnit(mytest);

    string str;
    cryptBase cr;
    char ch[] = "1234567";
    char *buf;
    int len;
    buf = new char[100];
    len = cr.digest((char *)ch,strlen(ch),buf);
    str = "1234567,digest + encodeHex:" + STR(len) + "=!" + buf+"!";
    PR(str);
    GT(len,0);
    endUnit();
}

void testCreateKeyFiles(string mytest)
{
    initUnit(mytest);

    string str;
    cryptBase cr;
    RSA *key;
    key = RSA_new();
    NEQ(key,NULL);
    int len;
    len = cr.rsaCreateKeyFiles();
    GT(len,0);
    key = cr.pubkeyGetfromFile(key,PUBLIC_KEY_FILE);
    NEQ(key,NULL);

    endUnit();
}

void tt1()
{
    cryptBase cr;
    char test[] = "hello";  
    char result[1000] = {0}; // ?????  
    cout << cr.base64Encode(test, strlen(test), result) << endl;  
    cout << result << endl;  
  
    char org[1000] = {0};    // ?????  
    cout << cr.base64Decode(result, strlen(result), org) << endl;  
    cout << org << endl;  
  
    return ;  
}
U_START(encrypt)
    string str;
    cryptBase cr;
    char ch1[] = "1234567";
    char *buf,*buf1,*ch;
    int len,leno;
    buf = new char[1000];
    buf1 = new char[1000];
    ch = ch1;
    len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);

    leno = cr.decryptPrikey(PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPri:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    // 15
    char ch2[] = "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890";
                #if 0
        
        "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890";
        #endif
    //printf("buf,buf1 = %x,%x\n",buf,buf1);
    ch = ch2;
    str="len in = " + STR((int)strlen(ch));
    PR(str);
    len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    GT(len,0);
  
    str = "1234567890*15,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    str="lenooo = " + STR(len);
    PR(str);
  //  GT(len,0);
      //printf("buf,buf1 = %x,%x\n",buf,buf1);
 
    leno = cr.decryptPrikey(PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
 
    str = " decryptPri:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));
//-------------------------------------------
    PR("=====encryptPub======decryptPrikey==============================================");
    ch = ch1;
    //len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf,leno) ;
    REM(" encode the some input , when 2nd time   the result is not the same, decode is OK")
    len = cr.encryptPub(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    str = "1234567,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);

    leno = cr.decryptPrikey(PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPri:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));
//-------------------------------------------
    PR("=======encryptPub==decryptPri================================================");
    ch = ch1;
    //len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf,leno) ;
    REM(" encode the some input , when 2nd time   the result is not the same, decode is OK")
    len = cr.encryptPub(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    str = "1234567,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);

    leno = cr.decryptPri(PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPri:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));
//-------------------------------------------
    PR("=======encryptPri==decryptPub================================================");
    ch = ch1;
    //len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf,leno) ;
    //REM(" encode the some input , when 2nd time   the result is not the same, decode is OK")
    len = cr.encryptPri(PRIVATE_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    str = "1234567,encryptPri:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);
 
    leno = cr.decryptPub(PUBLIC_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPUB:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));
  

    delete []buf;
    delete []buf1;
U_END

M_START
//int main222(){
 
#if 1
   //mytest("MYTEST");
   //testHex("testHex");
   testBase64("testBase64");
   //testDigest("testDigest");
   //testCreateKeyFiles("CreateKeyFiles");
#endif
   //U_TEST(encrypt)

M_END0
#if 0
M_START
   U_TEST(encrypt)
M_END0
#endif
