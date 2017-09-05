#include "LEncrypt.h"
#include "mypubkey1.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "testG.h"
 

void mytest(string mytest)
{
   initUnit(mytest);
   int i;
   i = 10;
   REM("i == 10,remark of the test:"); //option
   //cout << "line = " << __LINE__<<__FUNCTION__ << endl;
   EQ(i, 10);
   NEQ(i, 11);
   endUnit();
}
int createPubH()
{
   BIO     *b = NULL;
   BIO     *bb = NULL;
   int     len = 0, outlen = 0,len1;
   char    *out = NULL;
   char *p;
 
   b = BIO_new_file(PUBLIC_KEY_FILE, "r");
   bb = BIO_new_file("mypubkey1.h", "w");
   len = BIO_pending(b);
   
 //  printf("bio key file len = %s,%d\n", CMD_PUBKEYFILE,  len);


   len = 20000;
   out = (char *)OPENSSL_malloc(len);
   len = 1;
   printf("      unsigned char pubKey[] = ");
   len1 = BIO_printf(bb, "      unsigned char pubKey1[] = ");
   p = out;
   while (len > 0)
   {
  
      len = BIO_read(b, out + outlen, 1);
      if (out[outlen] == '\n') 
      { 
          printf("\\\n"); // end of the line;
          len1 = BIO_printf(bb,"\\\n");

          out[outlen] = 0;
          printf("      \"%s\\n\" ",p); 
          len1 = BIO_printf(bb, "      \"%s\\n\" ",p);
          p = out+outlen+1;      
      }
      outlen += len; 
   }
   printf(";\n"); // end of the all line;
   len1 = BIO_printf(bb, ";\n");

   BIO_free(b);
   BIO_free(bb);
    printf("bio file out = %s,%d\n", out, outlen);
   free(out);
   return 0;
}

void testBase64(string mytest)
{
    initUnit(mytest);

    string str;
    LEncrypt cr;
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
    EQ(len,(int)strlen(test));
    str = "hello,decodeBase64" + STR(len) + "=!" + org+"!";
    PR(str);   

    endUnit();
}
void testHex(string mytest)
{
    initUnit(mytest);

    string str,str1;
    LEncrypt cr;
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
    LEncrypt cr;
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
    LEncrypt cr;
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
    LEncrypt cr;
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
    LEncrypt cr;
    char ch1[] = "1234567";
    char *buf,*buf1,*ch;
    int len,leno;
    buf = new char[1000];
    buf1 = new char[1000];
    ch = ch1;
    len = cr.encryptPubkey((char *)PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);

    leno = cr.decryptPrikey((char *)PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
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
    len = cr.encryptPubkey((char *)PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    GT(len,0);
  
    str = "1234567890*15,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    str="lenooo = " + STR(len);
    PR(str);
  //  GT(len,0);
      //printf("buf,buf1 = %x,%x\n",buf,buf1);
 
    leno = cr.decryptPrikey((char *)PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
 
    str = " decryptPri:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));
//-------------------------------------------
    PR("=====encryptPub======decryptPrikey==============================================");
    ch = ch1;
    //len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf,leno) ;
    REM(" encode the some input , when 2nd time   the result is not the same, decode is OK")
    len = cr.encryptPub((char *)PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    str = "1234567,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);

    leno = cr.decryptPrikey((char *)PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
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
    len = cr.encryptPub((char *)PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    str = "1234567,encryptPUB:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);

    leno = cr.decryptPri((char *)PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPri:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));

        ch = ch1;
    //len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf,leno) ;
     
    len = cr.encryptPubChar((char *)pubKey1,(char *)ch,strlen(ch),buf) ;
    str = "1234567,encryptPubChar:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);

    leno = cr.decryptPri((char *)PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPri:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));

    
//-------------------------------------------
    PR("=======encryptPri==decryptPub,decryptPubChar================================================");
    ch = ch1;
    //len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf,leno) ;
    //REM(" encode the some input , when 2nd time   the result is not the same, decode is OK")
    len = cr.encryptPri((char *)PRIVATE_KEY_FILE,(char *)ch,strlen(ch),buf) ;
    str = "1234567,encryptPri:" + STR(len) + "=!" + cr.bin2Hex(buf)+"!";
    PR(str);
    GT(len,0);
 
    leno = cr.decryptPub((char *)PUBLIC_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPUB:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));

     leno = cr.decryptPubChar((char *)pubKey1,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "1234567,decryptPUBChar:" + STR(leno) + "=!" + buf1+"!";
    PR(str);
    GT(leno,0);
    EQ(string(ch),string(buf1));
 
    PR("=======encryptPub==decryptPri================================================");
    char ch315[316];
    int i;
    for (i = 0; i <315 ;i++)
    {
        ch315[i] = '1';
    }
    ch315[315] = 0;
    ch = ch315; 
    int lenin;
    lenin = 315;
    //len = cr.encryptPubkey(PUBLIC_KEY_FILE,(char *)ch,strlen(ch),buf,leno) ;
   
    str =  "lenin = " + STR(lenin)  ;
    PR(str);
    len = cr.encryptPub((char *)PUBLIC_KEY_FILE,(char *)ch,lenin,buf) ;
    str =  "len = " + STR(len)  ;
    PR(str);

    REM(" encode the in = 315  ");
    GT(len,0);

    leno = cr.decryptPri((char *)PRIVATE_KEY_FILE,(char *)buf,len,buf1) ;
   // len = cr.encryptPubkey("../pubout.key",(char *)ch,strlen(ch),buf,leno) ;
 
    str = "leno = " +  STR(leno)   ;
    PR(str);
    EQ(leno,lenin);
    EQ(string(ch),string(buf1));
    buf1[315] = 0;
    EQ(string(ch),string(buf1));

    delete []buf;
    delete []buf1;

    cout << "fun = " << __FUNCTION__ <<endl;
U_END
//void test_sign()
//{
U_START(sign)
    string str;
    LEncrypt cr;
    char ch1[] = "1234567";
    char *buf,*buf1,*ch;
    int len;
    buf = new char[1000];
    buf1 = new char[1000];
    ch = ch1;
    len = cr.sign((char *)PRIVATE_KEY_FILE,(char *)ch,buf) ;
  
    str = "1234567,sign:" + STR(len) + "=!" + buf+"!";
    PR(str);
    GT(len,0);
    bool b;
    b = cr.verifySign((char *)PUBLIC_KEY_FILE,(char *)buf,len,ch) ;
    str = "1234567,verify:" + STR(len) ;
    PR(str);
    EQ(b,true);

    PR("signHex,verifyHex============================================");
    len = cr.signHex((char *)PRIVATE_KEY_FILE,(char *)ch,buf) ;
   
    str = "1234567,signHex:" + STR(len) + "=!" + buf+"!";    
    PR(str);
    
    GT(len,0);
    b = cr.verifyHex((char *)PUBLIC_KEY_FILE,(char *)buf,ch) ;
    str = "1234567,verifyHex:" + STR(len) ;
    PR(str);
    EQ(b,true);

    PR("signHex,verifyHex============================================");
    len = cr.signHex((char *)PRIVATE_KEY_FILE,(char *)ch,buf) ;
   
    str = "1234567,signHex:" + STR(len) + "=!" + buf+"!";    
    PR(str);
    
    GT(len,0);
    b = cr.verifyHexPubChar((char *)pubKey1,(char *)buf,ch) ;
    str = "1234567,verifyHex:" + STR(len) ;
    PR(str);
    EQ(b,true);
U_END
U_START(pwCrypt)
    string str;
    LEncrypt cr;
    char ch1[] = "1234567";
    char ch2[] = "12345678901234567890123456789012345678901234567890";
    char pw[]="123";
    char *buf,*buf1,*buf2,*ch;
    int len;
    buf = new char[1000];
    buf1 = new char[1000];
    buf2 = new char[1000];
     PR("Encrypt1===Decrypt ====1234567==================");
    ch = ch1;
    len = cr.encrypt((char *)ch,strlen(ch),buf,pw) ;
    cr.encodeHex(buf,len,buf1);
    str = "1234567,PWencrypy:" + STR(len) + "=!" + buf1+"!";
    PR(str);
    GT(len,0);

    len = cr.decrypt((char *)buf,len,buf1,pw) ;
    //cr.encodeHex(buf1,len,buf);
  
    str = "1234567,PWdecrypy:" + STR(len) + "=!" + buf1+"!";
    PR(str);
    GT(len,0);
    EQ(string(ch),string(buf1));
     PR("Encrypt1=======1234567==================");
   
    len = cr.encrypt1((char *)ch,strlen(ch),buf,pw) ;
    cr.encodeHex(buf,len,buf1);
  
    str = "1234567,PWencrypy1:" + STR(len) + "=!" + buf1+"!";
    PR(str);
    GT(len,0);
     PR("Encrypt=====50=====Decrypt=========================");
    ch = ch2;
    len = cr.encrypt((char *)ch,strlen(ch),buf,pw) ;
     cr.encodeHex(buf,len,buf1);
      
    str = "1234567890(50),PWencrypy:" + STR(len) + "=!" + buf1+"!";
    PR(str);
    GT(len,0);

        len = cr.decrypt((char *)buf,len,buf1,pw) ;
    //cr.encodeHex(buf1,len,buf);
  
    str = "1234567890(50),PWdecrypy:" + STR(len) + "=!" + buf1+"!";
    PR(str);
    GT(len,0);
    EQ(string(ch),string(buf1));

    str = cr.getMac();
    PR(str);
    REM("str = cr.getMac()")
    GT(str.length(),0);

  
U_END
U_START(myuuid)
    string str;
    char buf[34];
    int len;
    LEncrypt cr;
    len  = cr.uuid1(buf);
    str = "uuid1 = :" + STR(len) + "=!" + buf+"!";
    PR(str);
    GT(len,0);

    len  = cr.uuid1(buf);
    str = "uuid1 = :" + STR(len) + "=!" + buf+"!";
    PR(str);
    GT(len,0);

    len  = cr.uuid1(buf);
    str = "uuid1 = :" + STR(len) + "=!" + buf+"!";
    PR(str);
    GT(len,0);

    str = cr.uuid1();
    str = "uuid1() = :" + STR((int)str.length()) + "=!" + str +"!";
    PR(str);
    GT(len,0);

    str = cr.uuid();
    str = "uuid1() = :" + STR((int)str.length()) + "=!" + str +"!";
    PR(str);
    GT(len,0);
U_END
U_START(cmd)
    string str,cmd;
    char buf[34];
    int len;
    LEncrypt cr;
    cmd = "pwd";
    str  = cr.cmd(cmd);
    str = str + "," + STR((int)str.length());
    PR(str);
    GT(str.length(),0);

    cmd = "ls -ltr /";
    str  = cr.cmd(cmd);
    //str = str + "," + STR((int)str.length());
    //PR(str);
    GT(str.length(),0);
U_END
U_START(encodePass)
    string inp,hex,ret;
    char passwd[]="12345";
    int len;
    LEncrypt cr;

    inp  = "1234567890";
    hex = cr.encodePassHex(inp,passwd);
    GT(hex.length(),0);
    qDebug() << "inLen = 10 ,encodeLen = " << hex.length() << hex.c_str();

    ret= cr.decodePassHex(hex,passwd);
    GT(ret.length(),0);
    EQ(ret,inp);

    inp  = "12345678905125123452362362362356236265463434634634634634634634634666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666634";
    hex = cr.encodePassHex(inp,passwd);
    GT(hex.length(),0);
    qDebug() << "inLen = 10 ,encodeLen = " << hex.length()  <<  hex.c_str();

    ret= cr.decodePassHex(hex,passwd);
    GT(ret.length(),0);
    EQ(ret,inp);
U_END

#ifndef TEST_UNIT
M_START
#else
void testCrypt()
{
#endif
 
#if 1
    
   mytest("MYTEST");
   testHex("testHex");
   testBase64("testBase64");
   testDigest("testDigest");
   //testCreateKeyFiles("CreateKeyFiles");   
   createPubH();
   U_TEST(myuuid);
   U_TEST(sign)
   U_TEST(pwCrypt)
   U_TEST(encrypt)
   U_TEST(cmd)
   U_TEST(encodePass)
   
#endif 
//U_TEST(sign)
  
#ifndef TEST_UNIT
M_END
#else
}
#endif
     
 
