
#include "LEncrypt.h"

LEncrypt::LEncrypt()
{
   // evp_cipher = EVP_des_ede3_cbc();//3des算法cbc模式
   evp_cipher = EVP_aes_128_cbc();

}
LEncrypt::~LEncrypt()
{
    

}
/** 
 get a uuid string len = 36:  from uuidgen \n
  652a4ecf-3db8-4f4e-96fe-eb476e1d6212
 */
string  LEncrypt::uuid()
{
    char buf[40];
    char cmd[]="uuidgen";
    string str;
    int len;
    FILE * pf;
    str = "";
    pf = popen(cmd,"r");
    if (pf == NULL)
    {
        printf("no uuidgen command error !!!\n");
        return str;
    }
    if(fgets(buf,100,pf) == NULL)
    {
         printf("no uuidgen gets error !!!\n");
        return str;
    }
    buf[36] =0;
     str = buf; 
    pclose(pf);
    return str;
}
/**
 *  uuid  from rand , eachtime first call is the same;
 */
string  LEncrypt::uuid1()
{
    char buf[34];
    string str;
    int len;
    len = uuid1((char *)buf);
    if (len >0) str = buf;
    else str = "";
    return str;
}
/**
 *  uuid  from rand , eachtime first call is the same;
 */
int LEncrypt::uuid1( char *buf)
{
    const char *c = "89ab";
    char *p = buf;
    int n;
  
    for( n = 0; n < 16; ++n )
    {
        int b = rand()%255;
        //printf("%0X",b);
        switch( n )
        {
            case 6:
                sprintf(p,"4%x", b%15 );
                break;
            case 8:
                sprintf(p, "%c%x",c[rand()%strlen( c )], b%15 );
                break;
            default:
                sprintf( p, "%02x",b );
                break;
        }
  
        p += 2;
  
        switch( n )
        {
            case 3:
            case 5:
            case 7:
            case 9:
                *p++ = '-';
                break;
        }
    }//
  
    *p = 0;
    return strlen(buf);
}
/**
 *  getRsaPubFromChar(char *keyChar)
 * 
 * @return RSA* 
 */
RSA* LEncrypt::getRsaPubFromChar(char *keyChar)
{
   RSA *key;
   key = RSA_new();
   if (NULL == key)
   {
      perror("RSA_new()");
      return NULL;
   }
   BIO     *b = NULL;

   //b = BIO_new(BIO_s_mem());
   b = BIO_new_mem_buf((void *)keyChar, strlen((char *)keyChar));
   // printf(" bio new b = 0x%0X,%d\n",b,strlen((char *)pubKey));

   key = PEM_read_bio_RSA_PUBKEY(b, &key, NULL, NULL);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_Char  wrong");
      printf(" bio read error\n");
      return NULL;
   }
   BIO_free(b);
   return key;
}
/**
 * getRsaPriFromFile(char *priKeyFile)
 * 
 * @return RSA* 
 */
RSA* LEncrypt::getRsaPriFromFile(char *priKeyFile)
{
   RSA *key;
   key = RSA_new();
   if (NULL == key)
   {
      perror("RSA_new()");
      return NULL;
   }
   // read key:
   key = prikeyGetfromFile(key, priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_File() wrong");
      return NULL;
   }
   return key;
}
/**
 * getRsaPubFromFile(char *pubKeyFile)
 */
RSA* LEncrypt::getRsaPubFromFile(char *pubKeyFile)
{
   RSA *key;
   key = RSA_new();
   if (NULL == key)
   {
      perror("RSA_new()");
      return NULL;
   }
   // read key:
   key = pubkeyGetfromFile(key, pubKeyFile);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_File() wrong");
      return NULL;
   }
   return key;
}
/**
 * 
 * get length of output buf. for asymeetry  encrypt;
 * 
 */
int LEncrypt::lenOfEncryptP(int len)
{
   int n;
   n = len / BUFSIZE0;
   return BUFSIZE / 8 + n * BUFSIZE / 8;
}
/**
 * 
 * get maximum length of output buf. for asymeetry  decrypt;
 * 
 */
int LEncrypt::lenOfDecryptP(int len)
{
   int n;
   n = len / (BUFSIZE / 8);
   return BUFSIZE0 + n * BUFSIZE0;
}

/**
 * 
 *   asymmetry  encrypt use publick Key RSA *;
 * 
 */
int LEncrypt::encryptPubkey(RSA *key, char *inBuf, int inLen, char *outBuf)
{
   unsigned char buff[BUFSIZE0];
   unsigned char buff1[BUFSIZE1];
   int ret, len;
   memset(buff, 0, BUFSIZE0);
   memset(buff1, 0, BUFSIZE1); //2048

   if (NULL == key)
   {
      perror("Pubkey_  wrong");
      return 0;
   }
// encrypt loop:
   char *buf, *buf1;
   buf = inBuf;
   buf1 = outBuf;
   //cout << "en = " <<  buf + BUFSIZE0  - inBuf  << "," << inLen << endl;
   //while ((ret = fread(buf, sizeof(char), BUFSIZE0, fp)) == BUFSIZE0) //read string from file
   ret = 0;
   while (buf + BUFSIZE0  - inBuf < inLen) //read string from file
   {
      // printf("encode is in loop,ret = %d\n",ret);
      memcpy(buff, buf, BUFSIZE0);
      memset(buff1, 0, BUFSIZE1);

      ret = RSA_public_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
                               key, RSA_PKCS1_PADDING); //en-code
                                                        //cout << "ret ====" << ret << endl;
      if (ret < 0)
      {
         perror("error in enc");
         return 0;
      }
      else
      {
         // fwrite(buf1, sizeof(char), ret, fp0); //write string to file
         // memcpy(buf1,buff1,BUFSIZE1);
         memcpy(buf1, buff1, ret);
         buf = buf + BUFSIZE0;
         buf1 = buf1 + ret;
      }
   }
   //cout <<"11111\n";
   // end of loop"
   //printf("encode out loop,ret = %d\n",ret);
   ret = inLen - (buf - inBuf);
   // printf(" calculate ret = %d\n",ret);
   if (ret > 0)
   {
      memcpy(buff, buf, ret);
      memset(buff1, 0, BUFSIZE1);
      ret = RSA_public_encrypt(ret, (unsigned char *)buff, (unsigned char *)buff1,
                               key, RSA_PKCS1_PADDING); //en-code
                                                        //printf("encode,ret = %d\n", ret);
      if (ret < 0)
      {
         perror("error in enc 1 ");
         return 0;
      }
      memcpy(buf1, buff1, ret);
   }
   // fwrite(buf1, sizeof(char), ret, fp0); //write string to file
   //fclose(fp);
   // fclose(fp0);
   RSA_free(key); //relase
                  //printf("encode OK\n");
   len = buf1 - outBuf + ret;
   return len;
}
/**
 * 
 *   asymmetry  decrypt use private  Key RSA *;
 * 
 */
int LEncrypt::decryptPrikey(RSA *key, char *inBuf, int inLen, char *outBuf)
{

   unsigned char buff[BUFSIZE];
   unsigned char buff1[BUFSIZE1];
   int ret, rsa_len;

   char *buf, *buf1;
   buf = inBuf;
   buf1 = outBuf;
   //read prikey----------------------------------------------------
   //key = prikeyGetfromFile(key, priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_File() wrong");
      return 0;
   }

   rsa_len = RSA_size(key);
   //printf("rsa_len = %d\n", rsa_len);


   // while ((ret = fread(buf, sizeof(char), rsa_len, fp)) == rsa_len) //read string from file
   while (buf +  rsa_len <= inBuf + inLen) //read string from file
   {
      memset(buff, 0, BUFSIZE);
      memcpy(buff, buf, rsa_len);
      memset(buff1, 0, BUFSIZE1);

      ret = RSA_private_decrypt(rsa_len, (unsigned char *)buff, (unsigned char *)buff1,
                                key, RSA_PKCS1_PADDING); //de-code
      if (ret < 0)
      {
         perror("error in dec");
         return 0;
      }
      else
      {
         //fwrite(buf1, sizeof(char), ret, fp0); //write string to file
         buf = buf + rsa_len;
         if (ret > 0)
         {
            memcpy(buf1, buff1, ret);
            buf1 = buf1 + ret;
         }
      }
      //printf("decode is in loop,ret = %d\n", ret);
   }

   int len;
   len = buf1 - outBuf;
   // printf("len === %d",len);
   outBuf[len] = 0;

   RSA_free(key); //relase
                  //printf("decode OK\n");
   return len;
}
//-------------------------------------------------------------------------------------------
/**
 * 
 *   asymmetry  encrypt use RSA * mode :0:publicKey, 1:privateKey;
 * 
 */
int LEncrypt::encryptPkey(int mode, RSA *key, char *inBuf, int inLen, char *outBuf)
{
   unsigned char buff[BUFSIZE0];
   unsigned char buff1[BUFSIZE1];
   int ret, len;
   memset(buff, 0, BUFSIZE0);
   memset(buff1, 0, BUFSIZE1); //2048

   if (NULL == key)
   {
      perror("Pubkey_  wrong");
      return 0;
   }
// encrypt loop:
   char *buf, *buf1;
   buf = inBuf;
   buf1 = outBuf;
   //cout << "en = " <<  buf + BUFSIZE0  - inBuf  << "," << inLen << endl;
   //while ((ret = fread(buf, sizeof(char), BUFSIZE0, fp)) == BUFSIZE0) //read string from file
   ret = 0;
   while (buf + BUFSIZE0  - inBuf < inLen) //read string from file
   {
      // printf("encode is in loop,ret = %d\n",ret);
      memcpy(buff, buf, BUFSIZE0);
      memset(buff1, 0, BUFSIZE1);
      if (mode == 0)  ret = RSA_public_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
                                               key, RSA_PKCS1_PADDING); //en-code
      else ret = RSA_private_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
                                     key, RSA_PKCS1_PADDING); //en-code
                                                              //cout << "ret ====" << ret << endl;
      if (ret < 0)
      {
         perror("error in enc");
         return 0;
      }
      else
      {
         // fwrite(buf1, sizeof(char), ret, fp0); //write string to file
         // memcpy(buf1,buff1,BUFSIZE1);
         memcpy(buf1, buff1, ret);
         buf = buf + BUFSIZE0;
         buf1 = buf1 + ret;
      }
   }
   //cout <<"11111\n";
   // end of loop"
   //printf("encode out loop,ret = %d\n",ret);
   ret = inLen - (buf - inBuf);
   // printf(" calculate ret = %d\n",ret);
   if (ret > 0)
   {
      memcpy(buff, buf, ret);
      memset(buff1, 0, BUFSIZE1);
      // update 2017.2.23 BUFFSIZE0->ret
      if (mode == 0)  ret = RSA_public_encrypt(ret, (unsigned char *)buff, (unsigned char *)buff1,
                                               key, RSA_PKCS1_PADDING); //en-code
      else ret = RSA_private_encrypt(ret, (unsigned char *)buff, (unsigned char *)buff1,
                                     key, RSA_PKCS1_PADDING); //en-code
                                                              //printf("encode,ret = %d\n", ret);
      if (ret < 0)
      {
         perror("error in enc 1 ");
         return 0;
      }
      memcpy(buf1, buff1, ret);
   }
   // fwrite(buf1, sizeof(char), ret, fp0); //write string to file
   //fclose(fp);
   // fclose(fp0);
   RSA_free(key); //relase
                  //printf("encode OK\n");
   len = buf1 - outBuf + ret;
   return len;
}
/**
 * 
 *   asymmetry  decrypt use RSA * mode :0:privateKey;,
 *   1:publicKey
 * 
 */
int LEncrypt::decryptPkey(int mode, RSA *key, char *inBuf, int inLen, char *outBuf)
{

   unsigned char buff[BUFSIZE];
   unsigned char buff1[BUFSIZE1];
   int ret, rsa_len;

   char *buf, *buf1;
   buf = inBuf;
   buf1 = outBuf;
   //read prikey----------------------------------------------------
   //key = prikeyGetfromFile(key, priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_File() wrong");
      return 0;
   }
   //printf("2222222222222222222\n");

   rsa_len = RSA_size(key);// = 128
   //printf("rsa_len = %d,%d\n", rsa_len,inLen);
   // return 0;


   // while ((ret = fread(buf, sizeof(char), rsa_len, fp)) == rsa_len) //read string from file
   while (buf +  rsa_len <= inBuf + inLen) //read string from file
   {
      memcpy(buff, buf, rsa_len);
      memset(buff1, 0, BUFSIZE1);

      if (mode == 0)  ret = RSA_private_decrypt(rsa_len, (unsigned char *)buff, (unsigned char *)buff1,
                                                key, RSA_PKCS1_PADDING); //de-code
      else   ret = RSA_public_decrypt(rsa_len, (unsigned char *)buff, (unsigned char *)buff1,
                                      key, RSA_PKCS1_PADDING); //de-code
      if (ret < 0)
      {
         perror("error in dec");
         return 0;
      }
      else
      {
         //fwrite(buf1, sizeof(char), ret, fp0); //write string to file
         buf = buf + rsa_len;
         if (ret > 0)
         {
            memcpy(buf1, buff1, ret);
            buf1 = buf1 + ret;
         }
      }
    //  printf("decode is in loop,ret = %d\n", ret);
   }

   int len;
   len = buf1 - outBuf;
   //printf("len === %d",len);
   outBuf[len] = 0;

   RSA_free(key); //relase
                  //printf("decode OK\n");
   return len;
}
//----------------------------------------------------------------------------------
/**
 * 
 *   asymmetry  encrypt use public Char
 * 
 */
int LEncrypt::encryptPubChar(char *pubKeyChar, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   key = getRsaPubFromChar(pubKeyChar);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_Char wrong");
      return 0;
   }
   return encryptPubkey(key, inBuf, inLen, outBuf);
}
/**
 * 
 *   asymmetry  decrypt use  publicKey Char,
 *    
 * 
 */
int LEncrypt::decryptPubChar(char *pubKeyChar, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   key = getRsaPubFromChar(pubKeyChar);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_Char wrong");
      return 0;
   }
   return decryptPkey(1, key, inBuf, inLen, outBuf);
}

//----------encryptPub---------------------------

/**
 * 
 *   asymmetry  encrypt with  publicKey File,
 *    
 * 
 */
int LEncrypt::encryptPub(char *pubKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   key = getRsaPubFromFile(pubKeyFile);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_file wrong");
      return 0;
   }
   return encryptPkey(0, key, inBuf, inLen, outBuf);
}
string LEncrypt::encryptPubHex(char *pubKeyFile,char *inBuf)
{
  RSA *key;
   key = getRsaPubFromFile(pubKeyFile);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_file wrong");
      return 0;
   }
   string str;
   char *outBuf,*hexBuf;
   int lenin,lenout,ir,ir1;
   lenin= strlen(inBuf);
   lenout = lenOfEncryptP(lenin);
   outBuf = new char[lenout];
  //cout  << "lenout = " << lenin <<","<< lenout;
   ir = encryptPkey(0, key, inBuf,lenin, outBuf);
  // cout << "encryptPkey in,out  = " << lenin<<  "," << ir <<endl;
   if (ir  > lenout || ir<=0) 
   {
       delete []outBuf;
       return str;
   }
   hexBuf = new char[ir*2];
   
   ir1 = encodeHex(outBuf,ir,hexBuf); 
  // cout << "encodeHex in,out  = " << ir<<  "," << ir1 <<endl;
    //cout << "ir = " <<ir;
   str = hexBuf;
    //cout << "ir = " <<ir <<","<< str;
   delete []outBuf;
   delete []hexBuf;
   return str;

}
string LEncrypt::decryptPriHex(char *priKeyFile,char *inBuf)
{
   RSA *key;
   key = getRsaPriFromFile(priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_file wrong");
      return 0;
   }
   string str;
   char *outBuf,*retBuf;
   int lenin,lenout,ir,ir1;
   lenin= strlen(inBuf);
   str = "";

   lenout =  lenin/2;
   outBuf = new char[lenout];
   retBuf = new char[lenout];

   ir = decodeHex(inBuf,outBuf);
   if (ir <= 0) 
   {
       delete []outBuf;
       return str;
   }
    //cout << "decodeHex in,out  = " << strlen(inBuf) <<  "," << ir <<endl;

   ir1 = decryptPkey(0, key, outBuf, lenout, retBuf);
    //cout << "decryptPkey in,out  = " << ir <<  "," << ir1 <<endl;
   if (ir1 <=0) 
   {
       cout << "decrypt error in decryptHex\n";
       return str;
   }
   else
        str = retBuf;

   delete []outBuf;
   delete []retBuf;
   return str;
}
/**
 * 
 *   asymmetry  decrypt with  privateKey File,
 *    
 * 
 */
int LEncrypt::decryptPri(char *priKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   key = getRsaPriFromFile(priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_file wrong");
      return 0;
   }
   return decryptPkey(0, key, inBuf, inLen, outBuf);
}
//encryptPri:-----------------------------------------------
/**
 * 
 *   asymmetry  encrypt with  privateKey File,
 *    
 * 
 */
int LEncrypt::encryptPri(char *priKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   key = getRsaPriFromFile(priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_file wrong");
      return 0;
   }
   return encryptPkey(1, key, inBuf, inLen, outBuf);
}
//decryptPub:-----------------------------------------------
/**
 * 
 *   asymmetry decrypt with  publicKey File,
 *    
 * 
 */
int LEncrypt::decryptPub(char *pubKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   key = getRsaPubFromFile(pubKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_file wrong");
      return 0;
   }
   //printf("decrypt pub0000\n");
   return decryptPkey(1, key, inBuf, inLen, outBuf);
}
//==encryptPubkey===========================================================
/**
 *   asymmetry encrypt with  publicKey File,
 *    
 */
int LEncrypt::encryptPubkey(char *pubKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   unsigned char buff[BUFSIZE0];
   unsigned char buff1[BUFSIZE1];
   int ret, len;

   memset(buff, 0, BUFSIZE0);
   memset(buff1, 0, BUFSIZE1); //2048

   key = RSA_new();
   if (NULL == key)
   {
      perror("RSA_new()");
      return 0;
   }
   // read key:
   key = pubkeyGetfromFile(key, pubKeyFile);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_File() wrong");
      return 0;
   }
// encrypt loop:
   char *buf, *buf1;
   buf = inBuf;
   buf1 = outBuf;
   //cout << "en = " <<  buf + BUFSIZE0  - inBuf  << "," << inLen << endl;
   //while ((ret = fread(buf, sizeof(char), BUFSIZE0, fp)) == BUFSIZE0) //read string from file
   ret = 0;
   while (buf + BUFSIZE0  - inBuf < inLen) //read string from file
   {
      // printf("encode is in loop,ret = %d\n",ret);
      memcpy(buff, buf, BUFSIZE0);
      memset(buff1, 0, BUFSIZE1);

      ret = RSA_public_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
                               key, RSA_PKCS1_PADDING); //en-code
                                                        //cout << "ret ====" << ret << endl;
      if (ret < 0)
      {
         perror("error in enc");
         return 0;
      }
      else
      {
         // fwrite(buf1, sizeof(char), ret, fp0); //write string to file
         // memcpy(buf1,buff1,BUFSIZE1);
         memcpy(buf1, buff1, ret);
         buf = buf + BUFSIZE0;
         buf1 = buf1 + ret;
      }
   }
   //cout <<"11111\n";
   // end of loop"
   //printf("encode out loop,ret = %d\n",ret);
   ret = inLen - (buf - inBuf);
   // printf(" calculate ret = %d\n",ret);
   if (ret > 0)
   {
      memcpy(buff, buf, ret);
      memset(buff1, 0, BUFSIZE1);
      ret = RSA_public_encrypt(ret, (unsigned char *)buff, (unsigned char *)buff1,
                               key, RSA_PKCS1_PADDING); //en-code
                                                        //printf("encode,ret = %d\n", ret);
      if (ret < 0)
      {
         perror("error in enc 1 ");
         return 0;
      }
      memcpy(buf1, buff1, ret);
   }
   // fwrite(buf1, sizeof(char), ret, fp0); //write string to file
   //fclose(fp);
   // fclose(fp0);
   RSA_free(key); //relase
                  //printf("encode OK\n");
   len = buf1 - outBuf + ret;
   return len;
}

/**
 *   asymmetry decrypt with  privateKey File,
 *    
 */
int LEncrypt::decryptPrikey(char *priKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   unsigned char buff[BUFSIZE];
   unsigned char buff1[BUFSIZE1];
   int ret, rsa_len;

   char *buf, *buf1;
   buf = inBuf;
   buf1 = outBuf;

   key = RSA_new();
   if (NULL == key)
   {
      perror("RSA_new()");
      return 0;
   }
   //read prikey----------------------------------------------------
   key = prikeyGetfromFile(key, priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_File() wrong");
      return 0;
   }

   rsa_len = RSA_size(key);
   //printf("rsa_len = %d\n", rsa_len);


   // while ((ret = fread(buf, sizeof(char), rsa_len, fp)) == rsa_len) //read string from file
   while (buf +  rsa_len <= inBuf + inLen) //read string from file
   {


      memcpy(buff, buf, rsa_len);
      memset(buff1, 0, BUFSIZE1);

      ret = RSA_private_decrypt(rsa_len, (unsigned char *)buff, (unsigned char *)buff1,
                                key, RSA_PKCS1_PADDING); //de-code
      if (ret < 0)
      {
         perror("error in dec");
         return 0;
      }
      else
      {
         //fwrite(buf1, sizeof(char), ret, fp0); //write string to file
         buf = buf + rsa_len;
         if (ret > 0)
         {
            memcpy(buf1, buff1, ret);
            buf1 = buf1 + ret;
         }
      }
      //printf("decode is in loop,ret = %d\n", ret);
   }

   int len;
   len = buf1 - outBuf;
   // printf("len === %d",len);
   outBuf[len] = 0;

   RSA_free(key); //relase
                  //printf("decode OK\n");
   return len;
}

/**
 *   encode Base64  ,
 *    
 */
int  LEncrypt:: encodeBase64(const char *input, int length, char *bufOut)
{
   BIO *bmem = NULL;
   BIO *b64 = NULL;
   BUF_MEM *bptr = NULL;
   bool with_new_line = true;

   b64 = BIO_new(BIO_f_base64());
   if (!with_new_line)
   {
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   }
   bmem = BIO_new(BIO_s_mem());
   b64 = BIO_push(b64, bmem);
   BIO_write(b64, input, length);
   BIO_flush(b64);
   BIO_get_mem_ptr(b64, &bptr);

   char *buff = bufOut;
   memcpy(buff, bptr->data, bptr->length);
   buff[bptr->length] = 0;

   BIO_free_all(b64);
   return bptr->length;
}
/**
 *   decode Base64  ,
 *    
 */
int  LEncrypt:: decodeBase64(char *input,  char *bufOut)
{
   BIO *b64 = NULL;
   BIO *bmem = NULL;
   int len, leno;
   bool with_new_line = true;
   len = strlen(input);

   char *buffer = bufOut;
   memset(buffer, 0, len);

   b64 = BIO_new(BIO_f_base64());
   if (!with_new_line)
   {
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   }
   bmem = BIO_new_mem_buf(input, len);
   bmem = BIO_push(b64, bmem);
   leno = BIO_read(bmem, buffer, len);

   BIO_free_all(bmem);

   return leno;
}
// encode:=============================================================================
/* 
功能：对length长度的input指向的内存块进行BASE64编码 
入口： 
const void *input           指向内存块的指针 
int length                  内存块的有效长度 
返回： 
char *                      返回字符串指针，使用完毕后，必须用free函数释放。 
*/
/**
 *   encode Base64    
 *    
 */
char* LEncrypt:: encodeBase64(const char *input, int length, bool with_new_line)
{
   BIO *bmem = NULL;
   BIO *b64 = NULL;
   BUF_MEM *bptr = NULL;

   b64 = BIO_new(BIO_f_base64());
   if (!with_new_line)
   {
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   }
   bmem = BIO_new(BIO_s_mem());
   b64 = BIO_push(b64, bmem);
   BIO_write(b64, input, length);
   BIO_flush(b64);
   BIO_get_mem_ptr(b64, &bptr);

   char *buff = (char *)malloc(bptr->length + 1);
   memcpy(buff, bptr->data, bptr->length);
   buff[bptr->length] = 0;

   BIO_free_all(b64);

   return buff;
}
/**
 *   decode Base64  ,for string only cannot decode binary
 *    
 */
char* LEncrypt:: decodeBase64(char *input, int length, bool with_new_line)
{
   BIO *b64 = NULL;
   BIO *bmem = NULL;
   char *buffer = (char *)malloc(length);
   memset(buffer, 0, length);

   b64 = BIO_new(BIO_f_base64());
   if (!with_new_line)
   {
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   }
   bmem = BIO_new_mem_buf(input, length);
   bmem = BIO_push(b64, bmem);
   BIO_read(bmem, buffer, length);

   BIO_free_all(bmem);

   return buffer;
}
/**
 *   encode Base64  ,
 *    
 */
int  LEncrypt::base64Encode(const char *encoded, int encodedLength, char *decoded)
{
   return EVP_EncodeBlock((unsigned char *)decoded, (const unsigned char *)encoded, encodedLength);
}
/**
 *   decode Base64  ,
 *    
 */
// base解码
int  LEncrypt::base64Decode(const char *encoded, int encodedLength, char *decoded)
{
   return EVP_DecodeBlock((unsigned char *)decoded, (const unsigned char *)encoded, encodedLength);
}
/**
 *   decode hex  ,
 *    
 */
int  LEncrypt:: decodeHex(char *buf, char *retBuf)
{
   int len, leno;
   int i, j;
   char ch;
   unsigned char tmp;
   len = strlen(buf) / 2;
   //cout << " decode hex --len = " << len << "," << strlen(buf) << endl;

   for (i = 0; i < len; i++)
   {
      tmp = 0;
      for (j = 0; j < 2; j++)
      {
         ch = buf[2 * i + j];
         //cout << i << ","<<j <<"=" << ch;
         if (ch >= '0' && ch <= '9')
         {
            //printf("----%x,",tmp);
            tmp = (tmp << 4) + (ch - '0');
            //printf("%x----",tmp);
         }
         else if (ch >= 'a' && ch <= 'f')
         {
            tmp = (tmp << 4) + (ch - 'a' + 10);
         }
         else if (ch >= 'A' && ch <= 'F')
         {
            tmp = (tmp << 4) + (ch - 'A' + 10);
         }
         else
         {
            // cout << "\n ree i,j="<< i <<"," << j << "=" << ch<<endl;
            leno = 0;
            retBuf[0] = 0;
            return leno;
         }
      }
      retBuf[i] = tmp;
   }
   leno = len;
   retBuf[leno] = 0;
   // cout << "\n leno=" << leno << "==" << retBuf <<endl;
   return leno;
}
/**
 *   encode Hex  ,
 *    
 */
int LEncrypt::encodeHex(const char *buf, int len,  char *str)
{
   //const char *set = "0123456789abcdef";
   const char *set = "0123456789ABCDEF";
   // char str11[65];

   // static char str[65], *tmp; // for digest: len = 16 *2 =32;
   char *tmp;
   char *end;
   //if (len > 32) len = 32;

   end = (char *)buf + len;
   // tmp = &str[0];
   tmp = str;

   while (buf < end)
   {
      //printf("0==%d,%d ,",set[((*buf) >> 4)& 0xF],((*buf) >> 4)& 0xF);
      *tmp++ = set[((*buf) >> 4) & 0xF];
      //printf("1==%d,%d \n",set[(*buf) & 0xF],(*buf) & 0xF);
      *tmp++ = set[(*buf) & 0xF];
      buf++;
   }
   *tmp = 0;
   //printf(" encode hex,len  = %d,%d\n", len, tmp - str);
   return  2 * len;
}


/**
 *   encode hex  ,string only
 *    
 */
string  LEncrypt::bin2Hex(string _in)
{
   std::string result;
   const char hexdig[] = "0123456789ABCDEF";

   if (_in.empty())
   {
      return result;
   }
   result.clear();
   for (std::string::iterator i = _in.begin(); i != _in.end(); i++)
   {
      result.append(1, hexdig[(*i >> 4) & 0xf]);  //留下高四位
      result.append(1, hexdig[(*i & 0xf)]);  //留下低四位

   }
   return result;
}

/**
 *   decode Hex  ,string only
 *    
 */
string  LEncrypt::hex2Bin(string _in)
{
   long int binSize = 0;
   unsigned char *t = NULL;
   std::string result;

   t = string_to_hex((char *)_in.c_str(), &binSize);  // 位于 x509v3.h

   result.clear();
   result.append((char *)t, binSize);

   return result;
}

//========================================
/**
 *   digext   ,type = EVP_md5()
 *    
 */
string  LEncrypt::digest( char *orig)
{
    char ch[32];
    string str;
    digest(orig,strlen(orig),ch);
    str = ch;
    return str;
}
int LEncrypt::digest(const char *orig, int lenOrig, char *out)
{
   char *buf;
   buf = (char *)orig;
   unsigned int mdlen;
   unsigned char md[EVP_MAX_MD_SIZE];

   EVP_MD_CTX ctx;
   const EVP_MD *type = EVP_md5();
   OpenSSL_add_all_digests();
#if 0
   if (argc > 1)
   {
      type = EVP_get_digestbyname(argv[1]);
      if (type == NULL)
      {
         fprintf(stderr, "Use default : MD5\n");
         type = EVP_md5();
      }
   }
#endif
   EVP_DigestInit(&ctx, type);
   EVP_DigestUpdate(&ctx, buf, lenOrig);
   //EVP_DigestUpdate(&ctx, buf, strlen(buf));
   // EVP_DigestUpdate(&ctx, buf2, strlen(buf2));
   //EVP_DigestUpdate(&ctx, buf3, strlen(buf3));
   EVP_DigestFinal(&ctx, md, &mdlen);
   int len;
#if 0
   int i;
   for (i = 0; i <mdlen;i++)
   {
      printf("%d,%d,%x\n",i,md[i],md[i]);
   }
#endif
   len = encodeHex((char *)md, mdlen, out);
   //printf("len = %d,%d\n",mdlen,EVP_MAX_MD_SIZE);
   // printf("%s\n", out);
   return len;
}
/**
 *    save privateKey RSA* to file
 */

//RSA:=======================================================
int LEncrypt:: prikeySavetoFile(RSA *rsa, const char *filename)
{
   FILE *file;
   if (NULL == rsa)
   {
      printf("RSA not initial.\n");
      return 0;
   }
   file = fopen(filename, "wb");
   if (NULL == filename)
   {
      fprintf(stderr, "%s open error", filename);
      return 0;
   }
   PEM_write_RSAPrivateKey(file, rsa, NULL, NULL, 512, NULL, NULL);
   fclose(file);
   return 1;
}
/**
 *    save publicKey RSA* to file
 */

int LEncrypt::pubkeySavetoFile(RSA *rsa, const char *filename)
{
   FILE *file;
   if (NULL == rsa)
   {
      printf("RSA not initial.\n");
      return 0;
   }
   file = fopen(filename, "wb");
   if (NULL == file)
   {
      fprintf(stderr, "%s open error", filename);
      return 0;
   }
   PEM_write_RSA_PUBKEY(file, rsa);
   fclose(file);
   return 1;
}
//---------------------------
/**
 *    get publicKey RSA* from file
 */

RSA* LEncrypt::pubkeyGetfromFile(RSA *rsa, const char *filename)
{
   FILE *file;
   if (NULL == rsa)
   {
      printf("RSA not initial!\n");
      return NULL;
   }
   file = fopen(filename, "rb");
   if (NULL == file)
   {
      fprintf(stderr, "%s open error", filename);
      return NULL;
   }
   // printf("111111111\n");

   // rsa = PEM_read_RSAPublicKey(file, NULL, NULL, NULL);
   rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);


   if (rsa == NULL)
   {
      printf("PEM_read_RSAPublicKey() err ");
      perror("PEM_read_RSA_PUBKEY() err!!! ");
      fclose(file);
      return NULL;
   }
   fclose(file);
   return rsa;
}
/**
 *    get private Key RSA* from file
 */

RSA* LEncrypt::prikeyGetfromFile(RSA *rsa, const char *filename)
{
   FILE *file;
   if (NULL == rsa)
   {
      printf("RSA not initial!\n");
      return NULL;
   }
   file = fopen(filename, "rb");
   if (NULL == file)
   {
      fprintf(stderr, "%s open error", filename);
      return NULL;
   }
   rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
   if (rsa == NULL)
   {
      perror("PEM_read_RSAPrivateKey() wrong\n");
      fclose(file);
      return NULL;
   }
   fclose(file);
   return rsa;
}
/**
 *   create public KEY private KEY file
 *   #define PUBLIC_KEY_FILE "mypub.key"
 *   #define PRIVATE_KEY_FILE "mypri.key"
 */

int LEncrypt::rsaCreateKeyFiles()
{
   return rsaCreateKeyFiles(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE);
}
/**
 *   create publicKEy private KEY file
 *   
 */
int LEncrypt::rsaCreateKeyFiles(const char *priKey, const char *pubKey)
{
   RSA *key;
   //FILE * fp_pub,*fp_pri;
   key = RSA_generate_key(BUFSIZE, 65537, NULL, NULL);
   if (NULL == key)
   {
      perror("generate_key error\n");
      exit(0);
   }
   if (!prikeySavetoFile(key, priKey))
   {
      perror("Prikey_Saveto_File() error\n");
      exit(0);
   }
   if (!pubkeySavetoFile(key, pubKey))
   {
      perror("Pubkey_Saveto_File() error\n");
      exit(0);
   }
   printf("generate key OK\n");
   return 1;
}
//sign:===============================================================================
/**
 *   sign with private key file
 *   
 */
int LEncrypt::sign(char *keyFile, char *plainText, char *cipherText)
{
   unsigned int len;
   FILE *fp = fopen(keyFile, "r");
   if (fp == NULL)   return 0;

   /* Read private key */
   EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
   fclose(fp);

   if (pkey == NULL)
   {
      ERR_print_errors_fp(stderr);
      return 0;
   }

   /* Do the signature */
   EVP_MD_CTX     md_ctx;
   EVP_SignInit(&md_ctx, EVP_sha1());
   EVP_SignUpdate(&md_ctx, plainText, strlen(plainText));
   int err = EVP_SignFinal(&md_ctx, (unsigned char *)cipherText, &len, pkey);

   if (err != 1)
   {
      ERR_print_errors_fp(stderr);
      return 0;
   }

   EVP_PKEY_free(pkey);
   return len;
}
/**
 *  verify sign with public key file
 *   
 */
bool  LEncrypt::verifySign(char *pubFile, char *cipherText,  int cipherTextLen, char *plainText)
{
   /* Get X509 */
   FILE *fp = fopen(pubFile, "r");
   if (fp == NULL)   return false;
   // cout << "000000\n" ;

   //  openssl rsa -in prikey.key -pubout -out pubout.key
   // make sure the pair

   EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
   if (pkey == NULL)
   {
      ERR_print_errors_fp(stderr);
      return false;
   }

   /* Verify the signature */
   EVP_MD_CTX md_ctx;
   EVP_VerifyInit(&md_ctx, EVP_sha1());
   EVP_VerifyUpdate(&md_ctx, plainText, strlen((char *)plainText));
   int err = EVP_VerifyFinal(&md_ctx, (unsigned char *)cipherText, cipherTextLen, pkey);
   EVP_PKEY_free(pkey);

   if (err != 1)
   {
      ERR_print_errors_fp(stderr);
      return false;
   }
   return true;
}
/**
 *   verify sign with private key Char
 *   
 */
bool  LEncrypt::verifySignPubChar(char *pubChar, char *cipherText,  int cipherTextLen, char *plainText)
{
#if 0
   /* Get X509 */
   FILE* fp = fopen (pubFile, "r");
   if (fp == NULL)
   return false;
#endif
   RSA *rsa = NULL;
   EVP_PKEY *pkey = NULL;
   rsa =   getRsaPubFromChar(pubChar);
   pkey = EVP_PKEY_new();
   if (NULL == pkey)
   {
      printf("open_public_key EVP_PKEY_new failed\n");
      RSA_free(rsa);
      return false;
   }

   EVP_PKEY_assign_RSA(pkey, rsa);
#if 0
   EVP_PKEY *pkey=PEM_read_PUBKEY(fp,NULL,NULL,NULL);
#endif
   if (pkey == NULL)
   {
      ERR_print_errors_fp(stderr);
      return false;
   }

   /* Verify the signature */
   EVP_MD_CTX md_ctx;
   EVP_VerifyInit(&md_ctx, EVP_sha1());
   EVP_VerifyUpdate(&md_ctx, plainText, strlen((char *)plainText));
   int err = EVP_VerifyFinal(&md_ctx, (unsigned char *)cipherText, cipherTextLen, pkey);
   EVP_PKEY_free(pkey);

   if (err != 1)
   {
      ERR_print_errors_fp(stderr);
      return false;
   }
   return true;
}
/**
 *   sign with private key file, and encode to Hex
 *   
 */
int  LEncrypt::signHex(char *keyFile, char *plainText, char *cipherText)
{
   char  hex[1000];
   int len, len1;
   len1 = 0;
   len = sign(keyFile, plainText, cipherText);

   if (len > 0)
   {
      len1 = encodeHex(cipherText, len, hex);
      //printf("encodeHex,len,len1 = %d,%d,\n",len,len1);
      if (len1 > 0)
      {
         memcpy(cipherText, hex, len1);
         cipherText[len1] = 0;
      }

   }
   return len1;
}
/**
 *   decode Hex and verify sign with public  key file
 *   
 */
bool LEncrypt::verifyHex(char *pubFile, char *cipherText, char *plainText)
{
   char  hex[1000];
   int len;
   len = decodeHex(cipherText, hex);
   //printf("len000 = %d\n",len);
   return verifySign(pubFile, hex, len, plainText);
}
/**
 *   decode Hex and verify sign with public  key Char 
 *   
 */
bool LEncrypt::verifyHexPubChar(char *pubChar, char *cipherText, char *plainText)
{
   char  hex[1000];
   int len;
   len = decodeHex(cipherText, hex);
   //printf("len000 = %d\n",len);
   return verifySignPubChar(pubChar, hex, len, plainText);
}
// encrypt sy==============================================================
/**
 *   symmetry encrypt with fixed passwd
 *   
 */
int LEncrypt::encrypt(char *inBuf, int inLen, char *outBuf)
{
   return cipher(inBuf, inLen, outBuf,(char *) MYPASSWD, 1);
}
/**
 *   symmetry de crypt with fixed passwd
 *   
 */
int LEncrypt::decrypt(char *inBuf, int inLen, char *outBuf)
{
   return cipher(inBuf, inLen, outBuf, (char *)MYPASSWD, 0);
}
/**
 *   symmetry encrypt with   passwd
 *   
 */
int LEncrypt::encrypt(char *inBuf, int inLen, char *outBuf, char *passwd)
{
   return cipher(inBuf, inLen, outBuf, passwd, 1);
}
/**
 *   symmetry encrypt with   passwd
 *   
 */
int LEncrypt::decrypt(char *inBuf, int inLen, char *outBuf, char *passwd)
{
   return cipher(inBuf, inLen, outBuf, passwd, 0);
}
/**
 *   symmetry encrypt decrypt  with   passwd \n
 *   mode = 1: encrypt 0:decrypt\n
 *   EVP_MAX_KEY_LENGHT = 64;\n
 *   ENCRYPT_BLOCK =1024 \n
 *    evp_cipher = EVP_aes_128_cbc(); \n

 */
int LEncrypt::cipher(char *inBuf, int inLen, char *outBuf, char *passwd, int mode) //mode = 1:encrypt,0:decrypt;
{

   EVP_CIPHER_CTX ctx;
   unsigned char key[EVP_MAX_KEY_LENGHT] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";  //EVP_MAX_KEY_LENGHT = 64
   unsigned char iv[EVP_MAX_KEY_LENGHT] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
   //unsigned char out[1024] = {0};
   int outl, tmp, i;
   int len, n, len0,ret;
   //len = inLen;
   //  unsigned char msg[1024] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
   //    unsigned char msg[1024] = " 1234567";
   // unsigned char *msg = (unsigned char *)inBuf;
   unsigned char msg[1024 +EVP_MAX_KEY_LENGHT ] = { 0 };
   unsigned char out[2048] = { 0 };
   char *outb,*inb;
   
   //unsigned char *out =  (unsigned char *)outBuf;
   memcpy(key, passwd, strlen(passwd));
   //printf("EVP_MAX_KEY_LENGHT = %d\n",EVP_MAX_KEY_LENGHT);

   int rv;
   OpenSSL_add_all_algorithms();
   EVP_CIPHER_CTX_init(&ctx);

   rv = EVP_CipherInit_ex(&ctx, evp_cipher, NULL, key, iv, mode);
   if (rv != 1)
   {
      printf("Error Init EVP");
      EVP_CIPHER_CTX_cleanup(&ctx);
      return -1;
   }
   outl = 0;
   len0 = ENCRYPT_BLOCK;
   n = inLen / len0;
   inb = inBuf;
   outb = outBuf;
   ret = 0;
   for (i = 0; i < n+1; i++)
   {
       len = len0;
       if(i == n)  len = inLen - i*len0;

       memcpy(msg,inb,len);
       memset(out,0,len0);

      // rv = EVP_EncryptUpdate(&ctx,(unsigned char *) out, &outl, (unsigned char *)msg, DATA_LEN);
      rv = EVP_CipherUpdate(&ctx, (unsigned char *)out, &outl, (unsigned char *)msg, len);
      if (rv != 1)
      {
         printf("Error update EVP");
         EVP_CIPHER_CTX_cleanup(&ctx);
         return -1;
      }
      memcpy(outb,out,outl);
      inb = inb +len;
      outb = outb+outl;
      ret = ret + outl;
      // printf("  update= i,inlen,outlen =%d, %d,%d,%d\n",i ,len, outl,ret);
   }
   
   rv = EVP_CipherFinal_ex(&ctx, (unsigned char *)out, &tmp);
   if (rv != 1)
   {
      printf("Error final EVP");
      EVP_CIPHER_CTX_cleanup(&ctx);
      return -1;
   }
    memcpy(outb,out,tmp);
    ret = ret +tmp;
   //outl = outl + tmp;
  // printf("outl final  = %d,%d\n", tmp,ret);
#if 0
   printf("----cipher_algo is AES128 cipher_mode is CBC  enc outdata is :-----------\n");
   for (i = 0; i < ret; i++) printf("%02X", (unsigned char)outBuf[i]);
   printf("\r\n");
#endif
   outBuf[ret] =0;
   return ret;

}
/**
 *  symmetry encrypt with passwd
 */
int LEncrypt::encrypt1(char *inBuf, int inLen, char *outBuf, char *passwd) //mode = 1:encrypt,0:decrypt;
{

   EVP_CIPHER_CTX ctx;
   unsigned char key[EVP_MAX_KEY_LENGHT] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";  //EVP_MAX_KEY_LENGHT = 64
   unsigned char iv[EVP_MAX_KEY_LENGHT] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
   //unsigned char out[1024] = {0};
   int outl, tmp;
   int len;
   len = inLen;
   //  unsigned char msg[1024] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
   //    unsigned char msg[1024] = " 1234567";
   unsigned char *msg = (unsigned char *)inBuf;
   unsigned char *out =  (unsigned char *)outBuf;
   memcpy(key, passwd, strlen(passwd));
   //printf("EVP_MAX_KEY_LENGHT = %d\n",EVP_MAX_KEY_LENGHT);

   int rv;
   OpenSSL_add_all_algorithms();
   EVP_CIPHER_CTX_init(&ctx);

   rv = EVP_EncryptInit_ex(&ctx, evp_cipher, NULL, key, iv);
   if (rv != 1)
   {
      printf("Error Init EVP");
      EVP_CIPHER_CTX_cleanup(&ctx);
      return -1;
   }
   outl = 0;
   // rv = EVP_EncryptUpdate(&ctx,(unsigned char *) out, &outl, (unsigned char *)msg, DATA_LEN);
   rv = EVP_EncryptUpdate(&ctx, (unsigned char *)out, &outl, (unsigned char *)msg, len);
   if (rv != 1)
   {
      printf("Error update EVP");
      EVP_CIPHER_CTX_cleanup(&ctx);
      return -1;
   }
   //printf("outl update outlen,inlen = %d,%d\n", outl, len);
   rv = EVP_EncryptFinal_ex(&ctx, (unsigned char *)out + outl, &tmp);
   if (rv != 1)
   {
      printf("Error final EVP");
      EVP_CIPHER_CTX_cleanup(&ctx);
      return -1;
   }
   outl = outl + tmp;
   //printf("outl final  = %d,%d\n", outl, tmp);
#if 0
   printf("----cipher_algo is AES128 cipher_mode is CBC  enc outdata is :-----------\n");
   for (i = 0; i < outl; i++) printf("%02x ", out[i]);
   printf("\r\n");
#endif
outBuf[outl] = 0;
   return outl;

}


string  LEncrypt::getMac()
{
    std::string  mac_address;
    mac_address.clear();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        return(false);
    }

    struct ifreq ifr = { 0 };
    strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name) - 1);
    bool ret = (ioctl(sock, SIOCGIFHWADDR, &ifr) >= 0);

    if (!ret )
    {    strncpy(ifr.ifr_name, "eth1", sizeof(ifr.ifr_name) - 1); 
          ret = (ioctl(sock, SIOCGIFHWADDR, &ifr) >= 0);
    }


    close(sock);

    const char hex[] = 
    {
        '0', '1', '2', '3', '4', '5', '6', '7', 
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' 
    };
    char mac[16] = { 0 };
    for (int index = 0; index < 6; ++index)
    {
         size_t value = ifr.ifr_hwaddr.sa_data[index] & 0xFF;
         mac[2 * index + 0] = hex[value / 16];
         mac[2 * index + 1] = hex[value % 16];
    }
    std::string(mac).swap(mac_address);

    return mac_address;
}


 
