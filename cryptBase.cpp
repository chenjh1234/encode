
#include "cryptBase.h"

cryptBase::cryptBase()
{

}
cryptBase::~cryptBase()
{

}
RSA * cryptBase::getRsaPubFromChar(char *keyChar)
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
   b = BIO_new_mem_buf((void *)keyChar,strlen((char *)keyChar));
   // printf(" bio new b = 0x%0X,%d\n",b,strlen((char *)pubKey));

   key = PEM_read_bio_RSA_PUBKEY(b,&key,NULL,NULL);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_Char  wrong");
      printf(" bio read error\n");
      return NULL;
   }
   BIO_free(b);
   return key;
}

RSA * cryptBase::getRsaPriFromFile(char *priKeyFile)
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
RSA * cryptBase::getRsaPubFromFile(char *pubKeyFile)
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
int cryptBase::encryptPubkey(RSA *key, char *inBuf, int inLen, char *outBuf)
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
int cryptBase::decryptPrikey(RSA *key, char *inBuf, int inLen, char *outBuf)
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
int cryptBase::encryptPkey(int mode ,RSA *key, char *inBuf, int inLen, char *outBuf)
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
      if (mode == 0)  
          ret = RSA_public_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
                               key, RSA_PKCS1_PADDING); //en-code     
       else
           ret = RSA_private_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
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
       
        if (mode == 0)  
          ret = RSA_public_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
                               key, RSA_PKCS1_PADDING); //en-code     
       else
           ret = RSA_private_encrypt(BUFSIZE0, (unsigned char *)buff, (unsigned char *)buff1,
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
int cryptBase::decryptPkey(int mode ,RSA *key, char *inBuf, int inLen,char *outBuf)
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

   rsa_len = RSA_size(key);
   //printf("rsa_len = %d,%d\n", rsa_len,inLen);
  // return 0;


   // while ((ret = fread(buf, sizeof(char), rsa_len, fp)) == rsa_len) //read string from file
   while (buf +  rsa_len <= inBuf + inLen) //read string from file
   {
      memcpy(buff, buf, rsa_len);
      memset(buff1, 0, BUFSIZE1);

      if (mode == 0)  
           ret = RSA_private_decrypt(rsa_len, (unsigned char *)buff, (unsigned char *)buff1,
                                key, RSA_PKCS1_PADDING); //de-code
      else   
             ret = RSA_public_decrypt(rsa_len, (unsigned char *)buff, (unsigned char *)buff1,
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
   //printf("len === %d",len);
   outBuf[len] = 0;

   RSA_free(key); //relase
   //printf("decode OK\n");
   return len;
}
//----------------------------------------------------------------------------------
int cryptBase::encryptPubChar(char *pubKeyChar, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
   key = getRsaPubFromChar(pubKeyChar);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_Char wrong");
      return 0;
   }
   return encryptPubkey(key, inBuf,inLen, outBuf);
}
//----------encryptPub---------------------------
int cryptBase::encryptPub(char *pubKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
    key = getRsaPubFromFile(pubKeyFile);
   if (NULL == key)
   {
      perror("Pubkey_Getfrom_file wrong");
      return 0;
   }
   return encryptPkey(0,key, inBuf,inLen,outBuf);
}
int cryptBase::decryptPri(char *priKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
    key = getRsaPriFromFile(priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_file wrong");
      return 0;
   }
   return decryptPkey(0,key, inBuf,inLen,outBuf);
}
//encryptPri:-----------------------------------------------
int cryptBase::encryptPri(char *priKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
    key = getRsaPriFromFile(priKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_file wrong");
      return 0;
   }
   return encryptPkey(1,key, inBuf,inLen,outBuf);
}
//decryptPub:-----------------------------------------------
int cryptBase::decryptPub(char *pubKeyFile, char *inBuf, int inLen, char *outBuf)
{
   RSA *key;
    key = getRsaPubFromFile(pubKeyFile);
   if (NULL == key)
   {
      perror("Prikey_Getfrom_file wrong");
      return 0;
   }
   //printf("decrypt pub0000\n");
   return decryptPkey(1,key, inBuf,inLen,outBuf);
}
//==encryptPubkey===========================================================
int cryptBase::encryptPubkey(char *pubKeyFile, char *inBuf, int inLen, char *outBuf)
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
int cryptBase::decryptPrikey(char *priKeyFile, char *inBuf, int inLen, char *outBuf)
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
int  cryptBase:: encodeBase64(const char *input, int length, char *bufOut)
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
int  cryptBase:: decodeBase64(char *input,  char *bufOut)
{
   BIO *b64 = NULL;
   BIO *bmem = NULL;
   int len,leno;
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
char* cryptBase:: encodeBase64(const char *input, int length, bool with_new_line)
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
char* cryptBase:: decodeBase64(char *input, int length, bool with_new_line)
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
int  cryptBase::base64Encode(const char *encoded, int encodedLength, char *decoded)
{
   return EVP_EncodeBlock((unsigned char *)decoded, (const unsigned char *)encoded, encodedLength);
}

// base解码
int  cryptBase::base64Decode(const char *encoded, int encodedLength, char *decoded)
{
   return EVP_DecodeBlock((unsigned char *)decoded, (const unsigned char *)encoded, encodedLength);
}

int  cryptBase:: decodeHex(char *buf, char *retBuf)
{
     int len,leno;
     int i,j;
     char ch;
     unsigned char tmp;
     len = strlen(buf)/2;
    // cout << "len = " << len <<endl;

    for (i = 0; i <len ;i++)
    {
        tmp = 0;
         for (j = 0; j <2;j++)
         {
             ch = buf[2*i+j];
             //cout << i << ","<<j <<"=" << ch;
            if (ch >= '0' && ch <= '9') 
            {
                 //printf("----%x,",tmp);
                tmp =( tmp <<4) + (ch - '0');
                //printf("%x----",tmp);
            }
            else if (ch >= 'a' && ch <= 'f')
            {
               tmp = ( tmp <<4) + (ch - 'a'+10);
            }
             else if (ch >= 'A' && ch <= 'F')
            {
               tmp = ( tmp <<4) + (ch - 'A'+10);
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
int cryptBase::encodeHex(const char *buf, int len,  char *str)
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
   *tmp = '\0';
   // printf(" str111 = %s\n",str);
   return  2 * len;
}


/** 
* @brief 二进制转十六进制 
* @author  
*/
string  cryptBase::bin2Hex(string _in)
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
* @brief 十六进制转二进制 
* @author  
*/
string  cryptBase::hex2Bin(string _in)
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
int cryptBase::digest(const char *orig, int lenOrig, char *out)
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

//RSA:=======================================================
int cryptBase:: prikeySavetoFile(RSA *rsa, const char *filename)
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
int cryptBase::pubkeySavetoFile(RSA *rsa, const char *filename)
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
RSA* cryptBase::pubkeyGetfromFile(RSA *rsa, const char *filename)
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
/****************************************
 *read private key from file
 ****************************************/
RSA* cryptBase::prikeyGetfromFile(RSA *rsa, const char *filename)
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
int cryptBase::rsaCreateKeyFiles()
{
   return rsaCreateKeyFiles(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE);
}
int cryptBase::rsaCreateKeyFiles(const char *priKey, const char *pubKey)
{
   RSA *key;
   FILE * fp_pub,*fp_pri;
   key = RSA_generate_key(1024, 65537, NULL, NULL);
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

#if 0
// 生成公钥文件和私钥文件，私钥文件带密码
int cryptBase::createKeyFiles(const char *pub_keyfile, const char *pri_keyfile,
                              const unsigned char *passwd, int passwd_len)
{
   RSA *rsa = NULL;
   RAND_seed(rnd_seed, sizeof(rnd_seed));
   rsa = RSA_generate_key(RSA_KEY_LENGTH, RSA_F4, NULL, NULL);
   if (rsa == NULL)
   {
      printf("RSA_generate_key error!\n");
      return -1;
   }

   // 开始生成公钥文件
   BIO *bp = BIO_new(BIO_s_file());
   if (NULL == bp)
   {
      printf("generate_key bio file new error!\n");
      return -1;
   }

   if (BIO_write_filename(bp, (void *)pub_keyfile) <= 0)
   {
      printf("BIO_write_filename error!\n");
      return -1;
   }

   if (PEM_write_bio_RSAPublicKey(bp, rsa) != 1)
   {
      printf("PEM_write_bio_RSAPublicKey error!\n");
      return -1;
   }

   // 公钥文件生成成功，释放资源
   printf("Create public key ok!\n");
   BIO_free_all(bp);

   // 生成私钥文件
   bp = BIO_new_file(pri_keyfile, "w+");
   if (NULL == bp)
   {
      printf("generate_key bio file new error2!\n");
      return -1;
   }

   if (PEM_write_bio_RSAPrivateKey(bp, rsa,
                                   EVP_des_ede3_ofb(), (unsigned char *)passwd,
                                   passwd_len, NULL, NULL) != 1)
   {
      printf("PEM_write_bio_RSAPublicKey error!\n");
      return -1;
   }

   // 释放资源
   printf("Create private key ok!\n");
   BIO_free_all(bp);
   RSA_free(rsa);

   return 0;
}
EVP_PKEY* cryptBase::openPublicKey(const char *keyfile)
{
   EVP_PKEY *key = NULL;
   RSA *rsa = NULL;

   OpenSSL_add_all_algorithms();
   BIO *bp = BIO_new(BIO_s_file());;
   BIO_read_filename(bp, keyfile);
   if (NULL == bp)
   {
      printf("open_public_key bio file new error!\n");
      return NULL;
   }

   rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
   if (rsa == NULL)
   {
      printf("open_public_key failed to PEM_read_bio_RSAPublicKey!\n");
      BIO_free(bp);
      RSA_free(rsa);

      return NULL;
   }

   printf("open_public_key success to PEM_read_bio_RSAPublicKey!\n");
   key = EVP_PKEY_new();
   if (NULL == key)
   {
      printf("open_public_key EVP_PKEY_new failed\n");
      RSA_free(rsa);

      return NULL;
   }

   EVP_PKEY_assign_RSA(key, rsa);
   return key;
}
// 打开私钥文件，返回EVP_PKEY结构的指针
EVP_PKEY* cryptBase::openPrivateKey(const char *keyfile, const unsigned char *passwd)
{
   EVP_PKEY *key = NULL;
   RSA *rsa = RSA_new();
   OpenSSL_add_all_algorithms();
   BIO *bp = NULL;
   bp = BIO_new_file(keyfile, "rb");
   if (NULL == bp)
   {
      printf("open_private_key bio file new error!\n");

      return NULL;
   }

   rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, (void *)passwd);
   if (rsa == NULL)
   {
      printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
      BIO_free(bp);
      RSA_free(rsa);

      return NULL;
   }

   printf("open_private_key success to PEM_read_bio_RSAPrivateKey!\n");
   key = EVP_PKEY_new();
   if (NULL == key)
   {
      printf("open_private_key EVP_PKEY_new failed\n");
      RSA_free(rsa);

      return NULL;
   }

   EVP_PKEY_assign_RSA(key, rsa);
   return key;
}
// 使用密钥加密，这种封装格式只适用公钥加密，私钥解密，这里key必须是公钥  ??
int cryptBase::rsaKeyEncrypt(EVP_PKEY *key, const unsigned char *orig_data, size_t orig_data_len,
                             unsigned char *enc_data, size_t& enc_data_len)
{
   EVP_PKEY_CTX *ctx = NULL;
   OpenSSL_add_all_ciphers();

   ctx = EVP_PKEY_CTX_new(key, NULL);
   if (NULL == ctx)
   {
      printf("ras_pubkey_encryptfailed to open ctx.\n");
      EVP_PKEY_free(key);
      return -1;
   }

   if (EVP_PKEY_encrypt_init(ctx) <= 0)
   {
      printf("ras_pubkey_encryptfailed to EVP_PKEY_encrypt_init.\n");
      EVP_PKEY_free(key);
      return -1;
   }

   if (EVP_PKEY_encrypt(ctx,
                        enc_data,
                        &enc_data_len,
                        orig_data,
                        orig_data_len) <= 0)
   {
      printf("ras_pubkey_encryptfailed to EVP_PKEY_encrypt.\n");
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(key);

      return -1;
   }

   EVP_PKEY_CTX_free(ctx);
   EVP_PKEY_free(key);

   return 0;
}
// 使用密钥解密，这种封装格式只适用公钥加密，私钥解密，这里key必须是私钥  ??
int cryptBase::rsaKeyDecrypt(EVP_PKEY *key, const unsigned char *enc_data, size_t enc_data_len,   unsigned char *orig_data, size_t& orig_data_len)
{
   EVP_PKEY_CTX *ctx = NULL;
   OpenSSL_add_all_ciphers();

   ctx = EVP_PKEY_CTX_new(key, NULL);
   if (NULL == ctx)
   {
      printf("ras_prikey_decryptfailed to open ctx.\n");
      EVP_PKEY_free(key);
      return -1;
   }
   if (EVP_PKEY_decrypt_init(ctx) <= 0)
   {
      printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt_init.\n");
      EVP_PKEY_free(key);
      return -1;
   }
   if (EVP_PKEY_decrypt(ctx,
                        orig_data,
                        &orig_data_len,
                        enc_data,
                        enc_data_len) <= 0)
   {
      printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt.\n");
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(key);

      return -1;
   }

   EVP_PKEY_CTX_free(ctx);
   EVP_PKEY_free(key);
   return 0;
}
#endif