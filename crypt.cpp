#include <iostream>
#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if 0
unsigned char *MD2(const unsigned char *d,unsigned long n,unsigned char *md);
unsigned char *MD4(const unsigned char *d,unsigned long n,unsigned char *md);
unsigned char *MD5(const unsigned char *d,unsigned long n,unsigned char *md);
#endif

using namespace std;
int main_dsa();
int main_sign();
int main_rsa();
int main_encode();
int main_decode();
int main_rsa_sign();
int main_bio_mem();
int main_bio_file();
int main_bio_key();
int main_app();
int main_evp();
int main_evpsub() ; 

string toHex(unsigned char *md,int len)
{
   char tmp[3] = { '\0' }, buf[41] = { '\0' };
   int i;
   len = 16;


   for (i = 0; i < len; i++)
   {
      //sprintf(tmp,"%2.2x",md[i]);
      sprintf(tmp, "%02X", md[i]);
      strcat(buf, tmp);
      if (i != i / 2 * 2 && i != 15)
      {
         sprintf(tmp, "%1s", "-");
         strcat(buf, tmp);
      }
   }

   string str;
   str = buf;
   return str;

}
string toHex0(unsigned char *md,int len)
{
   char tmp[3] = { '\0' };
   char buf[2*16] = { '\0' };
   int i;
   //len = 16;


   for (i = 0; i < len; i++)
   {
      //sprintf(tmp,"%2.2x",md[i]);
      sprintf(tmp, "%02X", md[i]);
      strcat(buf, tmp);
      #if 0
      if (i != i / 2 * 2 && i != 15)
      {
         sprintf(tmp, "%1s", "-");
         strcat(buf, tmp);
      }
      #endif
   }

   string str;
   str = buf;
   return str;

}
int main_md5()
{
   string str,s;
   int i;
   unsigned char md[16],*ret;
   
   s = "123456";

   str = s;
   const unsigned char *data = (unsigned char *)str.c_str();
   unsigned long z;
   z = s.length();
   //cout << "len = " << z << endl;
   //z = 4;
   ret = MD5(data, z, md);
   str = toHex(md,16);
   cout << "in = " << s << " md5 " << "out_md = " << str << endl;
   str = toHex(ret,16);
   cout << "in = " << s << " md5 " << "out_ret = " << str << endl;

   ret = MD2(data, z, md);
   str = toHex(md,16);
   cout << "in = " << s << " md2 " << "out_md = " << str << endl;
   str = toHex(ret,16);
   cout << "in = " << s << " md2 " << "out_ret = " << str << endl;

   ret = MD4(data, z, md);
   str = toHex(md,16);
   cout << "in = " << s << " md4 " << "out_md = " << str << endl;
   str = toHex(ret,16);
   cout << "in = " << s << " md4 " << "out_ret = " << str << endl;
   }

int main1 (int argc, char *argv[])
{
    //main_md5();// ok // from this file
    //main_dsa();// err // from mydsa.cpp
    //main_sign();// ok, from sign1.cpp
   // main_bio_mem();//ok
   // main_bio_file();//ok
    // main_bio_key();// ok create a mypubkey.h file
    // main_app();// pubkey in char *, and use PEM_read_bio_RSA_PUBKEY(b,&pub_key,NULL,NULL);
    //main_evp(); // ok 
   main_evpsub()  ;
   
    #if 0 // from rsa1.cpp ;
    main_rsa();//ok
    main_encode();//ok for rsa
    main_decode();// ok for rsa
    main_rsa_sign();//ok
    #endif

    //

    return(0);
}

