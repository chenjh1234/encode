
#ifndef TESTG_H
#define TESTG_H

#include <math.h>
#include <stdio.h>
#include <iostream>
#include "sumInfo.h"
#include <sstream>

using namespace std;
//#include "ggeometry.h"
#define BGSTR "---------- " //  use print message for testFrame; start with
#define ERRSTR "++++++++++++++++++++" // printout for Micro command if error =1;

#define prSTR "------ " // for pr() : use print message for testFrame; start with 

#define PRSTR "          " // for PR() : use print message for testFrame; start with


#define PASSED "PASSED            : "  // string for PASSED
#define NPASSED "NOT PASSED+++++++ : " // string for not passwd
#define GAPSTR "     " // blank gap
#define OUT cout<<PRSTR // output device ,start with UBGSTR;

void pr(string);// pring out message  start with prSTR
void prt(string); // printout message form 0 colume
void PR(string);// pring out message  start with PRSTR // user use

sumInfo sumUnit;
sumInfo sumTest;

/** 
   test Frame example: 
    
   void mytest(string mytest) 
   { 
        initUnit( mytest);
        int i;
        i = 10;
        REM("i == 10,remark of the test:");//option
        EQ(i,10);
        EQ(i,11);
        endUnit();
   } 
   int main() 
   { 
        initTest();
        mytest("MYTEST");
        endTest();
   } 
    
result: 
{ 
test ==============================begin
1: UNIT ===============1:
-----test MYTEST===============begin
-----1: PASSED           : i == 10,remark of the test:
-----2: NOT PASSED+++++++: i == 11,remark of the test:
-----pass = 1, err = 1
-----test MYTEST with Err ++++++++++++++++++++
-----test MYTEST===============end
test All==============================end
test UNIT = 1
test USECASE = 2
test PASSED = 1
test ERR = 1 
}    
   terms: 
    a UNIT:    a function is a unit;
    a usecase: a command Micro is a usecase;
*/
//function define:
//
#define U_START(x) \
    void test_x(string mytest) {\
    initUnit(mytest);

#define U_END \
    endUnit();\
    }

#define U_TEST(x) \
    test_x(#x); 
  
#define M_START \
    int main() {\
    initTest();

#define M_END \
    endTest();\
    }

#define M_END0  }
  
  
//

int pass =0; // test ok
int err =0;  // test err
int unit = 0;
int mypass,myerr;// test in Unit
string testUnit; // current UNIT name
string testRemark;// current case remark;
string paraMark;// current case remark;

/** STR function used processing */
#define STR_PROC(x) {\
    stringstream ss;\
    ss << x;\
    return ss.str();}\
/**
 * Function: convert number to string

 */
string STR(int x)
     STR_PROC(x)
string STR(int *x)
     STR_PROC(x)
string STR(long x)
     STR_PROC(x)
string STR(float x)
     STR_PROC(x)
string STR(double x)
     STR_PROC(x)

/** command common used processing :printout PASSED or NOT
 *  PASSWD */
#define COMMAND_PROC \
    {mypass = mypass +1;pr(STR(mypass+myerr) + ": " + PASSED +paraMark +GAPSTR+ testRemark);}\
else \
    {myerr = myerr +1;pr(STR(mypass+myerr) + ": " + NPASSED + paraMark + GAPSTR + testRemark);}\
testRemark = "";

 /**
 * Micro remark:REM : comment for next Micro command:
 */
#define REM(x)  testRemark = x;


/// Micro command (EQ,NEQ,GT,LT,NULL_PTR,VALID_PTR);
/**
 * Micro command:EQ
 */
#define PARA2_STR string("(")+#x+","+#y+") "

#define EQF(x,y) \
paraMark = string("EQF(")+#x+","+#y+") ";\
if(gEQ(x,y)) \
COMMAND_PROC

#define EQ(x,y) \
paraMark = string("EQ(")+#x+","+#y+") ";\
if (x == y) \
COMMAND_PROC
/**
 * Micro command:NEQ
 */
#define NEQF(x,y) \
paraMark = string("NEQF(")+#x+","+#y+") ";\
if(!gEQ(x,y)) \
COMMAND_PROC

#define NEQ(x,y) \
paraMark = string("NEQ(")+#x+","+#y+") ";\
if (x!=y ) \
COMMAND_PROC

/**
 * Micro command:GT
 */
#define GT(x,y) \
paraMark = string("GT(")+#x+","+#y+") ";\
if (x>y ) \
COMMAND_PROC
/**
 * Micro command:GT
 */
#define LT(x,y) \
paraMark = string("LT(")+#x+","+#y+") ";\
if (x<y ) \
COMMAND_PROC
/**
 * Micro command:NULL_PTR
 */
#define NULL_PTR(x) \
paraMark = string("NULL_PTR(")+#x+") ";\
if (x == NULL ) \
COMMAND_PROC
/**
 * Micro command:NULL_PTR
 */
#define VALID_PTR(x) \
paraMark = string("VALID_PTR(")+#x+") ";\
if (x != NULL ) \
COMMAND_PROC


/**
 * print out string Leading with TAB = "------"; 
 * used for testUnit; 
 */
void pr(string str)
{
    cout << prSTR << str.c_str() <<endl;
}
/**
 * print out string Leading with TAB = "     " 
 * used for testAll 
 */
void PR(string str)
{
    cout << PRSTR << str.c_str() <<endl;
}

/**
 * print out string Leading with TAB = "" 
 * used for testAll 
 */
void prt(string str)
{
    cout  << str.c_str() <<endl;
}
/**
 * initialize the test Frame, print out the begin test string
 */
void initTest()
{
    string str;
    mypass = 0;
    myerr = 0;
    str =  string("test ") + BGSTR + BGSTR + "begin"+ BGSTR + BGSTR;
    sumTest.start();

    prt(str);
}
/**
 *  begin test unit:
 * @param name : name of the test UNIT
 */
void initUnit(string name)
{
    string str;
    testUnit = name;
    stringstream ss;
    mypass = 0;
    myerr = 0;
    sumUnit.start();

    ss << unit+1 << ": " <<"UNIT " <<BGSTR <<  name + BGSTR;
    prt(ss.str());
    //str =  "test "+name + BGSTR + "begin";
    //pr(str);
}
/**
 * end of test UNIT,\n 
 * print some statistic informatin of the UNIT; 
 */
 
void endUnit()
{
    string str;
    string name;
    name = testUnit;
    //stringstream ss;
    //result:
    //ss << "pass = " << mypass << << myerr;
// number passed,err
    str = "pass = " + STR(mypass) + ", err = " + STR(myerr);
    pr(str);
// time: cputime
    sumUnit.elapsed();
    str = "elapsed = " + STR(sumUnit.getTime()) + ", cpuTime = " + STR(sumUnit.getCputime());
    pr(str);
    //is OK
// ok or err message:
    if (myerr == 0) str =  "test " + name + " OK"; 
    else str = "test " + name + " with Err "+ ERRSTR ; 
    pr(str);

    //end
    //str =  "test "+name + BGSTR+ "end";
   // pr(str);
    // statistic:
    pass = pass + mypass;
    err = err + myerr;
    unit ++;
}
/**
 * end of test Frame , 
 * print out some statistic information of the test. 
 * 
 * @author cjh (7/27/2016)
 */
void endTest()
{
    string str,str1;
    int i;
    str = string("test All") + BGSTR + BGSTR+ "statistic" + BGSTR + BGSTR;
    prt(str);
    str = "test UNIT = "+ STR(unit);
    prt(str);
    str = "test USECASE = "+ STR(pass+err);
    prt(str);
    str = "test PASSED = " + STR(pass);
    prt(str);
    str =   "test ERR = " +STR(err);
    prt(str);
    str1 = str;

        // time: cputime
    sumTest.elapsed();
    str = "test Elapsed = " + STR(sumTest.getTime()) + ", cpuTime = " + STR(sumTest.getCputime());
    prt(str);

    // all
    if (err == 0) 
        str = string("test All") + BGSTR + BGSTR + "end" + " OK" + BGSTR + BGSTR;
    else
         str = string("test All") + BGSTR + BGSTR + str1 + BGSTR + BGSTR;
    prt(str);

}
#endif

