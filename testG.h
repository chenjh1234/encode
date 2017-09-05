
#ifndef TESTG_H
#define TESTG_H

#include <math.h>
#include <stdio.h>
#include <map>
#include <iostream>
#include "LSummary.h"
#include <sstream>
using namespace std;

//defines:
#define BGSTR1 "----------"
#define BGSTR "==============================" //  use print message for testFrame; start with
#define ERRSTR "+++++++++++++++++++++++++++++++++++" // printout for Micro command if error =1;
#define prSTR "------ " // for pr() : use print message for testFrame; start with 
#define PRSTR "          " // for PR() : use print message for testFrame; start with
#define VERSION 1.2

#define PASSED "PASSED            : "  // string for PASSED
#define NPASSED "NOT PASSED+++++++ : " // string for not passwd
#define GAPSTR "     " // blank gap
#define OUT cout<<PRSTR // output device ,start with PRSTR;
// print functions:
void pr(string);// pring out message  start with prSTR
void prt(string); // printout message form 0 colume
void PR(string);// pring out message  start with PRSTR // user use

LSummary sumUnit;
LSummary sumTest;
map<string,int> errSum;

// for float compare functions:
template <typename T>
inline T gAbs(const T &t) { return t >= 0 ? t : -t; }
template <typename T>
inline const T &gMin(const T &a, const T &b) { if (a < b) return a; return b; }
template <typename T>
inline const T &gMax(const T &a, const T &b) { if (a < b) return b; return a; }
static inline bool gEQ(double p1, double p2)
{
    return (gAbs(p1 - p2) <= 0.000000000001 * gMin(gAbs(p1), gAbs(p2)));
}
static inline bool gEQ(float p1, float p2)
{
    return (gAbs(p1 - p2) <= 0.00001f * gMin(gAbs(p1), gAbs(p2)));
}

//function Macro define:
 
#define U_START(x) \
    void x (string mytest) {\
    initUnit(mytest);

#define U_END \
    endUnit();\
    }

#define U_TEST(x) \
    x(#x); 
  
#define M_START \
    int main(int argc,char **argv) {\
    initTest();

#define M_END \
    endTest();\
    }

#define M_END0  }
  
  
// statistic init:

int pass =0; // test ok
int err =0;  // test err
int unit = 0;
int mypass,myerr;// test in Unit
                
string testUnit; // current UNIT name
string testRemark;// current case remark;
string paraMark;// current case remark;

// data number to to string

/** STR function used processing: make x to string */
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

//statistic and print out

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
#define REM(x)  testRemark = #x;


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

// functions :
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
    string name,uname;
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
    if (myerr !=0)  
    {
        uname = STR(unit+1)+":"+name;
        errSum[uname] = myerr;
    }
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
    //int i;
    str = string("test All") + BGSTR1 + BGSTR1+ "statistic" + BGSTR1 + BGSTR1;
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
        str = string("test All") + BGSTR1 + BGSTR1 + "end" + " OK" + BGSTR1 + BGSTR1;
    else
         str = string("test All") + BGSTR1 + BGSTR1 + str1 + BGSTR1 + BGSTR1;
    prt(str);
      // pr errrs:
    QList<int> unitList;
    if (err !=0) 
    {
        str = string("Errs") + BGSTR1 + BGSTR1+ "errs" + BGSTR1 + BGSTR1;
        prt(str);

        map<string,int>::iterator iter;   
        for( iter = errSum.begin(); iter != errSum.end(); iter++ ) 
        {
            str = string("unit") +  iter->first  + " = " + STR(iter->second);
            pr(str);
        }

    }
}
#endif
#if 0

manual:
  test function & main function define:

    U_START(name) :unit test function begin
    U_END         :unit test function end
    M_START       : instate of main();  // main() { init_test()
    M_END         : end of main()       //  end_test() } :add statistic info
  micros: for usecase
    GT(x,y)       :x>y
    EQ(x,y)       :x==y
    NEQ(x,y)      :x!=y
    LT(x,y)       :x<y
    EQF(x,y)      :x==y ,for floating
    NEQF(x,y)     :x!=y ,for floating
    NULL_PTR(x)   :x==NULL
    VALID_PTR(x)  :x!=NULL
  print:
    PR(string x)         :prinf x  begin"    "
    pr(string x)         :prinf x  begin"----"
    prt(string x)        :same as cout 

#endif

#if 0 //version 1.2
   test Frame example: 
    
   U_START(mytest)
        int i;
        i = 10;
        REM("i == 10,remark of the test:");//option
        EQ(i,10);
        EQ(i,11);
   U_END 
   M_START 
        UTEST(mytest)
   M_END 
result:
{
test ---------- ---------- begin---------- ---------- 
1: UNIT ---------- mytest---------- 
------ 1: PASSED            : EQ(i,10)      i == 10,remark of the test:
------ 2: NOT PASSED+++++++ : EQ(i,11)      
------ pass = 1, err = 1
------ elapsed = 6.1e-05, cpuTime = 1
------ test MYTEST with Err ++++++++++++++++++++
test All---------- ---------- statistic---------- ---------- 
test UNIT = 1
test USECASE = 2
test PASSED = 1
test ERR = 1
test Elapsed = 0.000293, cpuTime = 1
test All---------- ---------- test ERR = 1---------- ---------- 
}
#endif
#if 0
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
#endif
