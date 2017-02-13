#include "sumInfo.h"
long sumInfo::getCputime()
{
#if  !defined(WIN32)
	struct tms cpuTime;
    long l;
	if( times( &cpuTime ) == -1 )
		return -1;
	l = cpuTime.tms_utime + cpuTime.tms_stime;	
    return l;//sysconf(_SC_CLK_TCK);//= 100; so the accuracy is 1/100S;
#endif
};
int sumInfo::start()
{
    struct timeval tv;
    if(gettimeofday( &tv, NULL ) == 0)
    {
        tv0 = tv;
        cpu0 = getCputime();
        return 0;
    }
    return -1;
};
 
long  sumInfo::elapsed() 
{
    struct timeval tv;
    long  u;
    if(gettimeofday( &tv, NULL ) == 0)
    {
        // time:
        u = (tv.tv_sec-tv0.tv_sec)*1000000 + (tv.tv_usec-tv0.tv_usec);
        sumU += u;
        // counter of record;
        counter ++;
        //cout <<sumU <<"," << u<<endl;
        //cpu
        cpu += getCputime() - cpu0;
        cpu0 = 0;
        if (sumU >= MAX_SUMU) 
        {
            //cout << "dddddddddddd" <<MAX_SUMU <<endl;
            sumS += double(sumU)/1000000;
            
            sumU = 0;
        }
        return u;
    }
    return -1; 
};

 

