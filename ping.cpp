#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/time.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <math.h>

typedef struct IPhead
{
    //这里使用了C语言的位域，也就是说像version变量它的大小在内存中是占4bit，而不是8bit
    uint8_t     version : 4; //IP协议版本
    uint8_t     headLength : 4;//首部长度
    uint8_t     serverce;//区分服务
    uint16_t    totalLength;//总长度
    uint16_t    flagbit;//标识
    uint16_t    flag : 3;//标志
    uint16_t    fragmentOffset : 13;//片偏移
    char        timetoLive;//生存时间（跳数）
    uint8_t     protocol;//使用协议
    uint16_t    headcheckSum;//首部校验和
    uint32_t    srcIPadd;//源IP
    uint32_t    dstIPadd;//目的IP
    //可选项和填充我就不定义了
} IPhead;

//ICMP头
typedef struct ICMPhead
{
    uint8_t type;//类型
    uint8_t code;//代码
    uint16_t checkSum;//校验和
    uint16_t ident;//进程标识符
    uint16_t seqNum;//序号
} ICMPhead;
//ICMP回显请求报文(发送用)
typedef struct ICMP
{
    ICMPhead icmphead;//头部
    uint32_t timeStamp;//时间戳
    char     data[32];//数据
};
//ICMP应答报文(接收用)
typedef struct ICMPReply
{
    IPhead iphead;//IP头
    ICMP icmpanswer;//ICMP报文
    char data[1024];//应答报文携带的数据缓冲区
} ICMPReply;


static uint16_t getCheckSum(void * protocol)
{
    uint32_t checkSum = 0;
    uint16_t* word = (uint16_t*)protocol;
    uint32_t size = sizeof(ICMP);

    while (size > 1)//用32位变量来存是因为要存储16位数相加可能发生的溢出情况，将溢出的最高位最后加到16位的最低位上
    {
        checkSum += *word++;
        // printf("[%s:%d]checkSum:0x%x\n", __FUNCTION__, __LINE__, checkSum);
        size -=sizeof(uint16_t);
    }
    if (size)
    {
        checkSum += *(uint8_t*)word;
        // printf("[%s:%d]checkSum:0x%x\n", __FUNCTION__, __LINE__, checkSum);
    }
    //二进制反码求和运算，先取反在相加和先相加在取反的结果是一样的，所以先全部相加在取反
    //计算加上溢出后的结果
    // while (checkSum >> 16) {
    //     checkSum = (checkSum >> 16) + (checkSum & 0xffff);
    // }
    checkSum =(checkSum >> 16) + (checkSum & 0xffff);
    // printf("[%s:%d]checkSum:0x%x\n", __FUNCTION__, __LINE__, checkSum);
    checkSum +=(checkSum >> 16);
    // printf("[%s:%d]checkSum:0x%x\n", __FUNCTION__, __LINE__, checkSum);
    //取反
    return (~checkSum);
}

static bool sendICMPReq(int mysocket, sockaddr_in &dstAddr,unsigned int num)
{
    struct timeval tv;
    //创建ICMP请求回显报文
    //设置回显请求
    ICMP myIcmp;//ICMP请求报文
    myIcmp.icmphead.type = 8;
    myIcmp.icmphead.code = 0;
    //设置初始检验和为0
    myIcmp.icmphead.checkSum = 0;
    //获得一个进程标识
    myIcmp.icmphead.ident = (uint16_t)getpid();
    //设置当前序号为0
    myIcmp.icmphead.seqNum = ++num;
    //保存发送时间
    gettimeofday(&tv, NULL);
    myIcmp.timeStamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    // myIcmp.timeStamp = GetTickCount();
    //计算并且保存校验和
    myIcmp.icmphead.checkSum = getCheckSum((void*)&myIcmp);
    
    //发送报文
    printf("[%s:%d]checkSum:0x%x\n", __FUNCTION__, __LINE__, myIcmp.icmphead.checkSum);
    printf("[%s:%d]send timeStamp:%lld\n", __FUNCTION__, __LINE__, myIcmp.timeStamp);
    int len = sendto(mysocket, (char*)&myIcmp, sizeof(ICMP), 0, (sockaddr*)&dstAddr, sizeof(sockaddr_in));
    if (len < 0)
    {
        printf("sendto len:%d\n", len);
        std::cerr << "socket 发送错误:" << errno << std::endl;
        return false;
    }
    return true;
}

// int waitForSocket(int mysocket)
// {
//     //5S 等待套接字是否由数据
//     timeval timeOut;
//     fd_set  readfd;
//     readfd.fd_count = 1;
//     readfd.fd_array[0] = mysocket;
//     timeOut.tv_sec = 5;
//     timeOut.tv_usec = 0;
//     return (select(1, &readfd, NULL, NULL, &timeOut));
// }

static int waitForSocket(int fd, int write)
{
    int ev = write ? POLLOUT : POLLIN;
    struct pollfd p = { .fd = fd, .events = ev, .revents = 0 };
    int ret;
    ret = poll(&p, 1, 2000);
    return ret < 0 ? ret : p.revents & (ev | POLLERR | POLLHUP) ? 0 : 1;
}

static int64_t readICMPanswer(int mysocket, sockaddr_in &srcAddr, char &TTL)
{
    ICMPReply icmpReply;//接收应答报文
    int addrLen = sizeof(sockaddr_in);
    //接收应答
    int len = recvfrom(mysocket, (char*)&icmpReply, sizeof(ICMPReply), 0, (sockaddr*)&srcAddr, (socklen_t *)&addrLen);
    printf("[%s:%d]recv len:%d\n", __FUNCTION__, __LINE__, len);
    if (len < 0)
    {
        std::cerr << "socket 接收错误:" << errno << std::endl;
        return -1;
    }
    //读取校验并重新计算对比
    uint16_t checkSum = icmpReply.icmpanswer.icmphead.checkSum;
    //因为发出去的时候计算的校验和是0
    icmpReply.icmpanswer.icmphead.checkSum = 0;
    printf("[%s:%d]recv timeStamp:%lld\n", __FUNCTION__, __LINE__, icmpReply.icmpanswer.timeStamp);
    //重新计算
    if (checkSum == getCheckSum((void*)&icmpReply.icmpanswer)) {
        //获取TTL值
        TTL = icmpReply.iphead.timetoLive;
        return icmpReply.icmpanswer.timeStamp;
    }

    return -1;
}

static void doPing(int mysocket, sockaddr_in & srcAddr, sockaddr_in & dstAddr, int num)
{
    int64_t    timeSent;//发送时的时间
    uint32_t    timeElapsed;//延迟时间
    char        TTL;//跳数
    struct timeval tv;
    //发送ICMP回显请求
    sendICMPReq(mysocket, dstAddr, num);
    //等待数据
    int ret = waitForSocket(mysocket, 0);
    if (ret < 0)
    {
        std::cerr << "socket发生错误:" << errno << std::endl;
        return;
    }
    if (ret > 0)
    {
        std::cout << "请求超时:" << std::endl;
        return;
    }
    timeSent = readICMPanswer(mysocket, srcAddr, TTL);
    printf("[%s:%d]timeSent:%u\n", __FUNCTION__, __LINE__, (uint32_t)timeSent);
    if (timeSent != -1) {
        gettimeofday(&tv, NULL);
        timeElapsed = tv.tv_sec * 1000 + tv.tv_usec / 1000 - timeSent;
        //输出信息，注意TTL值是ASCII码，要进行转换
        std::cout << "来自 " << inet_ntoa(srcAddr.sin_addr) << " 的回复: 字节= " << sizeof(((ICMP *)0)->data) << " 时间= " << timeElapsed << "ms TTL= " << fabs((int)TTL) << std::endl;
    }
    else {
        std::cout << "请求超时" << std::endl;
    }
}

static int ping(const char * dstIPaddr, short port)
{
    int      rawSocket;//socket
    sockaddr_in srcAddr;//socket源地址
    sockaddr_in dstAddr;//socket目的地址
    int         Ret;//捕获状态值
    char        TTL = '0';//跳数

    //生成一个套接字
    //TCP/IP协议族,RAW模式，ICMP协议
    //RAW创建的是一个原始套接字，最低可以访问到数据链路层的数据，也就是说在网络层的IP头的数据也可以拿到了。
    // rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    printf("[%s:%d]rawSocket:%d\n", __FUNCTION__, __LINE__, rawSocket);
    if (rawSocket < 0) {
        printf("[%s:%d]socket create err:<%d> rawSocket:%d\n", __FUNCTION__, __LINE__, errno, rawSocket);
        return -1;
    }
    //设置目标IP地址
    dstAddr.sin_addr.s_addr = inet_addr(dstIPaddr);
    //端口
    dstAddr.sin_port = htons(port);
    //协议族
    dstAddr.sin_family = AF_INET;

    //提示信息
    printf("ping address:%s bytes:%d\n", inet_ntoa(dstAddr.sin_addr), sizeof(((ICMP *)0)->data));

    //执行4次ping
    for (int i = 0; i < 4; i++)
    {
        doPing(rawSocket, srcAddr, dstAddr, i);
        usleep(1000000);
    }


    close(rawSocket);

    return 0;
}



int main(int argc, char *argv[]) {
    char *addr = "127.0.0.1";
    printf("start ping ...\n");
    // ping("172.16.20.202", 0);
    if (argc > 1) {
        addr = argv[1];
    }
    ping(addr, 0);
    printf("end ping ...\n");
}
