//
// Created by kwang on 12/28/2017.
//

#ifndef GOTHOOK_UTILS_H
#define GOTHOOK_UTILS_H

#include <vector>
#include <stdbool.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>


char* replace_char(char* str, char find, char replace);
class ProcMapsData {
public:
    char range[32];
    char mode[32];
    char size[32];
    char unk1[32];
    char unk2[32];
    char name[1024];
    unsigned int startddr;
    unsigned int endAddr;
    ProcMapsData() {
        name[0] = 0;
        range[0] = 0;
        size[0]=0;
        unk1[0]=0;
        unk2[0]=0;
    }
    void Init() {
        char tmp[32];
        strcpy(tmp,range);
        replace_char(tmp,'-',' ');
        sscanf(tmp,"%x %x",&startddr,&endAddr);
    }

};

class Utils {

};

pid_t GetPid(const char* process_name);
bool IsSelinuxEnabled();
void DisableSelinux();
long GetModuleBaseAddr(pid_t pid, const char* module_name);
long GetRemoteFuctionAddr(pid_t remote_pid, const char* module_name, long local_function_addr);
std::vector<unsigned char> ReadFile(const char *fileName);
std::vector<ProcMapsData> GetMaps(int pid);
ProcMapsData GetModuleDataByAddr(int pid,unsigned int addr);
ProcMapsData GetModuleData(int pid,char *moduleName);
unsigned int GetModuleBaseAddr(int pid,char *moduleName);
void DumpHex(void * src,int len);



#endif //GOTHOOK_UTILS_H
