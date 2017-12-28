//
// Created by kwang on 12/28/2017.
//

#include "Utils.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "Utils.h"

#include <android/log.h>
#include <cctype>

#define  LOG_TAG    "Utils"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

pid_t GetPid(const char* process_name) {
    if (process_name == NULL) {
        return -1;
    }
    DIR* dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }
    struct dirent* entry;
    while((entry = readdir(dir)) != NULL) {
        size_t pid = atoi(entry->d_name);
        if (pid != 0) {
            char file_name[30];
            snprintf(file_name, 30, "/proc/%d/cmdline", pid);
            FILE *fp = fopen(file_name, "r");
            char temp_name[50];
            if (fp != NULL) {
                fgets(temp_name, 50, fp);
                fclose(fp);
                if (strcmp(process_name, temp_name) == 0) {
                    return pid;
                }
            }
        }
    }
    return -1;
}

bool IsSelinuxEnabled() {
    FILE* fp = fopen("/proc/filesystems", "r");
    char* line = (char*) calloc(50, sizeof(char));
    bool result = false;
    while(fgets(line, 50, fp)) {
        if (strstr(line, "selinuxfs")) {
            result = true;
        }
    }
    if (line) {
        free(line);
    }
    fclose(fp);
    return result;
}

void DisableSelinux() {
    FILE* fp = fopen("/proc/mounts", "r");
    char* line = (char*) calloc(1024, sizeof(char));
    while(fgets(line, 1024, fp)) {
        if (strstr(line, "selinuxfs")) {
            strtok(line, " ");
            char* selinux_dir = strtok(NULL, " ");
            char* selinux_path = strcat(selinux_dir, "/enforce");
            FILE* fp_selinux = fopen(selinux_path, "w");
            char* buf = "0"; // set selinux to permissive
            fwrite(buf, strlen(buf), 1, fp_selinux);
            fclose(fp_selinux);
            break;
        }
    }
    fclose(fp);
    if (line) {
        free(line);
    }
}

long GetModuleBaseAddr(pid_t pid, const char* module_name) {
    long base_addr_long = 0;
    if (pid == -1) {
        return 0;
    }
    char* file_name = (char*) calloc(50, sizeof(char));
    snprintf(file_name, 50, "/proc/%d/maps", pid);
    FILE* fp = fopen(file_name, "r");
    free(file_name);
    char line[512];
    if (fp != NULL) {
        while(fgets(line, 512, fp) != NULL) {
            if (strstr(line, module_name) != NULL) {
                char* base_addr = strtok(line, "-");
                base_addr_long = strtoul(base_addr, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    return base_addr_long;
}

long GetRemoteFuctionAddr(pid_t remote_pid, const char* module_name, long local_function_addr) {
    pid_t pid = getpid();
    long local_base_addr = GetModuleBaseAddr(pid, module_name);
    long remote_base_addr = GetModuleBaseAddr(remote_pid, module_name);
    if (local_base_addr == 0 || remote_base_addr == 0) {
        return 0;
    }
    return local_function_addr + (remote_base_addr - local_base_addr);
}

char* replace_char(char* str, char find, char replace)
{
    char *current_pos = strchr(str,find);
    while (current_pos){
        *current_pos = replace;
        current_pos = strchr(current_pos,find);
    }
    return str;
}

std::vector<unsigned char> ReadFile(const char *fileName)
{

    FILE *f = fopen(fileName, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  //same as rewind(f);

    unsigned char *ptr = (unsigned char *)malloc(fsize);
    fread(ptr, fsize, 1, f);
    fclose(f);

    LOGD("ReadFile %s size=%ld",fileName,fsize);

    std::vector<unsigned char> ret;
    for(int i=0;i<fsize;i++){
        ret.push_back(ptr[i]);
    }
    free(ptr);
    return ret;
}


std::vector<ProcMapsData> GetMaps(int pid)
{
    std::vector<ProcMapsData> ret;
    char file_name[50];
    if (pid <= 0) {
        pid = getpid();
    }
    long base_addr_long = 0;
    snprintf(file_name, 50, "/proc/%d/maps", pid);
    FILE* fp = fopen(file_name, "r");
    char line[10240];
    if (fp != NULL) {
        while(fgets(line, sizeof(line)-1, fp) != NULL) {
            ProcMapsData p;
            if(sscanf(line,"%s %s %s %s %s %s",p.range,p.mode,p.size,p.unk1,p.unk2,p.name)>=5){
                p.Init();
                ret.push_back(p);
            }
        }
        fclose(fp);
    }
    return ret;
}

ProcMapsData GetModuleDataByAddr(int pid,unsigned int addr)
{
    std::vector<ProcMapsData> maps =  GetMaps(pid);
    for(int i=0;i<maps.size();i++){
        ProcMapsData p = maps[i];
        if((p.startddr <= addr)&&(p.endAddr >= addr))
        {
            LOGD("GetModuleDataByAddr %08X found at %08X %08X ",addr, p.startddr,p.endAddr);
            return p;
        }
    }
    return ProcMapsData();
}

ProcMapsData GetModuleData(int pid,char *moduleName)
{
    std::vector<ProcMapsData> maps =  GetMaps(pid);
    for(int i=0;i<maps.size();i++){
        ProcMapsData p = maps[i];
        if(strstr(p.name, moduleName) != NULL){
            //use ths first on we found
            LOGD("GetModuleData found %s at %08X",moduleName, p.startddr);
            return p;
        }
    }
    return ProcMapsData();
}

unsigned int GetModuleBaseAddr(int pid,char *moduleName)
{
    ProcMapsData p = GetModuleData(pid,moduleName);
    return(p.startddr);
}



void DumpHex(void * src,int len)
{
    char tmp[128];
    char line[1024];
    line[0] = 0;
    int i,j;
    unsigned char *p = (unsigned char *)src;
    for(i=0;i<len;i++){
        sprintf(tmp,"%02X ",p[i]);strcat(line,tmp);
        if(((i+1)%16)==0){
            for(j=16;j>0;j--){
                unsigned char ch = p[i+1-j];
                if(isalnum(ch)){
                    sprintf(tmp,"%c",ch);strcat(line,tmp);
                }else{
                    sprintf(tmp,".");strcat(line,tmp);
                }
            }
            //sprintf(tmp,"\n");strcat(line,tmp);
            LOGD("%s",line);line[0]=0;
        }
    }
    int index = i%16;
    // pad space
    for(j=0;j<(16-index);j++){
        sprintf(tmp,"   ");strcat(line,tmp);
    }
    // add the resh if have
    for(j=index;j>0;j--){
        unsigned char ch = p[i-j];
        if(isalnum(ch)){
            sprintf(tmp,"%c",ch);;strcat(line,tmp);
        }else{
            sprintf(tmp,".");;strcat(line,tmp);
        }
    }
    LOGD("%s",line);line[0]=0;
}





