//
// Created by kwang on 12/29/2017.
//
#include <jni.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <android/log.h>
#include <sys/mman.h>
#include "Utils.h"
#include "ProcUtil.h"

#include <android/log.h>
#include <dirent.h>

#define  LOG_TAG    "ProcUtil"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void ProcMapsData::Init() {
    char tmp[32];
    strcpy(tmp,range);
    Utils::replace_char(tmp,'-',' ');
    sscanf(tmp,"%x %x",&startAddr,&endAddr);
}


bool ProcUtil::IsSelinuxEnabled() {
    char line[512];
    FILE* fp = fopen("/proc/filesystems", "r");
    bool result = false;
    while(fgets(line, 50, fp)) {
        if (strstr(line, "selinuxfs")) {
            result = true;
        }
    }
    fclose(fp);
    return result;
}

void ProcUtil::DisableSelinux() {
    char line[512];
    FILE* fp = fopen("/proc/mounts", "r");
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
}

long ProcUtil::GetPid(const char *process_name) {
    DIR* dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }
    struct dirent* entry;
    while((entry = readdir(dir)) != NULL) {
        long pid = atoi(entry->d_name);
        if (pid != 0) {
            char file_name[64];
            sprintf(file_name, "/proc/%d/cmdline", pid);
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


ProcMap::ProcMap(int pid) {
    this->pid = pid;
    GetMaps(pid);
}

void ProcMap::GetMaps(int pid)
{
    maps.clear();
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
            ProcMapsData p(line);
            if(p.isValid()){
                maps.push_back(p);
            }
        }
        fclose(fp);
    }
}

ProcMapsData ProcMap::GetModuleData(char *moduleName)
{
    for(int i=0;i<maps.size();i++){
        ProcMapsData p = maps[i];
        if(strstr(p.name, moduleName) != NULL){
            //use ths first on we found
            LOGD("GetModuleData found %s at %08X",moduleName, p.startAddr);
            return p;
        }
    }
    return ProcMapsData();
}

ProcMapsData ProcMap::GetModuleDataByAddr(unsigned int addr)
{
    for(int i=0;i<maps.size();i++){
        ProcMapsData p = maps[i];
        if((p.startAddr <= addr)&&(p.endAddr >= addr))
        {
            LOGD("GetModuleDataByAddr %08X found at %08X %08X ",addr, p.startAddr,p.endAddr);
            return p;
        }
    }
    return ProcMapsData();
}

unsigned int ProcMap::GetModuleBaseAddr(char *moduleName)
{
    ProcMapsData p = GetModuleData(moduleName);
    return(p.startAddr);
}

bool ProcMap::MemoryProtect(ProcMapsData p, int value) {
    if(mprotect((void *)p.startAddr, p.endAddr - p.startAddr,value)!=0){
        LOGD("ProcMap::MemoryProtect Fail at %08X %08X %s",p.startAddr,p.endAddr - p.startAddr,strerror(errno));
        return false;
    }else{
        return true;
    }
}

bool ProcMap::Patch(unsigned int addr, unsigned char *data, int size) {
    PatchData patchData(addr,(unsigned char * )data,size);
    memcpy((void *)addr,data,size);
    if(memcmp((void *)addr,data,size)==0){
        patchs.push_back(patchData);
        return true;
    }else{
        LOGD("ProcMap::Patch fail at %08X",addr);
        return false;
    }
}

bool ProcMap::PatchInt(unsigned int addr, unsigned int value) {
    return Patch(addr,(unsigned char *)&value,sizeof(int));
}





