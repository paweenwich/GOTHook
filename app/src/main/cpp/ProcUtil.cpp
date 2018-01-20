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
#include "ELFFile.h"
#include "ProcUtil.h"

#include <android/log.h>
#include <dirent.h>

#define  LOG_TAG    "ProcUtil"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

ProcMapsData::ProcMapsData() {
    name[0] = 0;
    range[0] = 0;
    size[0]=0;
    unk1[0]=0;
    unk2[0]=0;
    startAddr = 0;
    endAddr = 0;
}

ProcMapsData::ProcMapsData(char *line){
    name[0] = 0;
    range[0] = 0;
    size[0]=0;
    unk1[0]=0;
    unk2[0]=0;
    startAddr = 0;
    endAddr = 0;
    if(sscanf(line,"%s %s %s %s %s %s",range,mode,size,unk1,unk2,name)>=5){
        Init();
    }
}

bool ProcMapsData::isValid(){
    return(endAddr != 0);
}


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
        int pid = atoi(entry->d_name);
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


ProcMap::ProcMap(int pid,bool all) {
    this->pid = pid;
    //printf("%d\n",all);
    GetMaps(pid,all);
}

void ProcMap::GetMaps(int pid,bool all)
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
            if(all){
                //printf("%s\n",line);
                maps.push_back(p);
            }else {
                if (p.isValid()) {
                    maps.push_back(p);
                }
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


unsigned int ProcMap::GetGotAddress(char *moduleName, char *funcName) {
    ProcMapsData p = GetModuleData(moduleName);
    if(!p.isValid()){
        LOGD("Module Not found %s",moduleName);
        return 0;
    }
    LOGD("moduleBaseAddr=%08X %s",p.startAddr,p.name);
    unsigned int moduleBaseAddr = p.startAddr;

    ELFFile elf(p.name);
    Elf32_Shdr *gotPltShdr = elf.GetSectionByName(".got.plt");
    for (int i = 0; i < gotPltShdr->sh_size; i += sizeof(long)) {
        unsigned int addr = moduleBaseAddr + gotPltShdr->sh_addr + i;
        unsigned int funcAddr = *(unsigned int *) (addr);
        LOGD(".got.plt %08X %08X %08X", funcAddr, funcAddr - moduleBaseAddr,gotPltShdr->sh_addr + i);
    }
    return 0;
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


SimpleBuffer::SimpleBuffer(int size): std::vector<unsigned char>(size,0) {

}

int SimpleBuffer::Size() {
    return this->size();
}

void SimpleBuffer::Append(void *ptr, int size) {
    this->insert(this->end(),(unsigned char *)ptr,(unsigned char *)((unsigned char *)ptr+size));
}

ProcMem::ProcMem(int pid) {
    char file_name[64];
    sprintf(file_name, "/proc/%d/mem", pid);

    this->pid = pid;
    this->f = fopen(file_name, "r+b");
    if(this->f==NULL) {
        LOGD("ProcMem fopen fail %s",file_name);
    }
}

SimpleBuffer ProcMem::Read(unsigned int addr, int size) {
    SimpleBuffer ret(size);
    if(this->f!=NULL){
        fseek(this->f,addr,SEEK_SET);
        fread(&ret[0],size,1,this->f);
    }
    return ret;
}

bool ProcMem::Write(unsigned int addr, void *ptr, int size) {
    if(this->f!=NULL){
        fseek(this->f,addr,SEEK_SET);
        fwrite(ptr,size,1,this->f);
    }
    return true;
}
