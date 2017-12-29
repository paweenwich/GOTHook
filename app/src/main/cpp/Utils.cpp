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
#include <sys/mman.h>

#define  LOG_TAG    "Utils"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


char* Utils::replace_char(char* str, char find, char replace)
{
    char *current_pos = strchr(str,find);
    while (current_pos){
        *current_pos = replace;
        current_pos = strchr(current_pos,find);
    }
    return str;
}

std::vector<unsigned char> Utils::ReadFile(const char *fileName)
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



void Utils::DumpHex(void * src,int len)
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

std::string Utils::ConcatStrings(std::vector<std::string> &lst,std::string seperator)
{
    std::string ret;
    for(int i=0;i<lst.size();i++){
        if(i!=0){
            ret += seperator;
        }
        ret+= lst[i];
    }
    return ret;
}

bool Utils::StringReplace(std::string& str, const std::string& from, const std::string& to)
{
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

std::string Utils::SaveCString(char *data)
{
    std::string ret(data);
    StringReplace(ret,"\"","\\\"");
    return ret;
}

bool Utils::WriteAllBytes(char *fileName,unsigned char *data,int size)
{
    FILE *f = fopen(fileName,"wb");
    if(f!=NULL){
        fwrite(data,size,1,f);
        fflush(f);
        fclose(f);
        return true;
    }
    return false;
}

bool Utils::WriteFile(char *fileName, std::vector<unsigned char> &data) {
    return WriteAllBytes(fileName,&data[0],data.size());
}

int Utils::MemoryFind(unsigned char *data,int data_size, unsigned char* pattern,int pattern_size)
{
    for(int i=0;i<data_size - pattern_size;i++){
        if(memcmp(&data[i],&pattern[0],pattern_size)==0){
            return i;
        }
    }
    return -1;
}

unsigned int Utils::AllocateExecutableMemory(unsigned int size)
{
    void * virtualCodeAddress = 0;
    virtualCodeAddress = mmap(
            NULL,
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE,
            0,
            0);
    //LOGD("AllocateExecutableMemory: virtualCodeAddress = %p\n", virtualCodeAddress);
    // write some code in
    return (unsigned int)virtualCodeAddress;
}





