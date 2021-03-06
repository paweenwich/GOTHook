//
// Created by kwang on 12/29/2017.
//

#ifndef GOTHOOK_PROCUTIL_H
#define GOTHOOK_PROCUTIL_H

class ProcMapsData {
protected:
    void Init();
public:
    char range[32];
    char mode[32];
    char size[32];
    char unk1[32];
    char unk2[32];
    char name[1024];
    unsigned int startAddr;
    unsigned int endAddr;
    ProcMapsData();
    ProcMapsData(char *line);
    bool isValid();

};

class ProcUtil {
public:
    static bool IsSelinuxEnabled();
    static void DisableSelinux();
    static long GetPid(const char* process_name);
};

class PatchData{
public:
    unsigned int addr;
    std::vector<unsigned char>data;
    PatchData(unsigned int addr,unsigned char *data,int size){
        this->addr = addr;
        for(int i=0;i<size;i++){
            this->data.push_back(data[i]);
        }
    }
};

class ProcMap {
public:
    int pid;
    std::vector<ProcMapsData> maps;
    std::vector<PatchData> patchs;
    ProcMap(int pid,bool all=false);
    void GetMaps(int pid,bool all);
    ProcMapsData GetModuleDataByAddr(unsigned int addr);
    ProcMapsData GetModuleData(char *moduleName);
    unsigned int GetModuleBaseAddr(char *moduleName);
    unsigned int GetGotAddress(char *moduleName,char *funcName);
    bool MemoryProtect(ProcMapsData p,int value);
    bool Patch(unsigned int addr,unsigned char *data,int size);
    bool PatchInt(unsigned int addr,unsigned int);
};

class SimpleBuffer: public std::vector<unsigned char> {
public:
    SimpleBuffer(int size=0);
    int Size();
    void Append(void *ptr,int size);
};

class ProcMem {
public:
    int pid;
    FILE *f;
    ProcMem(int pid);
    SimpleBuffer Read(unsigned int addr,int size);
    bool Write(unsigned int addr,void *ptr,int size);
};




#endif //GOTHOOK_PROCUTIL_H
