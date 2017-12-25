#include <jni.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <android/log.h>
extern "C"
{
#include "elf_utils.h"
}

#define  LOG_TAG    "native-lib"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
extern "C"
JNIEXPORT jstring

JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++ Na Ja";
    return env->NewStringUTF(hello.c_str());
}


extern "C"
JNIEXPORT jstring JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_stringFromJNI2(JNIEnv *env, jobject instance) {
    // TODO
    std::string hello = "Hello from C++ Na Ja2";
    return env->NewStringUTF(hello.c_str());
}

char* replace_char(char* str, char find, char replace){
    char *current_pos = strchr(str,find);
    while (current_pos){
        *current_pos = replace;
        current_pos = strchr(current_pos,find);
    }
    return str;
}

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

unsigned int GetModuleBaseAddr(int pid,char *moduleName)
{
    std::vector<ProcMapsData> maps =  GetMaps(pid);
    for(int i=0;i<maps.size();i++){
        ProcMapsData p = maps[i];
        if(strstr(p.name, moduleName) != NULL){
            //use ths first on we found
            LOGD("GetModuleBaseAddr found %s at %08X",moduleName, p.startddr);
            return p.startddr;
        }
    }
    return 0;
}

void DumpELF(char *fileName)
{
    FILE* elf_file = OpenElfFile(fileName);
    Elf32_Shdr* got_section_header = (Elf32_Shdr*) malloc(sizeof(Elf32_Shdr));
    GetSectionHeaderByName(got_section_header, elf_file, ".got");
/*    size_t got_section_size = got_section_header->sh_size;
    off_t got_addr_offset = got_section_header->sh_addr;
    free(got_section_header);
    LOGD("got section size: %u, got addr offset: %lx\n", got_section_size, got_addr_offset);

    long module_base_addr = GetModuleBaseAddr(0, fileName);
    long got_section_address = module_base_addr + got_addr_offset;
    LOGD("module base addr: %lx, got section address: %lx\n", module_base_addr, got_section_address);

    for (int i = 0; i < got_section_size; i += sizeof(long)) {
        //long got_entry = ptrace(PTRACE_PEEKDATA, pid, (void *)(got_section_address + i), NULL);
        //if (got_entry == original_function_addr) {
        //    PtraceWrite(pid, (uint8_t*)(got_section_address + i), (uint8_t*)&target_function_addr, sizeof(long));
        //   LOGD("hooked got entry %d: %lx with %lx\n", i / sizeof(long), got_entry, target_function_addr);
        //}
    }
*/
}



extern "C"
JNIEXPORT jobject JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_getModules(JNIEnv *env, jobject instance) {

    jobjectArray ret;
    int i;
    std::vector<ProcMapsData> maps =  GetMaps(0);
    ret= (jobjectArray)env->NewObjectArray(maps.size(),env->FindClass("java/lang/String"),env->NewStringUTF(""));
    char tmp[1024];
    for(i=0;i<maps.size();i++){
        ProcMapsData p = maps[i];
        sprintf(tmp,"[%08X %08X %s %s %s]",p.startddr,p.endAddr,p.mode,p.size,p.name);
        jstring data = env->NewStringUTF(tmp);
        env->SetObjectArrayElement(ret,i,data);
        env->DeleteLocalRef(data);
    }

    //GetModuleBaseAddr(0,"libc.so");
    return(ret);
}

extern "C"
JNIEXPORT void JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_test(JNIEnv *env, jobject instance) {

    // TODO
    DumpELF("/system/lib/libc.so");
}