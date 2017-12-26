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


void DumpELFHeader(Elf32_Ehdr* elf_header)
{
    LOGD("e_entry=%08X e_phoff=%08X e_shstrndx=%d",elf_header->e_entry,elf_header->e_phoff,elf_header->e_shstrndx);
    LOGD("e_shoff=%08X e_shnum=%d e_shentsize=%d",elf_header->e_shoff,elf_header->e_shnum,elf_header->e_shentsize);
}

void DumpELFSectionHeader(Elf32_Shdr *section_header)
{
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
    LOGD("sh_name=%d sh_type=%08X sh_addr=%08X sh_offset=%08X sh_size=%08X",
         section_header->sh_name,section_header->sh_type,section_header->sh_addr,section_header->sh_offset,
         section_header->sh_size
    );
}

Elf32_Shdr GetSectionByName(char *fileName,char *sectionName)
{
    Elf32_Shdr ret;
    memset(&ret,0,sizeof(Elf32_Shdr));
    std::vector<unsigned char> elfData =  ReadFile(fileName);
    Elf32_Ehdr* elf_header = (Elf32_Ehdr*)&elfData[0];
    off_t shstrtab_header_offset = elf_header->e_shoff + elf_header->e_shstrndx * sizeof(Elf32_Shdr);
    Elf32_Shdr *shstrtab_header = (Elf32_Shdr *)&elfData[shstrtab_header_offset];
    unsigned char *shstrtab_ptr = (unsigned char *)&elfData[shstrtab_header->sh_offset];
    size_t section_count = elf_header->e_shnum;
    off_t base_section_header_offset = elf_header->e_shoff;
    Elf32_Shdr *section_header;
    for(int i = 0; i < section_count; ++i) {
        section_header = (Elf32_Shdr *)&elfData[elf_header->e_shoff + (i*sizeof(Elf32_Shdr))];
        char *section_name = (char *)(&shstrtab_ptr[section_header->sh_name]);
        if(strcmp(section_name,sectionName)==0){
            ret = *section_header;
            break;
        }
    }
    return ret;
}

void DumpELF(char *fileName)
{
    //FILE* elf_file = OpenElfFile(fileName);
    std::vector<unsigned char> elfData =  ReadFile(fileName);
    Elf32_Ehdr* elf_header = (Elf32_Ehdr*)&elfData[0];
    //DumpHex(elf_header,sizeof(Elf32_Ehdr));
    DumpELFHeader(elf_header);
    //Find String Table
    LOGD("String table");
    off_t shstrtab_header_offset = elf_header->e_shoff + elf_header->e_shstrndx * sizeof(Elf32_Shdr);
    Elf32_Shdr *shstrtab_header = (Elf32_Shdr *)&elfData[shstrtab_header_offset];
    //DumpHex(shstrtab_header,sizeof(Elf32_Shdr));
    DumpELFSectionHeader(shstrtab_header);
    unsigned char *shstrtab_ptr = (unsigned char *)&elfData[shstrtab_header->sh_offset];
    //DumpHex(shstrtab_ptr,shstrtab_header->sh_size);

    LOGD("Section table");
    size_t section_count = elf_header->e_shnum;
    off_t base_section_header_offset = elf_header->e_shoff;
    Elf32_Shdr *section_header;

    for(int i = 0; i < section_count; ++i) {
        //fseek(elf_file, base_section_header_offset, SEEK_SET);
        //fread(section_header, sizeof(Elf32_Shdr), 1, elf_file);
        section_header = (Elf32_Shdr *)&elfData[elf_header->e_shoff + (i*sizeof(Elf32_Shdr))];
        char *section_name = (char *)(&shstrtab_ptr[section_header->sh_name]);
        //DumpHex(section_header,sizeof(Elf32_Shdr));
        LOGD("%s",section_name);
        DumpELFSectionHeader(section_header);
    }
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

    printf("This is printf");
    // TODO
    DumpELF("/system/lib/libc.so");
    unsigned int moduleBaseAddr = GetModuleBaseAddr(0,"/system/lib/libc.so");
    LOGD("moduleBaseAddr=%08X",moduleBaseAddr);
    Elf32_Shdr gotShdr = GetSectionByName("/system/lib/libc.so",".got");
    DumpHex((void *)(moduleBaseAddr + gotShdr.sh_addr),gotShdr.sh_size);
    for (int i = 0; i < gotShdr.sh_size; i += sizeof(long)) {
        unsigned int funcAddr = *(unsigned int *) (moduleBaseAddr + gotShdr.sh_addr + i);
        LOGD("%08X %08X %08X", funcAddr, funcAddr - moduleBaseAddr,gotShdr.sh_addr + i);
        if (funcAddr == (unsigned int) printf) {
            LOGD("printf %08X", funcAddr);
        }
        if (funcAddr == (unsigned int) strncmp) {
            LOGD("strncmp %08X", funcAddr);
        }
        if (funcAddr == (unsigned int) strcmp) {
            LOGD("strcmp %08X", funcAddr);
        }
    }
    LOGD("strcmp %08X %08X",(int)strcmp,(unsigned int)strcmp - moduleBaseAddr);
    LOGD("strcpy %08X %08X",(int)strcpy,(unsigned int)strcpy - moduleBaseAddr);
    LOGD("printf %08X %08X",(int)printf,(unsigned int)printf - moduleBaseAddr);
}