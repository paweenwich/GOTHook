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
/*
extern "C"
{
#include "elf_utils.h"
#include "utils.h"
}*/

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
    std::string hello = "Hello from C++ Na Ja2";
    return env->NewStringUTF(hello.c_str());
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
int mystrncmp(char *src,char *dest,int num)
{
    LOGD("mystrcmp start");
    DumpHex(src,num);
    DumpHex(dest,num);
    int ret = strncmp(src,dest,num);
    LOGD("mystrcmp end");
    return ret;
}

extern "C"
JNIEXPORT void JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_test(JNIEnv *env, jobject instance) {

    ProcMapsData p = GetModuleData(0,"/libfoo.so");
    LOGD("moduleBaseAddr=%08X %s",p.startddr,p.name);
    unsigned int moduleBaseAddr =p.startddr;
    //DumpELF(p.name);
    Elf32_Shdr gotShdr = GetSectionByName(p.name,".dynsym");
    DumpHex((void *)(moduleBaseAddr + gotShdr.sh_addr),gotShdr.sh_size);
    for (int i = 0; i < gotShdr.sh_size; i += sizeof(Elf32_Sym)) {
        Elf32_Sym *sym = (Elf32_Sym *)(moduleBaseAddr + gotShdr.sh_addr + i);
        LOGD("name=%d size=%08X value=%08X",sym->st_name,sym->st_size,sym->st_value);
    }
    //Elf32_Sym
    //.dynsym

/*    DumpELF("/system/lib/libc.so");
    unsigned int moduleBaseAddr = GetModuleBaseAddr(0,"/system/lib/libc.so");
    LOGD("moduleBaseAddr=%08X",moduleBaseAddr);
    Elf32_Shdr gotShdr = GetSectionByName("/system/lib/libc.so",".got");
    DumpHex((void *)(moduleBaseAddr + gotShdr.sh_addr),gotShdr.sh_size);
    for (int i = 0; i < gotShdr.sh_size; i += sizeof(long)) {
        unsigned int funcAddr = *(unsigned int *) (moduleBaseAddr + gotShdr.sh_addr + i);
        LOGD(".got %08X %08X %08X", funcAddr, funcAddr - moduleBaseAddr,gotShdr.sh_addr + i);
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

    Elf32_Shdr gotPltShdr = GetSectionByName("/system/lib/libc.so",".got.plt");
    DumpHex((void *)(moduleBaseAddr + gotPltShdr.sh_addr),gotPltShdr.sh_size);
    for (int i = 0; i < gotPltShdr.sh_size; i += sizeof(long)) {
        unsigned int funcAddr = *(unsigned int *) (moduleBaseAddr + gotPltShdr.sh_addr + i);
        //LOGD(".got.plt %08X %08X %08X", funcAddr, funcAddr - moduleBaseAddr,gotPltShdr.sh_addr + i);
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
*/
    ///data/app/me.noip.muminoi.myappnative-1/lib/x86/libfoo.so
}extern "C"

JNIEXPORT void JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_patchstrncmp(JNIEnv *env, jobject instance) {
    if(IsSelinuxEnabled()) {
        LOGD("SelinuxEnabled");
        return;
    }
    LOGD("%p",env);
    LOGD("GetByteArrayElements %p",&JNIEnv::GetByteArrayElements);
    LOGD("ReleaseByteArrayElements %p",&JNIEnv::ReleaseByteArrayElements);
    ProcMapsData p = GetModuleData(0,"/libfoo.so");
    LOGD("moduleBaseAddr=%08X %s",p.startddr,p.name);
    Elf32_Shdr gotPltShdr = GetSectionByName(p.name,".got.plt");


    unsigned int moduleBaseAddr = p.startddr;
    if(mprotect((void *)p.startddr, p.endAddr - p.startddr,PROT_READ| PROT_WRITE | PROT_EXEC)!=0) {
        LOGD("mprotect code Fail %s",strerror(errno));
        return;
    }
    unsigned char nop2[2] = {0x90,0x90};
    unsigned char patch[5] = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
    DumpHex((void *)(moduleBaseAddr + 0x98B),5);
    memcpy((void *)(moduleBaseAddr + 0x976),nop2,sizeof(nop2));
    //memcpy((void *)(moduleBaseAddr + 0x98B),patch,sizeof(patch));
    DumpHex((void *)(moduleBaseAddr + 0x98B),5);

    //DumpHex((void *)(moduleBaseAddr + gotPltShdr.sh_addr),gotPltShdr.sh_size);
    for (int i = 0; i < gotPltShdr.sh_size; i += sizeof(long)) {
        unsigned int addr = moduleBaseAddr + gotPltShdr.sh_addr + i;
        unsigned int funcAddr = *(unsigned int *) (addr);
        //LOGD(".got.plt %08X %08X %08X", funcAddr, funcAddr - moduleBaseAddr,gotPltShdr.sh_addr + i);
        if (funcAddr == (unsigned int) strncmp) {
            LOGD("strncmp %08X at %08X", funcAddr,addr);
            ProcMapsData pm = GetModuleDataByAddr(0,addr);
            LOGD("moduleBaseAddr=%08X %08X %s",pm.startddr,pm.endAddr,pm.name);
            if(mprotect((void *)pm.startddr, pm.endAddr - pm.startddr,PROT_READ| PROT_WRITE)!=0) {
                LOGD("mprotect Fail %s",strerror(errno));
            }else{
                *(unsigned int *) (addr) = (unsigned int)mystrncmp; //funcAddr;
                LOGD("Done");
                LOGD("strncmp %08X at %08X",*(unsigned int *) (addr),addr);
            }
            break;
        }
    }

}extern "C"
JNIEXPORT void JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_testParam(JNIEnv *env, jobject instance,
                                                        jbyteArray a_) {
    jbyte *a = env->GetByteArrayElements(a_, NULL);

    // TODO

    env->ReleaseByteArrayElements(a_, a, 0);
}