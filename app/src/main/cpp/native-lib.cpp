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
    ProcMap procMap(getpid());
    jobjectArray ret;
    int i;
    ret= (jobjectArray)env->NewObjectArray(procMap.maps.size(),env->FindClass("java/lang/String"),env->NewStringUTF(""));
    char tmp[1024];
    for(i=0;i<procMap.maps.size();i++){
        ProcMapsData p = procMap.maps[i];
        sprintf(tmp,"[%08X %08X %s %s %s]",p.startAddr,p.endAddr,p.mode,p.size,p.name);
        jstring data = env->NewStringUTF(tmp);
        env->SetObjectArrayElement(ret,i,data);
        env->DeleteLocalRef(data);
    }
    return(ret);
}

extern "C"
int mystrncmp(char *src,char *dest,int num)
{
    LOGD("mystrcmp start");
    Utils::DumpHex(src,num);
    Utils::DumpHex(dest,num);
    int ret = strncmp(src,dest,num);
    LOGD("mystrcmp end");
    return ret;
}

extern "C"
JNIEXPORT void JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_test(JNIEnv *env, jobject instance) {
    char *moduleName = "/libfoo.so";
    ProcMap procMap(getpid());
/*    ProcMapsData p = procMap.GetModuleData(moduleName);
    if(!p.isValid()){
        LOGD("Module Not found %s",moduleName);
        return;
    }
    LOGD("moduleBaseAddr=%08X %s",p.startAddr,p.name);
    unsigned int moduleBaseAddr =p.startAddr;

    ELFFile elf(p.name);
    elf.Dump();*/

    ProcMapsData pLibC = procMap.GetModuleData("/libc.so");
    if(!pLibC.isValid()){
        LOGD("Module Not found %s",moduleName);
        return;
    }
    ELFFile elfLibC(pLibC.name);
    elfLibC.Dump();

    std::vector<ELFExportData> exports = elfLibC.GetExports();
    for(int i=0;i<exports.size();i++){
        LOGD("%d %s %08X %08X %08X",i,exports[i].name.c_str(),exports[i].size,exports[i].offset,pLibC.startAddr + exports[i].offset);
    }
    LOGD("strncmp = %08X",(int)strncmp);
    LOGD("getgid = %08X",(int)getgid);

    //procMap.GetGotAddress(moduleName,"");

}extern "C"

JNIEXPORT void JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_patchstrncmp(JNIEnv *env, jobject instance) {
    if(ProcUtil::IsSelinuxEnabled()) {
        LOGD("SelinuxEnabled");
        return;
    }
    ProcMap procMap(getpid());
    ProcMapsData p = procMap.GetModuleData("/libfoo.so");
    if(!p.isValid()){
        LOGD("Module Not found %s","/libfoo.so");
        return;
    }
    LOGD("moduleBaseAddr=%08X %s",p.startAddr,p.name);
    unsigned int moduleBaseAddr = p.startAddr;

    ELFFile elf(p.name);
    Elf32_Shdr *gotPltShdr = elf.GetSectionByName(".got.plt");

    if(!procMap.MemoryProtect(p,PROT_READ| PROT_WRITE | PROT_EXEC)) {
        return;
    }
    unsigned char nop2[2] = {0x90,0x90};
    //Utils::DumpHex((void *)(moduleBaseAddr + 0x98B),5);
    //memcpy((void *)(moduleBaseAddr + 0x976),nop2,sizeof(nop2));
    if(!procMap.Patch(moduleBaseAddr + 0x976,nop2,sizeof(nop2))){
        return;
    }
    //memcpy((void *)(moduleBaseAddr + 0x98B),patch,sizeof(patch));
    Utils::DumpHex((void *)(moduleBaseAddr + 0x98B),5);

    //DumpHex((void *)(moduleBaseAddr + gotPltShdr.sh_addr),gotPltShdr.sh_size);
    for (int i = 0; i < gotPltShdr->sh_size; i += sizeof(long)) {
        unsigned int addr = moduleBaseAddr + gotPltShdr->sh_addr + i;
        unsigned int funcAddr = *(unsigned int *) (addr);
        //LOGD(".got.plt %08X %08X %08X", funcAddr, funcAddr - moduleBaseAddr,gotPltShdr.sh_addr + i);
        if (funcAddr == (unsigned int) strncmp) {
            LOGD("Found strncmp at %08X value %08X", addr, funcAddr);
            ProcMapsData pm = procMap.GetModuleDataByAddr(addr);
            LOGD("moduleBaseAddr=%08X %08X %s",pm.startAddr,pm.endAddr,pm.name);
            if(!procMap.MemoryProtect(pm,PROT_READ| PROT_WRITE )) {
                LOGD("mprotect Fail %s",strerror(errno));
            }else{
                if(!procMap.PatchInt(addr,(unsigned int)mystrncmp)){
                    return;
                }
                LOGD("Done");
                LOGD("Patch strncmp at %08X to %08X",addr,*(unsigned int *) (addr));
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