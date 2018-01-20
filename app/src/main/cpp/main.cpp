#include "Utils.h"
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "Utils.h"
#include "ProcUtil.h"

#include <android/log.h>
#include <cctype>
#include <sys/mman.h>

#define  LOG_TAG    "main"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

int main(int argc, char const *argv[]) {
    printf("Hello World Haha\n");
    int pid = ProcUtil::GetPid("com.netmarble.revolutionthm");
    printf("pid=%d\n",pid);
    if(pid >0){
        ProcMem pMem(pid);
        if(pMem.f!=NULL){
            printf("Success\n");
        }
    }

}
