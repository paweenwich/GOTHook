#include <jni.h>
#include <string>

extern "C"
JNIEXPORT jstring

JNICALL
Java_me_noip_muminoi_myappnative_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++ Na Ja";
    return env->NewStringUTF(hello.c_str());
}
