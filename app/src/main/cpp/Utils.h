//
// Created by kwang on 12/28/2017.
//

#ifndef GOTHOOK_UTILS_H
#define GOTHOOK_UTILS_H

#include <vector>
#include <stdbool.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <string>

class Utils {
public:
    static std::vector<unsigned char> ReadFile(const char *fileName);
    static bool WriteFile(char *fileName,std::vector<unsigned char>& data);
    static bool WriteAllBytes(char *fileName,unsigned char *data,int size);
    static void DumpHex(void * src,int len);
    static char* replace_char(char* str, char find, char replace);
    static std::string ConcatStrings(std::vector<std::string> &lst,std::string seperator);
    static bool StringReplace(std::string& str, const std::string& from, const std::string& to);
    static std::string SaveCString(char *data);
    static int MemoryFind(unsigned char *data,int data_size, unsigned char* pattern,int pattern_size);
    static unsigned int AllocateExecutableMemory(unsigned int size);
};

#endif //GOTHOOK_UTILS_H
