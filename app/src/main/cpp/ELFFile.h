//
// Created by kwang on 12/28/2017.
//

#ifndef GOTHOOK_ELFFILE_H
#define GOTHOOK_ELFFILE_H
#include <elf.h>

class ELFFile {
protected:
    unsigned char *dataPtr;
public:
    Elf32_Ehdr* headerPtr;
    char *sectStringTablePtr;
    char *dynStringTablePtr;
    std::vector<unsigned char> fileBuffer;

    ELFFile(char *fileName);
    void Dump();
    Elf32_Shdr *GetSectionByName(char *sectionName);
    char *GetSectString(int index);
    char *GetDynString(int index);
    static void DumpELFHeader(Elf32_Ehdr* elf_header);
    static void DumpELFSectionHeader(Elf32_Shdr *section_header);
};

#endif //GOTHOOK_ELFFILE_H
