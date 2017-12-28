//
// Created by kwang on 12/28/2017.
//

#ifndef GOTHOOK_ELFFILE_H
#define GOTHOOK_ELFFILE_H
#include <elf.h>

class ELFFile {
public:
    std::vector<unsigned char> data;
    bool Read(char *fileName);
};

void DumpELFHeader(Elf32_Ehdr* elf_header);
void DumpELFSectionHeader(Elf32_Shdr *section_header);
Elf32_Shdr GetSectionByName(char *fileName,char *sectionName);
void DumpELF(char *fileName);


#endif //GOTHOOK_ELFFILE_H
