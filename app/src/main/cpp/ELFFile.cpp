//
// Created by kwang on 12/28/2017.
//
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

#include <android/log.h>
#define  LOG_TAG    "ELFFile"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

bool ELFFile::Read(char *fileName) {
    return false;
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


