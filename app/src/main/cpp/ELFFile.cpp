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

ELFFile::ELFFile(char *fileName) {
    fileBuffer = Utils::ReadFile(fileName);
    this->dataPtr = &fileBuffer[0];

    //Get sectStringTablePtr
    headerPtr = (Elf32_Ehdr*)dataPtr;
    off_t shstrtab_header_offset = headerPtr->e_shoff + headerPtr->e_shstrndx * sizeof(Elf32_Shdr);
    Elf32_Shdr *shstrtab_header = (Elf32_Shdr *)&dataPtr[shstrtab_header_offset];
    sectStringTablePtr = (char *)&dataPtr[shstrtab_header->sh_offset];

    //Get dynStringTablePtr
    Elf32_Shdr *dynStr_header = GetSectionByName(".dynstr");
    dynStringTablePtr = (char *)&dataPtr[dynStr_header->sh_offset];
}



void ELFFile::DumpELFHeader(Elf32_Ehdr* elf_header)
{
    LOGD("ELF Header");
    LOGD("e_entry=%08X e_phoff=%08X e_shstrndx=%d",elf_header->e_entry,elf_header->e_phoff,elf_header->e_shstrndx);
    LOGD("e_shoff=%08X e_shnum=%d e_shentsize=%d",elf_header->e_shoff,elf_header->e_shnum,elf_header->e_shentsize);
}

void ELFFile::DumpELFSectionHeader(Elf32_Shdr *section_header)
{
    LOGD("sh_name=%d sh_type=%08X sh_addr=%08X sh_offset=%08X sh_size=%08X",
         section_header->sh_name,section_header->sh_type,section_header->sh_addr,section_header->sh_offset,
         section_header->sh_size
    );
}

void ELFFile::Dump()
{
    unsigned int moduleBaseAddr = (unsigned int)dataPtr;
    Elf32_Ehdr* elf_header = (Elf32_Ehdr*)dataPtr;
    DumpELFHeader(elf_header);

    LOGD("Section table");
    size_t section_count = elf_header->e_shnum;
    off_t base_section_header_offset = elf_header->e_shoff;
    Elf32_Shdr *section_header;
    for(int i = 0; i < section_count; ++i) {
        section_header = (Elf32_Shdr *)&dataPtr[elf_header->e_shoff + (i*sizeof(Elf32_Shdr))];
        //DumpHex(section_header,sizeof(Elf32_Shdr));
        LOGD("%s",GetSectString(section_header->sh_name));
        DumpELFSectionHeader(section_header);
    }

    LOGD("Dynamic Symbol section (.dynsym)");
    Elf32_Shdr *gotShdr = GetSectionByName(".dynsym");
    if(gotShdr!=NULL) {
        Utils::DumpHex((void *) (moduleBaseAddr + gotShdr->sh_addr), gotShdr->sh_size);
        for (int i = 0; i < gotShdr->sh_size; i += sizeof(Elf32_Sym)) {
            Elf32_Sym *sym = (Elf32_Sym *) (moduleBaseAddr + gotShdr->sh_addr + i);
            LOGD("name=%d size=%08X value=%08X Type=%02X Binding=%02X %s",
                 sym->st_name, sym->st_size, sym->st_value, sym->st_info & 0x0f, sym->st_info>>4, GetDynString(sym->st_name));
        }
    }

    LOGD("GOT section (.got.plt)");
    Elf32_Shdr *gotPltShdr = GetSectionByName(".got.plt");
    if(gotPltShdr!=NULL) {
        for (int i = 0; i < gotPltShdr->sh_size; i += sizeof(long)) {
            unsigned int addr = moduleBaseAddr + gotPltShdr->sh_addr + i;
            unsigned int funcAddr = *(unsigned int *) (addr);
            LOGD("addr=%08X funcAddr=%08X %08X %08X",addr, funcAddr, funcAddr - moduleBaseAddr,
                 gotPltShdr->sh_addr + i);
        }
    }
}

Elf32_Shdr* ELFFile::GetSectionByName(char *sectionName)
{
    Elf32_Ehdr* elf_header = (Elf32_Ehdr*)dataPtr;
    off_t shstrtab_header_offset = elf_header->e_shoff + elf_header->e_shstrndx * sizeof(Elf32_Shdr);
    Elf32_Shdr *shstrtab_header = (Elf32_Shdr *)&dataPtr[shstrtab_header_offset];
    unsigned char *shstrtab_ptr = (unsigned char *)&dataPtr[shstrtab_header->sh_offset];
    size_t section_count = elf_header->e_shnum;
    off_t base_section_header_offset = elf_header->e_shoff;
    Elf32_Shdr *section_header;
    for(int i = 0; i < section_count; ++i) {
        section_header = (Elf32_Shdr *)&dataPtr[elf_header->e_shoff + (i*sizeof(Elf32_Shdr))];
        char *section_name = (char *)(&shstrtab_ptr[section_header->sh_name]);
        if(strcmp(section_name,sectionName)==0){
            return section_header;
            break;
        }
    }
    return NULL;
}

char *ELFFile::GetDynString(int index) {
    return &dynStringTablePtr[index];
}

char *ELFFile::GetSectString(int index) {
    return &sectStringTablePtr[index];
}

std::vector<ELFExportData> ELFFile::GetExports() {
    std::vector<ELFExportData> ret;
    unsigned int moduleBaseAddr = (unsigned int)dataPtr;
    Elf32_Shdr *gotShdr = GetSectionByName(".dynsym");
    if(gotShdr!=NULL) {
        for (int i = 0; i < gotShdr->sh_size; i += sizeof(Elf32_Sym)) {
            Elf32_Sym *sym = (Elf32_Sym *) (moduleBaseAddr + gotShdr->sh_addr + i);
            int type = sym->st_info & 0x0f;
            if((sym->st_value != 0) && (type == 2)) {   // type 2 = function
                char *symName = GetDynString(sym->st_name);
                ELFExportData d;
                d.name = symName;
                d.size = sym->st_size;
                d.offset = sym->st_value;
                ret.push_back(d);
            }
        }
    }
    return ret;
}


