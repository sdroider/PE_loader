#pragma once
#include <sys/types.h>
#include <stdint.h>
#include <windows.h>

uint8_t check_format(WORD dos_sign, DWORD nt_sign);
void write_sections(char *ImageBase, char *ptr_data, PIMAGE_SECTION_HEADER sections, WORD nsections);
void write_imports(char *ImageBase, PIMAGE_IMPORT_DESCRIPTOR import_descriptor);
void write_relocations(char *ImageBase, PIMAGE_BASE_RELOCATION base_reloc, DWORD delta);
void write_protections(char *ImageBase, PIMAGE_SECTION_HEADER sections, WORD nsections, DWORD size_of_headers);
void *load_PE(char *ptr_data);
