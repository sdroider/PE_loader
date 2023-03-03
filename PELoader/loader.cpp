#include "stdafx.h"
#include "loader.h"

uint8_t check_format(WORD dos_signature, DWORD nt_signature)
{
	if (dos_signature != IMAGE_DOS_SIGNATURE)
		return 1;

	if (nt_signature != IMAGE_NT_SIGNATURE)
		return 1;

	return 0;
}

void *memory_copy(void *dst, const void *src, size_t size)
{
	char *ptr_dst = (char *)dst;
	char *ptr_src = (char *)src;

	while (size--)
		*ptr_dst++ = *ptr_src++;

	return dst;
}

void *memory_set(void *dst, char c, size_t size)
{
	char *ptr_dst = (char *)dst;

	while (size--)
		*ptr_dst = c;

	return dst;
}

void write_sections(char *ImageBase, char *ptr_data, PIMAGE_SECTION_HEADER sections, WORD nsections)
{
	char *addr = NULL;
	for (uint8_t i = 0; i < nsections; i++) {
		addr = (ImageBase + sections[i].VirtualAddress);
		if (sections[i].SizeOfRawData)
			memory_copy(addr, ptr_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
		else
			memory_set(addr, 0, sections[i].Misc.VirtualSize);
	}
}

void write_imports(char *ImageBase, PIMAGE_IMPORT_DESCRIPTOR import_descriptor)
{
	HMODULE lib = NULL;
	IMAGE_THUNK_DATA *HINT_TABLE = NULL, *IAT_TABLE = NULL;
	PIMAGE_IMPORT_BY_NAME by_name = NULL;
	DWORD function_addr = 0, i = 0;

	for (i = 0; import_descriptor[i].OriginalFirstThunk; i++) {

		lib = LoadLibraryA((ImageBase + import_descriptor[i].Name));

		HINT_TABLE = (PIMAGE_THUNK_DATA)(ImageBase + import_descriptor[i].OriginalFirstThunk);
		IAT_TABLE = (PIMAGE_THUNK_DATA)(ImageBase + import_descriptor[i].FirstThunk);

		for (; HINT_TABLE[0].u1.AddressOfData; HINT_TABLE++, IAT_TABLE++) {

			function_addr = HINT_TABLE[0].u1.AddressOfData;

			by_name = (PIMAGE_IMPORT_BY_NAME)(ImageBase + function_addr);

			IAT_TABLE[0].u1.Function = (function_addr & IMAGE_ORDINAL_FLAG) ? (DWORD)GetProcAddress(lib, (LPSTR)function_addr) : (DWORD)GetProcAddress(lib, (LPSTR)&by_name->Name);
		}
	}
}

void write_relocations(char *ImageBase, PIMAGE_BASE_RELOCATION base_reloc, DWORD delta)
{
	DWORD size_blocks = 0, *patch_addr = NULL, i = 0;

	while (base_reloc->VirtualAddress) {

		size_blocks = ((base_reloc->SizeOfBlock) - sizeof(IMAGE_BASE_RELOCATION)) / 2;

		WORD *reloc = (WORD *)(base_reloc + 1);

		for (i = 0; i < size_blocks; i++) {
			patch_addr = (PDWORD)(ImageBase + base_reloc->VirtualAddress + (reloc[i] & 0xfff));

			if ((reloc[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
				*patch_addr += delta;
		}

		base_reloc = (PIMAGE_BASE_RELOCATION)(((DWORD)base_reloc) + base_reloc->SizeOfBlock);
	}
}

void write_protections(char *ImageBase, PIMAGE_SECTION_HEADER sections, WORD nsections, DWORD size_of_headers)
{
	DWORD i = 0, old_prot = 0, new_prot = 0;
	char *addr = NULL;

	VirtualProtect(ImageBase, size_of_headers, PAGE_READONLY, &old_prot);

	for (i = 0; i < nsections; i++) {

		addr = (ImageBase + sections[i].VirtualAddress);

		if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			new_prot = ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ);
		else
			new_prot = ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY);
		VirtualProtect(addr, sections[i].Misc.VirtualSize, new_prot, &old_prot);
	}
}

void *load_PE(char *ptr_data)
{
	PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)ptr_data;
	PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(((char *)dos_hdr) + dos_hdr->e_lfanew);
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(nt_hdr + 1);
	PIMAGE_DATA_DIRECTORY data_dir = (PIMAGE_DATA_DIRECTORY)(nt_hdr->OptionalHeader.DataDirectory);
	char *image_base = NULL;
	DWORD delta = 0;

	if (check_format(dos_hdr->e_magic, nt_hdr->Signature))
		return (NULL);

	image_base = (char *)VirtualAlloc(NULL, nt_hdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	memory_copy(image_base, ptr_data, nt_hdr->OptionalHeader.SizeOfHeaders);

	write_sections(image_base, ptr_data, sections, nt_hdr->FileHeader.NumberOfSections);

	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(image_base + data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	write_imports(image_base, import_descriptor);

	delta = ((DWORD)image_base) - nt_hdr->OptionalHeader.ImageBase;

	if (data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress && delta) {

		PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION)(image_base + data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		write_relocations(image_base, base_reloc, delta);
	}

	write_protections(image_base, sections, nt_hdr->FileHeader.NumberOfSections, nt_hdr->OptionalHeader.SizeOfHeaders);

	return ((void *)(image_base + nt_hdr->OptionalHeader.AddressOfEntryPoint));
}