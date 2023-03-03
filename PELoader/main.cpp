

#include "stdafx.h"
#include "loader.h"
#include <stdio.h>


int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Error input PE file. Need argument! \n");
		return 1;
	}

	FILE *file;
	fopen_s(&file, argv[1], "rb");
	if (!file) {
		fprintf(stderr, "Error read PE file \n");
		return 1;
	}
	fseek(file, 0L, SEEK_END);
	int file_len = ftell(file);
	fseek(file, 0L, SEEK_SET);
	char* file_data = (char *)malloc((sizeof(char) * file_len) + 1);
	fread(file_data, sizeof(char), file_len, file);

	void *entry_point = load_PE(file_data);
	if (entry_point)
		((void(*)(void)) entry_point)();
	return 0;

}

