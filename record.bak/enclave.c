#include "sgx_trts.h"

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "enclave.h"
#include "enclave_t.h"
#include <string.h>
#include <ctype.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <sgx_tcrypto.h>
#include <stdlib.h>
#include "sgx_tprotected_fs.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

// #define MAX_DATA_LEN 50 * 4096

// const sgx_key_128bit_t *key = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
sgx_key_128bit_t arg_128bit_key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

SGX_FILE *ecall_file_open(const char *filename, const char *mode)
{
	SGX_FILE *a;
	// a = sgx_fopen_auto_key(filename, mode);

    // sgx_key_128bit_t key_128bit;
    // if (!sgx_is_outside_enclave(_key_128bit, sizeof(sgx_key_128bit_t)))
    //     return -1;
    // memcpy(&key_128bit, _key_128bit, sizeof(sgx_key_128bit_t));

	a = sgx_fopen(filename, mode, &arg_128bit_key);
	return a;
}

uint64_t ecall_file_get_file_size(SGX_FILE *fp)
{
	uint64_t file_size = 0;
	sgx_fseek(fp, 0, SEEK_END);
	file_size = sgx_ftell(fp);
	return file_size;
}

//write pages
size_t ecall_file_write(SGX_FILE *fp, char *data, uint64_t len)
{
	size_t sizeofWrite;
	// size_t len = strlen(data);
	sizeofWrite = sgx_fwrite(data, sizeof(char), len, fp);
	printf("In enclave: write %d chars at %p...\n", sizeofWrite, fp);
	return sizeofWrite;
}

size_t ecall_file_read(SGX_FILE *fp, char *readData, uint64_t size)
{
	char *data;
	uint64_t startN = 1;
	sgx_fseek(fp, 0, SEEK_END);
	uint64_t finalN = sgx_ftell(fp);
	sgx_fseek(fp, 0, SEEK_SET);
	printf("In enclave: read %d chars...\n", finalN);
	data = (char *)malloc(sizeof(char) * finalN);
	memset(data, 0, sizeof(char) * finalN);
	size_t sizeofRead = sgx_fread(data, startN, finalN, fp);
	int len = strlen(data);

	memcpy(readData, data, len);

	//WL: need to close SGX files here
	sgx_fclose(fp);
	return sizeofRead;
}

void ecall_file_close(SGX_FILE *fp)
{
	printf("In enclave: try to close SGX file\n");
	//WL: something wrong
	// sgx_fclose(fp);
	// printf("debug\n");
}
