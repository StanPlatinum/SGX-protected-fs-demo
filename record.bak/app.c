#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>

#include <time.h>

#define MAX_PATH FILENAME_MAX

#include "sgx_tprotected_fs.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "app.h"
#include "enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t eid = 0;

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,
     "Unexpected error occurred.",
     NULL},
    {SGX_ERROR_INVALID_PARAMETER,
     "Invalid parameter.",
     NULL},
    {SGX_ERROR_OUT_OF_MEMORY,
     "Out of memory.",
     NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE,
     "Invalid enclave image.",
     NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID,
     "Invalid enclave identification.",
     NULL},
    {SGX_ERROR_INVALID_SIGNATURE,
     "Invalid enclave signature.",
     NULL},
    {SGX_ERROR_OUT_OF_EPC,
     "Out of EPC memory.",
     NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,
     "Memory map conflicted.",
     NULL},
    {SGX_ERROR_INVALID_METADATA,
     "Invalid enclave metadata.",
     NULL},
    {SGX_ERROR_DEVICE_BUSY,
     "SGX device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION,
     "Enclave version was invalid.",
     NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE,
     "Enclave was not authorized.",
     NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,
     "Can't open enclave file.",
     NULL},
    {SGX_ERROR_NDEBUG_ENCLAVE,
     "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH)
    {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    }
    else
    {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
    {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL)
    {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
        {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);

        if (fp != NULL)
            fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL)
    {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL)
            fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL)
        return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

//void ocall_dimatcopy(const char ordering, const char trans, size_t rows, size_t cols, const double alpha, double * AB, size_t lda, size_t ldb, size_t size)
//{
//    mkl_dimatcopy(ordering, trans, rows, cols, alpha, AB, lda, ldb);
//}

void ocall_print_uint(uint8_t *u, size_t size)
{
    printf("Info: uint8_t*: ");
    for (int i = 0; i < size; i++)
    {
        if (i % 24 == 0)
            printf("\n");
        printf("%4d", (uint8_t) * (u + i));
    }
    printf("\n");
}

/***************************WL: record demo***************************/

#define MAX_BUF_LEN 49 * 4096
#define RANGE 26
#define MAX_SNAPSHOT_LEN 49 * 2 * 4096

int snapshot_collect(const char* filename, const char* mode)
{
    //WL: read config data from the protected file
    //WL: have to open snapshot; the snapshot file is only opened by PFS APIs
    FILE *fp_snapshot;
    if ((fp_snapshot = fopen(filename, mode)) == NULL)
    {
        printf("Fail to open file!\n");
        return -1;
    }

    //WL: get snapshot file length
    unsigned long int snapshot_filelen = 0;
    fseek(fp_snapshot, 0, SEEK_END);
    snapshot_filelen = ftell(fp_snapshot);
    printf("current snapshot file length: %ld\n", snapshot_filelen);
    //WL: filter some files, according to the file length
    //WL: requirepass at: 

    //WL: init snapshot_buffer
    //WL: not the MAX_BUF_LEN
    char snapshot_buffer[MAX_SNAPSHOT_LEN] = {0};
    printf("Start to copy snapshot...\n");
    fseek(fp_snapshot, 0, SEEK_SET);
    fread(snapshot_buffer, 1, snapshot_filelen, fp_snapshot);
    // printf("first 3 letters in snapshot_buffer: %c%c%c\n", snapshot_buffer[0], snapshot_buffer[1], snapshot_buffer[2]);

    //WL: write snapshot to final file
    FILE *fp_snapshot_final;
    const char* ss_filename = "redis.snapshot";
    const char* ss_mode = "w+";
    if ((fp_snapshot_final = fopen(ss_filename, ss_mode)) == NULL)
    {
        printf("Fail to open file!\n");
        return -1;
    }
    unsigned long int sizeoffinal = fwrite(snapshot_buffer, 1, snapshot_filelen, fp_snapshot_final);
    printf("final snapshot length: %ld\n", sizeoffinal);
    //WL: do not close fp_snapshot
    fclose(fp_snapshot_final);
    return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint64_t file_size = 0;

    SGX_FILE *fp_redis_pfs;
    //WL: write data to redis_pfs.conf
    const char *filename = "redis.pfs.conf";
    const char *mode = "w+";

    //Open PFS file
    ret = ecall_file_open(eid, &fp_redis_pfs, filename, mode);
    if (ret < 0)
    {
        printf("bad open\n");
        return -1;
    }

    // //WL: open another file
    // SGX_FILE *fp2;
    // //WL: write data to redis_pfs.conf
    // const char *filename2 = "redis_pfs2.conf";
    // const char *mode2 = "w+";
    // //Open PFS file
    // ret = ecall_file_open(eid, &fp2, filename2, mode2);
    // if (ret < 0)
    // {
    //     printf("bad open\n");
    //     return -1;
    // }

    //WL: init write_buffer
    char write_buffer[MAX_BUF_LEN] = {0};

    //WL: read config data from the unprotected file
    const char *configfilename = "./redis.conf";
    const char *configfilemode = "r";

    //WL: open config file
    FILE *fp_config;
    if ((fp_config = fopen(configfilename, configfilemode)) == NULL)
    {
        printf("Fail to open file!\n");
        return -1;
    }
    printf("original redis file opens successfully\n");

    //WL: get length of original config file
    unsigned long int redis_filelen, read_filelen = 0;
    fseek(fp_config, 0, SEEK_END);
    redis_filelen = ftell(fp_config);
    printf("original redis.conf length: %ld\n", redis_filelen);

    //WL: read fp_config data to write_buffer
    if (redis_filelen > MAX_BUF_LEN)
    {
        read_filelen = MAX_BUF_LEN;
    }
    else
    {
        read_filelen = redis_filelen;
    }
    printf("actual read length: %ld\n", read_filelen);
    fseek(fp_config, 0, SEEK_SET);
    fread(write_buffer, 1, read_filelen, fp_config);
    // printf("first 3 letters in write_buffer: %c%c%c\n", write_buffer[0], write_buffer[1], write_buffer[2]);
    fclose(fp_config);

    size_t sizeOfWrite = 0;
    printf("Start to write...\n");
    ret = ecall_file_write(eid, &sizeOfWrite, fp_redis_pfs, write_buffer, strlen(write_buffer));
    //WL: write again
    // ret = ecall_file_write(eid, &sizeOfWrite, fp, write_buffer, strlen(write_buffer));
    //WL: out-of-order write？
    //WL: append random data
    //WL: generate random array
    // srand((unsigned)time(NULL));
    // for (int j = 0; j < MAX_BUF_LEN; j++)
    // {
    //     write_buffer[j] = rand() % RANGE + 33;
    // }
    // ret = ecall_file_write(eid, &sizeOfWrite, fp, write_buffer, strlen(write_buffer));

    // //WL: write fp2
    // printf("Writing fp2...\n");
    // ret = ecall_file_write(eid, &sizeOfWrite, fp2, write_buffer, strlen(write_buffer));
    // //WL: write fp1 again but using random data
    // //WL: generate random array
    // srand((unsigned)time(NULL));
    // for (int j = 0; j < MAX_BUF_LEN; j++)
    // {
    //     write_buffer[j] = rand() % RANGE + 33;
    // }
    // printf("Writing fp again...\n");
    // ret = ecall_file_write(eid, &sizeOfWrite, fp, write_buffer, strlen(write_buffer));

    // printf("Size of Write=  %ld\n", sizeOfWrite);

    //WL: test: read fp data to read_buffer
    printf("Start to get file size...\n");
    ret = ecall_file_get_file_size(eid, &file_size, fp_redis_pfs);
    printf("In app: file size = %ld\n", file_size);
    size_t sizeOfRead = 0;
    //WL: init the read buffer
    char read_buffer[MAX_BUF_LEN] = {0};
    printf("Start to read...\n");
    if (file_size > MAX_BUF_LEN)
    {
        read_filelen = MAX_BUF_LEN;
    }
    else
    {
        read_filelen = file_size;
    }
    // printf("actual read length: %ld\n", read_filelen);
    //WL: ecall_file_read calls the sgx_fseek inside the enclave
    ret = ecall_file_read(eid, &sizeOfRead, fp_redis_pfs, read_buffer, file_size);
    printf("Size of Read= %ld\n", sizeOfRead);
    printf("first 3 letters in read_buffer: %c%c%c\n", read_buffer[0], read_buffer[1], read_buffer[2]);

    //WL: close the file (need a fd?)
    // int32_t fileHandle;
    //WL: try not to close the file, seeing if we can get surprised
    ecall_file_close(eid, fp_redis_pfs);

    /* Destroy the enclave */
    //WL: we also do not destroy the enclave
    sgx_destroy_enclave(eid);

    printf("Info: demo successfully finished.\n");

    //WL: start to run the snapshot collection module...
    //WL: write snapshot at redis.snapshot
    int collect_ret = snapshot_collect(filename, "r");
    if (collect_ret == 0) {
        printf("Snapshot collected...\n");
    }

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}
