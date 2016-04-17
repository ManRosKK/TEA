#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

void print_data(uint8_t* block)
{
    printf("block: %02X %02X %02X %02X %02X %02X %02X %02X \n",
           block[0],
           block[1],
           block[2],
           block[3],
           block[4],
           block[5],
           block[6],
           block[7]);

}

void print_key(uint32_t* key)
{
    printf("key: %08X %08X %08X %08X\n",
           key[0],
           key[1],
           key[2],
           key[3]);
}

static uint32_t tea_rand()
{
    return rand(); //random by dice roll
}

void tea_cycle_encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void tea_cycle_decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void tea_block_encrypt(uint8_t* data, uint32_t* key)
{
    tea_cycle_encrypt((uint32_t*)data, key);
}

void tea_block_decrypt(uint8_t* data, uint32_t* key)
{
    int i = 0;
    tea_cycle_decrypt((uint32_t*)data, key);
}

void tea_encrypt_EBC(uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{

    //TODO: pararell
    int i = 0;
    int j = 0;
    int k = 0;
    for (i =0; i + 8 < len; i+= 8)
    {
        tea_block_encrypt(data+i, key);
    }
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
        
        tea_block_encrypt(data + i, key);
    } else {
        tea_block_encrypt(data + i, key);
    }
}

void tea_decrypt_EBC (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    //TODO: pararell
    int i = 0;
    int j = 0;
    int k = 0;
    for (i =0; (i+8) < len; i+= 8)
    {
        tea_block_decrypt(data+i, key);
    }
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
        
        tea_block_decrypt(data + i, key);
    } else {
        tea_block_decrypt(data + i, key);
    }

}

void tea_encrypt_CBC (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    for (i =0; i + 8 < len; i+= 8)
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        *d = *d ^ *iv;
        tea_block_encrypt(data+i, key);
        *iv = *d;
    }
    
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
        
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        *d = *d ^ *iv;        
        tea_block_encrypt(data + i, key);
        *iv = *d;
    } else {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        *d = *d ^ *iv;
        tea_block_encrypt(data + i, key);
        *iv = *d;
    }
}

void tea_decrypt_CBC (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    uint64_t last;
    for (i =0; (i+8) < len; i+= 8)
    {
        last = *((uint64_t*)(data+i));
        tea_block_decrypt(data+i, key);
        (*((uint64_t*)(data+i))) ^= *((uint64_t*)(init_vector));
        *((uint64_t*)(init_vector)) = last;
    }
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
        
        last = *((uint64_t*)(data+i));
        tea_block_decrypt(data+i, key);
        (*((uint64_t*)(data+i))) ^= *((uint64_t*)(init_vector));
        *((uint64_t*)(init_vector)) = last;
    } else {
        last = *((uint64_t*)(data+i));
        tea_block_decrypt(data+i, key);
        (*((uint64_t*)(data+i))) ^= *((uint64_t*)(init_vector));
        *((uint64_t*)(init_vector)) = last;
    }
}

void tea_encrypt_PCBC (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    uint64_t last;
    for (i =0; i + 8 < len; i+= 8)
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        last = *d;
        *d = *d ^ *iv;
        tea_block_encrypt(data+i, key);
        *iv =  *d ^ last;
    }
    
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
        
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        last = *d;
        *d = *d ^ *iv;        
        tea_block_encrypt(data + i, key);
        *iv = *d ^ last;
    } else {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        last = *d;
        *d = *d ^ *iv;
        tea_block_encrypt(data + i, key);
        *iv = *d ^ last;
    }
}

void tea_decrypt_PCBC (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    uint64_t last;
    for (i =0; i + 8 < len; i+= 8)
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        last = *d;
        tea_block_decrypt(data+i, key);
        *d ^= *iv;
        *iv =  *d ^ last;
    }
    
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
        
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        last = *d;
        tea_block_decrypt(data+i, key);
        *d ^= *iv;
        *iv =  *d ^ last;
    } else {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        last = *d;
        tea_block_decrypt(data+i, key);
        *d ^= *iv;
        *iv =  *d ^ last;        
    }
}

void tea_encrypt_CFB (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    for (i =0; i + 8 < len; i+= 8)
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        tea_block_encrypt(init_vector, key);
        *d = *d ^ *iv;
	*iv = *d;
    }
    
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
    }
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        tea_block_encrypt(init_vector, key);
        *d = *d ^ *iv;
	*iv = *d;
    }
}

void tea_decrypt_CFB (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    uint64_t last;
    for (i =0; i + 8 < len; i+= 8)
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
	last = *d;
        tea_block_encrypt(init_vector, key);
        *d = *iv ^ last;
	*iv = last;
    }
    
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
    }
    {
	uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
	last = *d;
        tea_block_encrypt(init_vector, key);
        *d = *iv ^ last;
	*iv = last;
    }
}

void tea_encrypt_OFB (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    for (i =0; i + 8 < len; i+= 8)
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        tea_block_encrypt(init_vector, key);
        *d = *d ^ *iv;
    }
    
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
    }
    {
	uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        tea_block_encrypt(init_vector, key);
        *d = *d ^ *iv;
    }
}

void tea_decrypt_OFB (uint8_t* data, uint32_t len, uint32_t* key, uint8_t* init_vector)
{
    int i = 0;
    int j = 0;
    int k = 0;
    for (i =0; i + 8 < len; i+= 8)
    {
        uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        tea_block_encrypt(init_vector, key);
        *d = *d ^ *iv;
    }
    
    if ( (i + 8) != len)
    {
        for (j = len; j < i + 8; j++)
            *(data + j) = 0;
    }
    {
	uint64_t* iv = (uint64_t*)init_vector;
        uint64_t* d = (uint64_t*)(data+i);
        tea_block_encrypt(init_vector, key);
        *d = *d ^ *iv;
    }
}


enum tea_mode_t
{
    EBC=0,
    CBC,
    PCBC,
    CFB,
    OFB
};

enum tea_mode_t tea_mode = EBC;
int tea_encrypt_flag = 0;
int tea_decrypt_flag = 0;
int tea_generate_flag = 0;
char tea_file_path_key[1024];
char tea_file_path_iv[1024];
uint32_t tea_key[4];
uint8_t  tea_init_vector[8];

void (*tea_encrypt_mode[])(uint8_t*, uint32_t, uint32_t*, uint8_t*) = {
    tea_encrypt_EBC,
    tea_encrypt_CBC,
    tea_encrypt_PCBC,
    tea_encrypt_CFB,
    tea_encrypt_OFB
};

void (*tea_decrypt_mode[])(uint8_t*, uint32_t, uint32_t*, uint8_t*) = {
    tea_decrypt_EBC,
    tea_decrypt_CBC,
    tea_decrypt_PCBC,
    tea_decrypt_CFB,
    tea_decrypt_OFB
};


void parse_args(int argc, char** argv)
{
    int c;
    // c- sciezka do pliku z kluczem i wektorem poczotkowym (jesli nie ma to przy szyfrowaniu jest tworzony
    //C -compakt szyfrue lub deszyfruje z do pliku z naglowkiem z kluczem i wektorem
    sprintf(tea_file_path_key, "%s", "key.bin");
    sprintf(tea_file_path_iv, "%s", "iv.bin");
    
    while ((c = getopt (argc, argv, "edgm:D:")) != -1)
        switch (c)
        {
        case 'e':
            tea_encrypt_flag = 1;
            break;
        case 'd':
            tea_decrypt_flag = 1;
            break;
        case 'g':
            tea_generate_flag = 1;
            break;
        case 'D':
            sprintf(tea_file_path_key, "%s%s",optarg, "key.bin");
            sprintf(tea_file_path_iv, "%s%s", optarg, "iv.bin");
            break;
        case 'm':
            if (strcmp(optarg, "ebc") == 0)
                tea_mode = EBC;
            else if (strcmp(optarg, "cbc") == 0)
                tea_mode = CBC;
            else if (strcmp(optarg, "pcbc") == 0)
                tea_mode = PCBC;
            else if (strcmp(optarg, "cfb") == 0)
                tea_mode = CFB;
            else if (strcmp(optarg, "ofb") == 0)
                tea_mode = OFB;
            else if (strcmp(optarg, "cbc") == 0)
                tea_mode = CBC;
            break;
        default:
            abort ();
        }
}

int write_bin_file(uint8_t* buffer, int len, const char* filename)
{
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0)
        return -errno;

    int l = write(fd, buffer, len);
    if (l != len)
        return -1;
    
    close (fd);
    return 0;
}

int read_bin_file (uint8_t* buffer, int len,  const char* filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -errno;

    int l = read(fd, buffer, len);
    if (l != len)
        return -1;
    close (fd);
    return 0;
}

int do_tea(void (*tea_block_operation)(uint8_t*, uint32_t, uint32_t*, uint8_t*))
{
    int r = 0;
    int offset = 0;
    uint8_t buffer[8*128];
    fprintf(stderr, "---1\n");
    while ( (r = read(STDIN_FILENO, buffer + offset, (8*128)-offset)) > 0)
    {
        fprintf(stderr, "---2 : %d\n", r);
        offset += r;
        if (offset >= 8*128)
        {
            fprintf(stderr, "---3\n");
            tea_block_operation(buffer, offset, tea_key, tea_init_vector);
            r = write(STDOUT_FILENO, buffer, offset);
            if (r <= 0)
            {
                fprintf(stderr, "Cannot write to output\n");
                return r;
            }
            offset = 0;
        }
    }
    if (offset)
    {
        fprintf(stderr, "---4\n");
        tea_block_operation(buffer, offset, tea_key, tea_init_vector);
        
        r = write(STDOUT_FILENO, buffer, (offset/8 + ((offset%8 == 0)?0:1))*8);
        if (r <= 0)
        {
            fprintf(stderr, "Cannot write to output\n");
            return r;
        }
    }
    return 0;
}

int main(int argc, char** argv)
{
    int r;
    void (*tea_block_operation)(uint8_t*, uint32_t, uint32_t*, uint8_t*);
    srand(time(NULL));
//    uint8_t data[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
//    uint32_t key[] = { 0xabcd3245, 0x1639a1b2, 0xf32e2c2a, 0x321aaadd};

    parse_args(argc, argv);
    
//    print_data(data);
//    print_key(key);

//    tea_encrypt_EBC(data, sizeof(data), key, NULL);

    //  print_data(data);

//    tea_decrypt_EBC(data, sizeof(data), key, NULL);

//    print_data(data);

    if (tea_generate_flag)
    {
        int i = 0;
        for (i=0;i<4;i++)
            tea_key[i] = tea_rand();
        i = write_bin_file((uint8_t*)tea_key, 16, tea_file_path_key);
        
        if (i)
            fprintf(stderr, "Cannot write key: %d\n", i); 
    }
    
    r = read_bin_file( (uint8_t*)tea_key, 16, tea_file_path_key);
    if (r)
        fprintf(stderr, "Cannot read key: %d\n", r);

    r = read_bin_file( (uint8_t*)tea_init_vector, 8, tea_file_path_iv);
    if (r)
        fprintf(stderr, "Cannot read iv: %d\n", r);
    
    if (tea_encrypt_flag)
    {
        int i = 0;
        for (i=0;i<2;i++)
            ((uint32_t*)tea_init_vector)[i] = tea_rand();
        i = write_bin_file((uint8_t*)tea_init_vector, 8, tea_file_path_iv);
        
        if (i)
            fprintf(stderr, "Cannot write key: %d\n", i);
        
        tea_block_operation = tea_encrypt_mode[tea_mode];
    } else if (tea_decrypt_flag)
    {
        tea_block_operation = tea_decrypt_mode[tea_mode];
    }
    
    return do_tea(tea_block_operation);
}
