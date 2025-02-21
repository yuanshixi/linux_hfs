/*
    @author yuanluo2
    
    file server based on http protocol, written in ANSI C, only single file.
    this program is used to seek the file list of my server or upload files to my server.
    only supports linux platform.
*/
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

/* linux headers. */
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <ifaddrs.h>

typedef unsigned char      Boolean;
typedef struct MimePair    MimePair;
typedef struct MimeMap     MimeMap;
typedef struct String      String;
typedef struct StringNode  StringNode;
typedef struct StringList  StringList;
typedef struct HeaderPair  HeaderPair;
typedef struct Headers     Headers;
typedef struct Request     Request;
typedef struct Response    Response;
typedef struct Connection  Connection;
typedef struct Server      Server;

/* for arena allocator. */
typedef unsigned char            ArenaFlag;
typedef struct ArenaBlockHeader  ArenaBlockHeader;
typedef struct ArenaAllocator    ArenaAllocator;

#define TIME_BUF_SIZE          64
#define DEFAULT_BLOCK_SIZE     8192
#define DEFAULT_BUF_SIZE       8192
#define HTTP_CHUNKED_BUF_SIZE  8192

#define THRESHOLD_FILE_LIST_CONCAT_LEN  (DEFAULT_BLOCK_SIZE - 512)

#define MAX_HTTP_REQUEST_LENGTH       2048
#define MAX_HTTP_REQUEST_METHOD_LEN   16
#define MAX_HTTP_REQUEST_URL_LEN      1024
#define MAX_HTTP_REQUEST_VERSION_LEN  16
#define MAX_HTTP_HEADERS_NUM          64

#define MAX_HTTP_RESPONSE_VERSION_LEN  16
#define MAX_HTTP_RESPONSE_CODE_LEN     8
#define MAX_HTTP_RESPONSE_MSG_LEN      32

#define HEADERS_DEFAULT_BUCKET_SIZE  101
#define MIMEMAP_DEFAULT_BUCKET_SIZE  101

/* 
    store ip:port like 192.168.102.39:55539

    ip    max length is INET6_ADDRSTRLEN
    :     length is 1
    port  max length is 5
    \0    a null terminated character length is 1.
*/
#define MAX_IP_PORT_BUF_SIZE             (INET6_ADDRSTRLEN + 7)

#define RECV_TIMEOUT_SEC   5
#define RECV_TIMEOUT_USEC  0

/* bool values. */
#define b_True   1
#define b_False  0

/*
    this is for arena allocator.
    when allocate a block, it can only be those 3 status:

    1. only one pointer to take the whole block,
    2. multi pointers split this block,
    3. no usage.

    if case 1 is fit, then if that block is not in use, we can
    consider it as a new block, and reuse it in case 1 or case 2.
*/
#define ARENA_FLAG_ONLY_ONE      0
#define ARENA_FLAG_MULTI_PARTS   1
#define ARENA_FLAG_NO_USE        2

struct MimePair {
    String* key;
    String* value;
    MimePair* next;
};

struct MimeMap {
    MimePair* bucket[MIMEMAP_DEFAULT_BUCKET_SIZE];
    String* defaultValue;
    size_t length;
};

struct ArenaBlockHeader {
    size_t used;
    size_t capacity;
    ArenaFlag flag;
    ArenaBlockHeader* next;
};

struct ArenaAllocator {
    ArenaBlockHeader* head;
    size_t blockSize;
    size_t blockNum;
};

struct String {
    size_t length;
    size_t capacity;

    /* 
        this field is always ends with '\0'. 
        so it can deal with ANSI C's <string.h> functions.
    */
    char* data;  
};

struct StringNode {
    String* str;
    StringNode* next;
};

struct StringList {
    StringNode* head;
    size_t length;
};

struct HeaderPair {
    String* key;
    String* value;
    HeaderPair* next;
};

struct Headers {
    HeaderPair* bucket[HEADERS_DEFAULT_BUCKET_SIZE];
    size_t length;
};

struct Request {
    String* method;
    String* url;
    String* version;
    Headers* headers;
};

struct Response {
    String* version;
    String* code;
    String* msg;
    Headers* headers;
    String* body;
};

struct Connection {
    ArenaAllocator* arena;
    String* ip_port;
    String* path;
    int fd;
};

struct Server {
    ArenaAllocator* arena;
    const char* rootDir;
    int fd;
    int port;
};

/************************** global variables. ***************************/
/* 
    server running status. 
*/
static volatile sig_atomic_t running = 1;

/* 
    extension -> mime mapping. 
*/
static MimeMap* mimeMapping = NULL;

static String* server_ip_port = NULL;

/************************* functions. **************************/
void hfs_log(FILE* stream, const char* fmt, ...) {
    va_list args;
    time_t current_time;
    struct tm* local_time;
    char time_str[TIME_BUF_SIZE];

    time(&current_time);
    local_time = localtime(&current_time);
    strftime(time_str, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", local_time);

    fprintf(stream, "[%s] ", time_str);
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);
}

Boolean is_dir(const char* path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        hfs_log(stderr, "stat() failed: `%s`, %s\n", path, strerror(errno));
        return b_False;
    }

    return S_ISDIR(st.st_mode);
}

Boolean is_regular_file(const char* path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        hfs_log(stderr, "stat() failed: `%s`, %s\n", path, strerror(errno));
        return b_False;
    }

    return S_ISREG(st.st_mode);
}

/*
    create a arena allocator handle.
    remember to call arena_free() at last.
*/
ArenaAllocator* arena_create(size_t blockSize) {
    ArenaAllocator* arena = (ArenaAllocator*)malloc(sizeof(ArenaAllocator));

    if (arena == NULL) {
        return NULL;
    }

    arena->head = (ArenaBlockHeader*)malloc(sizeof(ArenaBlockHeader) + blockSize);
    if (arena->head == NULL) {
        free(arena);
        return NULL;
    }

    arena->blockSize = blockSize;
    arena->head->capacity = blockSize;
    arena->head->flag = ARENA_FLAG_NO_USE;
    arena->head->used = 0;
    arena->head->next = NULL;
    arena->blockNum = 1;

    return arena;
}

/*
    free all blocks and arena itself.
    this function will do nothing if arena is NULL.
*/
void arena_free(ArenaAllocator* arena) {
    ArenaBlockHeader* cursor;

    if (arena != NULL) {
        cursor = arena->head;

        while (cursor != NULL) {
            arena->head = cursor->next;
            free(cursor);
            cursor = arena->head;
        }

        free(arena);
    }
}

/*
    create a new block with given params.

    if allocation failed, this function will log and error and call abort().
*/
ArenaBlockHeader* arena_create_new_block(ArenaAllocator* arena, size_t size, size_t used, ArenaFlag flag) {
    ArenaBlockHeader* newBlock = (ArenaBlockHeader*)malloc(sizeof(ArenaBlockHeader) + size);
    
    if (newBlock != NULL) {
        newBlock->capacity = size;
        newBlock->flag = flag;
        newBlock->used = used;
        newBlock->next = arena->head;
        arena->head = newBlock;

        arena->blockNum += 1;
    }
    else {
        /*
            In this program, when out of memory, I choose to using abort policy, because this server
            actually do not have some important data to be saved, abort() just fit the usage.
        */
        hfs_log(stderr, "arena allocator failed: out of memory\n");
        fflush(stderr);
        abort();
    }

    return newBlock;
}

/*
    same usage as malloc().

    this function would allocate memory from the existing blocks, if size not fit,
    new block will be allocated.
*/
void* arena_malloc(ArenaAllocator* arena, size_t size) {
    ArenaBlockHeader* cursor = arena->head;
    ArenaBlockHeader* newBlock;

    while (cursor != NULL) {
        if (cursor->flag != ARENA_FLAG_ONLY_ONE && cursor->used + size <= cursor->capacity) {
            cursor->used += size;

            if (size == arena->blockSize) {
                cursor->flag = ARENA_FLAG_ONLY_ONE;
            }
            else {
                cursor->flag = ARENA_FLAG_MULTI_PARTS;
            }

            return (void*)((char*)(cursor + 1) + cursor->used - size);
        }

        cursor = cursor->next;
    }

    /* if can't find, create a new block. */
    if (size < arena->blockSize) {
        newBlock = arena_create_new_block(arena, arena->blockSize, size, ARENA_FLAG_MULTI_PARTS);
    }
    else {
        newBlock = arena_create_new_block(arena, size, size, ARENA_FLAG_ONLY_ONE);
    }

    return (void*)(newBlock + 1);
}

/*
    try to recycle memory allocated by arena allocator.
*/
void arena_recycle(ArenaAllocator* arena, void* memory, size_t capacity) {
    ArenaBlockHeader* header = (ArenaBlockHeader*)memory - 1;

    if (capacity >= arena->blockSize && header->flag == ARENA_FLAG_ONLY_ONE) {
        hfs_log(stdout, "arena allocator trigger recycle for %ld bytes\n", capacity);
        header->flag = ARENA_FLAG_NO_USE;
        header->used = 0;
    }
}

void arena_seek_usage(ArenaAllocator* arena) {
    float total = 0;
    float totalUsed = 0;
    float percent;
    ArenaBlockHeader* cursor = arena->head;

    while (cursor != NULL) {
        total += cursor->capacity;
        totalUsed += cursor->used;
        cursor = cursor->next;
    }

    percent = totalUsed / total * 100;
    hfs_log(stdout, "total memory: `%d` bytes, used: `%d` bytes, percent: %.2f%%\n", (int)total, (int)totalUsed, percent);
}

String* str_create_ex(ArenaAllocator* arena, size_t capacity) {
    String* str = (String*)arena_malloc(arena, sizeof(String));

    str->capacity = capacity;
    str->length = 0;
    str->data = (char*)arena_malloc(arena, capacity * sizeof(char));
    str->data[0] = '\0';
    return str;
}

String* str_create(ArenaAllocator* arena) {
    return str_create_ex(arena, 32);
}

String* str_create_by_cstr_ex(ArenaAllocator* arena, const char* cstr, size_t len) {
    String* str = str_create_ex(arena, (len + 1) * sizeof(char));
    
    memcpy(str->data, cstr, len * sizeof(char));
    str->capacity = len + 1;
    str->length = len;
    str->data[len] = '\0';
    return str;
}

String* str_create_by_cstr(ArenaAllocator* arena, const char* cstr) {
    return str_create_by_cstr_ex(arena, cstr, strlen(cstr));
}

void str_reset(String* str) {
    str->length = 0;
}

void str_expand_capacity(ArenaAllocator* arena, String* str, size_t newCapacity) {
    char* temp;
    
    if (newCapacity <= str->capacity) {
        return;
    }

    temp = (char*)arena_malloc(arena, newCapacity * sizeof(char));

    memcpy(temp, str->data, (str->length + 1) * sizeof(char));
    arena_recycle(arena, str->data, str->capacity);
    str->data = temp;
    str->capacity = newCapacity;
}

void str_add_char(ArenaAllocator* arena, String* str, char c) {
    if (str->length + 1 == str->capacity) {
        str_expand_capacity(arena, str, 1.5 * str->capacity * sizeof(char));
    }

    str->data[str->length] = c;
    str->length += 1;
    str->data[str->length] = '\0';
}

void str_add_cstr_ex(ArenaAllocator* arena, String* str, const char* cstr, size_t len) {
    size_t needLen = (str->length + len + 1) * sizeof(char);

    if (needLen > str->capacity) {
        str_expand_capacity(arena, str, needLen);
    }
    
    memcpy(str->data + str->length, cstr, len * sizeof(char));
    str->length += len;
    str->data[str->length] = '\0';
}

void str_add_cstr(ArenaAllocator* arena, String* str, const char* cstr) {
    str_add_cstr_ex(arena, str, cstr, strlen(cstr));
}

void str_add_str(ArenaAllocator* arena, String* str, String* other) {
    str_add_cstr_ex(arena, str, other->data, other->length);
}

void str_pop_back(String* str) {
    if (str->length > 0) {
        str->length -= 1;
        str->data[str->length] = '\0';
    }
}

void str_reverse(String* str) {
    size_t i, j;
    char c;

    for (i = 0; i < str->length / 2; ++i) {
        j = str->length - 1 - i;

        /* swap two. */
        c = str->data[i];
        str->data[i] = str->data[j];
        str->data[j] = c;
    }
}

void str_reverse_pos(String* str, size_t begin, size_t end) {
    char c;

    for (; begin < end; ++begin, --end) {
        c = str->data[begin];
        str->data[begin] = str->data[end];
        str->data[end] = c;
    }
}

Boolean str_ends_with_char(String* str, char c) {
    if (str->length > 0) {
        if (str->data[str->length - 1] == c) {
            return b_True;
        }
    }

    return b_False;
}

String* str_create_by_long(ArenaAllocator* arena, long num) {
    long remainder;
    String* str = str_create(arena);

    if (num == 0) {
        str_add_char(arena, str, '0');
    }
    else {
        while (num > 0) {
            remainder = num % 10;
            str_add_char(arena, str, remainder + '0');
            num /= 10;
        }

        str_reverse(str);
    }

    return str;
}

void str_add_long(ArenaAllocator* arena, String* str, long num) {
    long remainder;
    size_t begin = str->length;

    if (num == 0) {
        str_add_char(arena, str, '0');
    }
    else {
        while (num > 0) {
            remainder = num % 10;
            str_add_char(arena, str, remainder + '0');
            num /= 10;
        }

        str_reverse_pos(str, begin, str->length - 1);
    }
}

/*
    add a long integer, but in hex format.
*/
void str_add_long_in_hex(ArenaAllocator* arena, String* str, long num) {
    long remainder;
    size_t begin = str->length;

    while (num > 0) {
        remainder = num % 16;

        if (remainder < 10) {   /* 0-9 */
            str_add_char(arena, str, remainder + '0');
        }
        else {   /* A-E */
            str_add_char(arena, str, remainder - 10 + 'A');
        }

        num /= 16;
    }

    str_reverse_pos(str, begin, str->length - 1);
}

/*
    convert a float number to a string with specified precision.
*/
String* str_create_by_float(ArenaAllocator* arena, float num, int precision) {
    long long_part = (long)num;
    float float_part = num - long_part;
    long digit;
    int i;
    
    String* numStr = str_create_by_long(arena, long_part);
    str_add_char(arena, numStr, '.');
    
    for (i = 0; i < precision; ++i) {
        float_part *= 10;
        digit = (long)(float_part);
        str_add_char(arena, numStr, digit + '0');
        float_part -= digit;
    }

    return numStr;
}

Boolean str_compare_ignore_case(String* left, String* right) {
    size_t i;
    
    if (left->length != right->length) {
        return b_False;
    }

    for (i = 0; i < left->length; ++i) {
        if (tolower(left->data[i]) != tolower(right->data[i])) {
            return b_False;
        }
    }

    return b_True;
}

StringNode* str_node_create(ArenaAllocator* arena, String* str) {
    StringNode* node = (StringNode*)arena_malloc(arena, sizeof(StringNode));

    node->str = str;
    node->next = NULL;
    return node;
}

StringList* str_list_create(ArenaAllocator* arena) {
    StringList* list = (StringList*)arena_malloc(arena, sizeof(StringList));

    list->head = NULL;
    list->length = 0;
    return list;
}

void str_list_add(ArenaAllocator* arena, StringList* list, String* str) {
    StringNode* node = str_node_create(arena, str);

    if (list->head == NULL) {
        list->head = node;
    }
    else {
        node->next = list->head;
        list->head = node;
    }

    list->length += 1;
}

MimePair* mime_pair_create(ArenaAllocator* arena, String* key, String* value) {
    MimePair* mp = (MimePair*)arena_malloc(arena, sizeof(MimePair));
    
    mp->key = key;
    mp->value = value;
    mp->next = NULL;
    return mp;
}

MimeMap* mime_map_create(ArenaAllocator* arena) {
    MimeMap* mm = (MimeMap*)arena_malloc(arena, sizeof(MimeMap));
    size_t i;

    for (i = 0; i < HEADERS_DEFAULT_BUCKET_SIZE; ++i) {
        mm->bucket[i] = NULL;
    }

    mm->defaultValue = str_create_by_cstr(arena, "text/plain");
    mm->length = 0;
    return mm;
}

unsigned int mime_map_hash(String* key) {
    unsigned int hashval = 0;
    size_t i;

    for (i = 0; i < key->length; ++i) {
        /* K&R's hash algorithm. because the mime map should ignore case, so using tolower() here. */
        hashval = tolower(key->data[i]) + 31 * hashval;
    }

    return hashval % MIMEMAP_DEFAULT_BUCKET_SIZE;
}

MimePair* mime_map_search(MimeMap* mm, String* key) {
    unsigned int hashval = mime_map_hash(key);
    MimePair* cursor = mm->bucket[hashval];

    while (cursor != NULL) {
        if (str_compare_ignore_case(key, cursor->key)) {
            return cursor;
        }

        cursor = cursor->next;
    }

    return NULL;
}

/*
    get value from the mimeMap with specified key.
    if key is NULL or can't find this key, then return the mimeMap's defaultValue.
*/
String* mime_map_get(MimeMap* mm, String* key) {
    MimePair* pair;
    
    if (key == NULL) {
        return mm->defaultValue;
    }
    else {
        pair = mime_map_search(mm, key);
        return pair == NULL ? mm->defaultValue : pair->value;
    }
}

void mime_map_add(ArenaAllocator* arena, MimeMap* mm, String* key, String* value) {
    MimePair* mp = mime_map_search(mm, key);
    unsigned int hashval;

    if (mp != NULL) {
        return;
    }

    hashval = mime_map_hash(key);
    mp = mime_pair_create(arena, key, value);

    if (mm->bucket[hashval] == NULL) {
        mm->bucket[hashval] = mp;
    }
    else {
        mp->next = mm->bucket[hashval];
        mm->bucket[hashval] = mp;
    }

    mm->length += 1;
}

/*
    read one line from the file, discard the end \n.
    this function do not add \0 at the buf's end.

    return -1 if line's len exceed the param `len` or any error occurs.
    else return the read length.
*/
int file_read_line(FILE* f, char* buf, int len) {
    int n = 0;
    char c = '\0';

    while (!feof(f)) {
        if (n == len) {
            return -1;
        }

        fread(&c, sizeof(char), 1, f);
        
        if (ferror(f)) {
            return -1;
        }
        else {
            if (c == '\n') {
                break;
            }
            else {
                buf[n] = c;
                ++n;
            }
        }
    }

    return n;
}

void split_mime_line_and_save(ArenaAllocator* arena, const char* buf, int len) {
    int i;
    String* key;
    String* value;

    for (i = 0; i < len; ++i) {
        if (buf[i] == ' ' || buf[i] == '\t') {
            break;
        }
    }

    key = str_create_by_cstr_ex(arena, buf, i);

    while (buf[i] == ' ' || buf[i] == '\t') {
        ++i;
    }

    value = str_create_by_cstr_ex(arena, buf + i, len - i);
    mime_map_add(arena, mimeMapping, key, value);
}

Boolean mime_map_init(ArenaAllocator* arena, const char* mimeMapFilePath) {
    char buf[128];
    FILE* f;
    int len;

    if ((f = fopen(mimeMapFilePath, "r")) == NULL) {
        hfs_log(stderr, "can't open `%s`\n", mimeMapFilePath);
        return b_False;
    }

    mimeMapping = mime_map_create(arena);

    while (!feof(f)) {
        len = file_read_line(f, buf, sizeof(buf) / sizeof(char));

        if (len == 0) {   /* skip the empty line. */
            continue;
        }
        else if (len < 0) {
            fclose(f);
            hfs_log(stderr, "`%s` read line failed\n", mimeMapFilePath);
            return b_False;
        }
        else {
            split_mime_line_and_save(arena, buf, len);
        }
    }

    fclose(f);
    return b_True;
}

String* extension_to_mime(String* extension) {
    return mime_map_get(mimeMapping, extension);
}

Boolean local_ip_port_init(ArenaAllocator* arena, int port) {
    struct ifaddrs* ifaddr;
    struct ifaddrs* cursor;
    struct sockaddr_in* sockaddr;
    char ip[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) != 0) {
        hfs_log(stderr, "getifaddrs() failed, %s\n", strerror(errno));
        return b_False;
    }

    server_ip_port = str_create_ex(arena, MAX_IP_PORT_BUF_SIZE);

    for (cursor = ifaddr; cursor != NULL; cursor = cursor->ifa_next) {
        if (cursor->ifa_addr->sa_family == AF_INET) {   /* ignore ipv6. */
            sockaddr = (struct sockaddr_in*)(cursor->ifa_addr);

            if (inet_ntop(AF_INET, &(sockaddr->sin_addr), ip, INET6_ADDRSTRLEN) == NULL) {
                hfs_log(stderr, "inet_ntop() failed, %s\n", strerror(errno));
                freeifaddrs(ifaddr);
                return b_False;
            }

            /* ignore the 127.0.0.1 or 172.xxx.xxx.xxx */
            if (strstr(ip, "127") == NULL && strstr(ip, "172") == NULL) {
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    str_add_cstr(arena, server_ip_port, ip);
    str_add_cstr(arena, server_ip_port, ":");
    str_add_long(arena, server_ip_port, port);
    return b_True;
}

HeaderPair* header_pair_create(ArenaAllocator* arena, String* key, String* value) {
    HeaderPair* hp = (HeaderPair*)arena_malloc(arena, sizeof(HeaderPair));
    
    hp->key = key;
    hp->value = value;
    hp->next = NULL;
    return hp;
}

Headers* headers_create(ArenaAllocator* arena) {
    Headers* headers = (Headers*)arena_malloc(arena, sizeof(Headers));
    size_t i;

    for (i = 0; i < HEADERS_DEFAULT_BUCKET_SIZE; ++i) {
        headers->bucket[i] = NULL;
    }

    headers->length = 0;
    return headers;
}

unsigned int headers_hash(String* key) {
    unsigned int hashval = 0;
    size_t i;

    for (i = 0; i < key->length; ++i) {
        /* K&R's hash algorithm, because headers should ignore case, using tolower() here. */
        hashval = tolower(key->data[i]) + 31 * hashval;
    }

    return hashval % HEADERS_DEFAULT_BUCKET_SIZE;
}

HeaderPair* headers_search(Headers* headers, String* key) {
    unsigned int hashval = headers_hash(key);
    HeaderPair* cursor = headers->bucket[hashval];

    while (cursor != NULL) {
        if (str_compare_ignore_case(key, cursor->key)) {
            return cursor;
        }

        cursor = cursor->next;
    }

    return NULL;
}

String* headers_get(Headers* headers, String* key) {
    HeaderPair* pair = headers_search(headers, key);
    return pair == NULL ? NULL : pair->value;
}

void headers_add(ArenaAllocator* arena, Headers* headers, String* key, String* value) {
    HeaderPair* hp = headers_search(headers, key);
    unsigned int hashval;

    if (hp != NULL) {
        hp->value = value;
        return;
    }

    hashval = headers_hash(key);
    hp = header_pair_create(arena, key, value);

    if (headers->bucket[hashval] == NULL) {
        headers->bucket[hashval] = hp;
    }
    else {
        hp->next = headers->bucket[hashval];
        headers->bucket[hashval] = hp;
    }

    headers->length += 1;
}

void conn_free(Connection* conn) {
    if (conn->fd >= 0) {
        close(conn->fd);
    }

    arena_free(conn->arena);

    conn->fd = -1;
    conn->ip_port = NULL;
}

Boolean conn_init(Connection* conn, int fd, size_t blockSize, const char* rootDir) {
    conn->fd = fd;
    conn->ip_port = NULL;
    conn->arena = arena_create(blockSize);
    conn->path = str_create_by_cstr(conn->arena, rootDir);

    return conn->arena != NULL;
}

/* this function will try port to 65535 until success. */
Boolean server_bind_ip_port(int fd, const char* ip, int* port) {
    struct sockaddr_in addr;
    int option = 1;
    int ret;
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(*port);

    ret = inet_pton(AF_INET, ip, &(addr.sin_addr));
    if (ret < 0) {
        hfs_log(stderr, "inet_pton() failed, %s\n", strerror(errno));
        return b_False;
    }
    else if (ret == 0) {
        hfs_log(stderr, "`%s` is not valid ipv4/ipv6 address\n", ip);
        return b_False;
    }

    while (bind(fd, (const struct sockaddr*)(&addr), sizeof(addr)) != 0) {
        if (*port == 65535) {
            hfs_log(stderr, "bind() failed, %s\n", strerror(errno));
            return b_False;
        }
        else {
            *port += 1;
            addr.sin_port = htons(*port);
        }
    }

    if (listen(fd, 32) != 0) {
        hfs_log(stderr, "listen() failed, %s\n", strerror(errno));
        return b_False;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*)(&option), sizeof(option)) < 0) {
        hfs_log(stderr, "setsockopt() on SO_REUSEADDR failed, %s\n", strerror(errno));
        return b_False;
    }

    return b_True;
}

Boolean conn_get_ip_port(Connection* conn) {
    char ip[INET6_ADDRSTRLEN];
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (getpeername(conn->fd, (struct sockaddr*)(&addr), &len) != 0) {
        hfs_log(stderr, "getpeername() failed, %s\n", strerror(errno));
        return b_False;
    }

    if (inet_ntop(addr.sin_family, &(addr.sin_addr), ip, sizeof(ip) / sizeof(char)) == NULL) {
        hfs_log(stderr, "inet_ntop() failed, %s\n", strerror(errno));
        return b_False;
    }

    conn->ip_port = str_create_ex(conn->arena, MAX_IP_PORT_BUF_SIZE);
    str_add_cstr(conn->arena, conn->ip_port, ip);
    str_add_cstr(conn->arena, conn->ip_port, ":");
    str_add_long(conn->arena, conn->ip_port, ntohs(addr.sin_port));
    return b_True;
}

Boolean conn_set_recv_timeout(Connection* conn) {
    struct timeval timeout;

    timeout.tv_sec = RECV_TIMEOUT_SEC;
    timeout.tv_usec = RECV_TIMEOUT_USEC;

    if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        hfs_log(stderr, "setsockopt() on SO_RCVTIMEO failed, %s\n", strerror(errno));
		return b_False;
	}

    return b_True;
}

Request* request_create(ArenaAllocator* arena) {
    Request* req = (Request*)arena_malloc(arena, sizeof(Request));

    req->method = str_create(arena);
    req->url = str_create(arena);
    req->version = str_create(arena);
    req->headers = headers_create(arena);

    return req;
}

Response* response_create(ArenaAllocator* arena) {
    Response* res = (Response*)arena_malloc(arena, sizeof(Response));

    res->version = str_create(arena);
    res->code = str_create(arena);
    res->msg = str_create(arena);
    res->headers = headers_create(arena);
    res->body = str_create(arena);

    return res;
}

/*
    read one line with socket fd.
    this function would discard the end \r\n.

    if any system call error occurs, returns -1.
    if request length exceed the bufSize, returns -1.
    if meets the final \r\n, returns 0.
    else return the length of the line.
*/
int socket_read_line(int fd, char* buf, size_t bufSize) {
    int numOfRecvBytes = 0;
    int n = 0;
    char c = '\0';

    while (numOfRecvBytes < bufSize) {
        n = recv(fd, &c, 1, 0);

        if (n <= 0) {
            return -1;
        }
        else {
            if (c == '\r') {
                n = recv(fd, &c, 1, MSG_PEEK);
                
                if (n <= 0) {
                    return -1;
                }
                else {
                    if (c == '\n') {
                        recv(fd, &c, 1, 0);
                        break;
                    }
                    else {
                        return -1;
                    }
                }
            }
            else {
                buf[numOfRecvBytes] = c;
                numOfRecvBytes += 1;
            }
        }
    }

    return c == '\n' ? numOfRecvBytes : -1;
}

Boolean parse_method_url_version(Connection* conn, Request* req, char* buf, size_t bufSize) {
    int len = socket_read_line(conn->fd, buf, bufSize);
    int i;

    if (len < 0) {
        return b_False;
    }

    i = 0;
    while (buf[i] != ' ') {
        if (req->method->length == MAX_HTTP_REQUEST_METHOD_LEN) {
            return b_False;
        }

        str_add_char(conn->arena, req->method, buf[i]);
        ++i;
    }

    ++i;   /* ignore the space. */
    while (buf[i] != ' ') {
        if (req->url->length == MAX_HTTP_REQUEST_URL_LEN) {
            return b_False;
        }
        
        str_add_char(conn->arena, req->url, buf[i]);
        ++i;
    }

    ++i;   /* ignore the space. */
    if (len - i >= MAX_HTTP_REQUEST_VERSION_LEN) {
        return b_False;
    }

    while (i < len) {
        str_add_char(conn->arena, req->version, buf[i]);
        ++i;
    }

    return b_True;
}

void split_http_header_and_save(ArenaAllocator* arena, Request* req, const char* buf, int len) {
    String* key;
    String* value;
    int i;

    for (i = 0; i < len; ++i) {
        if (buf[i] == ':') {
            break;
        }
    }

    key = str_create_by_cstr_ex(arena, buf, i);
    value = str_create_by_cstr_ex(arena, buf + i + 2, len - i - 2);
    headers_add(arena, req->headers, key, value);
}

Boolean parse_http_request_headers(Connection* conn, Request* req, char* buf, size_t bufSize) {
    int len;

    while (b_True) {
        len = socket_read_line(conn->fd, buf, bufSize);

        if (len < 0) {
            return b_False;
        }
        else if (len == 0) {   /* meets the final \r\n. */
            return b_True;
        }

        if (req->headers->length == MAX_HTTP_HEADERS_NUM) {
            return b_False;
        }

        split_http_header_and_save(conn->arena, req, buf, len);
    }
}

int hex_to_decimal(char c) {
    if (c >= '0' && c <= '9'){
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f'){
        return c - 'a' + 10;
    }
    else if (c >= 'A' && c <= 'F'){
        return c - 'A' + 10;
    }
    else {
        return -1;
    }
}

Boolean decode_percent_encoding_url(ArenaAllocator* arena, Request* req) {
    String* temp = str_create_ex(arena, req->url->length);
    size_t i;
    int p1, p2;

    for (i = 0; i < req->url->length; ) {
        if (req->url->data[i] == '%') {
            if (i + 2 >= req->url->length) {
                return b_False;
            }

            p1 = hex_to_decimal(req->url->data[i + 1]);
            p2 = hex_to_decimal(req->url->data[i + 2]);

            if (p1 >= 0 && p2 >= 0) {
                str_add_char(arena, temp, 16 * p1 + p2);
                i += 3;
            }
            else {
                return b_False;
            }
        }
        else {
            str_add_char(arena, temp, req->url->data[i]);
            ++i;
        }
    }

    req->url = temp;
    return b_True;
}

Boolean parse_request(Connection* conn, Request* req) {
    char* buf = (char*)arena_malloc(conn->arena, DEFAULT_BUF_SIZE);

    if (!parse_method_url_version(conn, req, buf, DEFAULT_BUF_SIZE)) {
        return b_False;
    }

    if (!parse_http_request_headers(conn, req, buf, DEFAULT_BUF_SIZE)) {
        return b_False;
    }

    if (!decode_percent_encoding_url(conn->arena, req)) {
        return b_False;
    }

    arena_recycle(conn->arena, buf, DEFAULT_BLOCK_SIZE);
    return b_True;
}

Response* response_create_by_template(ArenaAllocator* arena, const char* code, const char* msg) {
    Response* res = response_create(arena);

    str_add_cstr(arena, res->version, "HTTP/1.1");
    str_add_cstr(arena, res->code, code);
    str_add_cstr(arena, res->msg, msg);

    str_add_cstr(arena, res->body, "<html><head><h1>");
    str_add_cstr(arena, res->body, code);
    str_add_cstr(arena, res->body, "</h1></head><body>");
    str_add_cstr(arena, res->body, msg);
    str_add_cstr(arena, res->body, "</body></html>");

    headers_add(arena, res->headers, str_create_by_cstr(arena, "Content-Type"), str_create_by_cstr(arena, "text/html"));
    headers_add(arena, res->headers, str_create_by_cstr(arena, "Content-Length"), str_create_by_long(arena, res->body->length));

    return res;
}

String* response_to_str(ArenaAllocator* arena, Response* res) {
    String* str = str_create(arena);
    HeaderPair* cursor;
    size_t i;

    str_add_str(arena, str, res->version);
    str_add_char(arena, str, ' ');
    str_add_str(arena, str, res->code);
    str_add_char(arena, str, ' ');
    str_add_str(arena, str, res->msg);
    str_add_cstr(arena, str, "\r\n");

    for (i = 0; i < HEADERS_DEFAULT_BUCKET_SIZE; ++i) {
        cursor = res->headers->bucket[i];

        while (cursor != NULL) {
            str_add_str(arena, str, cursor->key);
            str_add_cstr(arena, str, ": ");
            str_add_str(arena, str, cursor->value);
            str_add_cstr(arena, str, "\r\n");

            cursor = cursor->next;
        }
    }

    str_add_cstr(arena, str, "\r\n");
    str_add_str(arena, str, res->body);
    return str;
}

void print_request_brief(Connection* conn, Request* req) {
    hfs_log(stdout, "%s  --  %s  --  %s\n", conn->ip_port->data, req->method->data, req->url->data);
}

void print_request_detail(Connection* conn, Request* req) {
    size_t i;
    HeaderPair* cursor;
    hfs_log(stdout, "%s\n", conn->ip_port->data);
    hfs_log(stdout, "%s %s %s\n", req->method->data, req->url->data, req->version->data);

    for (i = 0; i < HEADERS_DEFAULT_BUCKET_SIZE; ++i) {
        cursor = req->headers->bucket[i];

        while (cursor != NULL) {
            printf("%s: %s\n", cursor->key->data, cursor->value->data);
            cursor = cursor->next;
        }
    }
}

Boolean send_all(int fd, String* str) {
    ssize_t total = str->length;
    ssize_t sent = 0;

    while (total > 0) {
        sent = send(fd, str->data + sent, str->length - sent, 0);

        if (sent < 0) {
            hfs_log(stderr, "send() failed, %s\n", strerror(errno));
            return b_False;
        }

        total -= sent;
    }

    return b_True;
}

void send_response(ArenaAllocator* arena, int fd, Response* res) {
    String* str = response_to_str(arena, res);
    (void)send_all(fd, str);
}

String* get_file_extension(ArenaAllocator* arena, String* filePath) {
    size_t i;

    for (i = 0; i < filePath->length; ++i) {
        if (filePath->data[i] == '.') {
            break;
        }
    }

    if (i == filePath->length) {
        return NULL;
    }
    else {
        return str_create_by_cstr_ex(arena, filePath->data + i, filePath->length - i);
    }
}

void send_chunked_file_data(Connection* conn, String* path) {
    char* buf = (char*)arena_malloc(conn->arena, HTTP_CHUNKED_BUF_SIZE);
    String* temp = str_create(conn->arena);
    int len;

    /* before this, path has been checked in handle_files_page(), so it must be valid. */
    FILE* f = fopen(path->data, "rb");
    while (!feof(f)) {
        len = fread(buf, sizeof(char), HTTP_CHUNKED_BUF_SIZE, f);

        if (ferror(f)) {
            hfs_log(stderr, "fread() failed, can't send chunked data for %s\n", path->data);
            return;
        }

        str_add_long_in_hex(conn->arena, temp, len);
        
        /*
            may be send some very big size file,
            if it failed, just return.
        */
        if (!send_all(conn->fd, temp)) {
            hfs_log(stderr, "send file failed: `%s`\n", path->data);
            return;
        }

        send(conn->fd, "\r\n", 2, 0);
        send(conn->fd, buf, len, 0);
        send(conn->fd, "\r\n", 2, 0);

        str_reset(temp);
    }

    send(conn->fd, "0\r\n\r\n", 5, 0);
}

void serve_single_file(Connection* conn, String* path) {
    String* extension = get_file_extension(conn->arena, path);
    String* mimeType = extension_to_mime(extension);
    Response* res = response_create(conn->arena);

    str_add_cstr(conn->arena, res->version, "HTTP/1.1");
    str_add_cstr(conn->arena, res->code, "200");
    str_add_cstr(conn->arena, res->msg, "OK");
    
    headers_add(conn->arena, res->headers, str_create_by_cstr(conn->arena, "Content-Type"), mimeType);
    headers_add(conn->arena, res->headers, str_create_by_cstr(conn->arena, "Transfer-Encoding"), str_create_by_cstr(conn->arena, "chunked"));

    send_response(conn->arena, conn->fd, res);
    send_chunked_file_data(conn, path);
}

String* concat_path(ArenaAllocator* arena, String* parent, String* sub) {
    String* temp = str_create_ex(arena, parent->length + sub->length + 2);
    str_add_str(arena, temp, parent);

    if (str_ends_with_char(temp, '/')) {
        str_pop_back(temp);
    }

    if (sub->data[0] != '/') {
        str_add_char(arena, temp, '/');
    }

    str_add_str(arena, temp, sub);
    return temp;
}

String* file_size_to_str(ArenaAllocator* arena, float fileSize, int precision) {
    int level = 0;
    String* str;

	while (b_True) {
		if (fileSize / 1024.0 < 1.0f || level == 4) {
			break;
		}
		else {
			fileSize /= 1024.0;
			++level;
		}
	}

    str = str_create_by_float(arena, fileSize, precision);

    switch(level) {
        case 0:
            str_add_cstr(arena, str, " B");
            break;
        case 1:
            str_add_cstr(arena, str, " KB");
            break;
        case 2:
            str_add_cstr(arena, str, " MB");
            break;
        case 3:
            str_add_cstr(arena, str, " GB");
            break;
        case 4:
        default:
            str_add_cstr(arena, str, " TB");
            break;
    }

    return str;
}

/*
    In this program's early time, the StringList doesn't exist, this function would add all file names into 
    the Response' body directly, because arena allocator only allocate, never release, so this body would
    expand again and again, some day when I open a dir on my browser, it's very slow, because this dir contains many files,
    the memory usage of this connection takes me 568040576 bytes! This is really a mistake!
    
    I can't tolerant that, so I came up with this StringList. to save every file's name, string would expand, but they have limit, 
    can't expand many times, and can't take a huge memory usage. using a list to save the strings can avoid a single long string's 2x 
    expand policy, so this idea can decrease the memory usage. After I add this list, the memory usage only takes 516096 bytes.
*/
size_t build_file_list(ArenaAllocator* arena, DIR* dir, String* baseDir, Request* req, StringList* list) {
    struct dirent* entry;
	struct stat st;
    String* entryName;
    String* subUrl;
    String* completePath;
    String* line;
    size_t totalLength = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        entryName = str_create_by_cstr(arena, entry->d_name);
        subUrl = concat_path(arena, req->url, entryName);
        completePath = concat_path(arena, baseDir, subUrl);

        if (stat(completePath->data, &st) < 0) {
            /* may be permission denied or some other error, just skip those files. */
            continue;
        }

        line = str_create_ex(arena, 128);

        str_add_cstr(arena, line, "<li><a href=\"");
        str_add_str(arena, line, subUrl);
        str_add_cstr(arena, line, "\">");

		if (S_ISDIR(st.st_mode)) {
            str_add_cstr(arena, line, "/");
		}

        str_add_str(arena, line, entryName);

        if (S_ISREG(st.st_mode)) {
            str_add_cstr(arena, line, "</a><span>&nbsp;&nbsp;");
            str_add_str(arena, line, file_size_to_str(arena, st.st_size, 2));
            str_add_cstr(arena, line, "</span></li>\n");
        }
        else {
            str_add_cstr(arena, line, "</a></li>\n");
        }

        totalLength += line->length;
        str_list_add(arena, list, line);
    }

    return totalLength;
}

void serve_file_list(Connection* conn, Request* req, String* currentPath) {
    Response* res;
    DIR* dir;
    StringNode* node;
    StringList* list = str_list_create(conn->arena);
    String* temp;
    String* bodyEnd;
    size_t totalLength;
    size_t contentLength;
    
    if ((dir = opendir(currentPath->data)) == NULL) {
        hfs_log(stderr, "opendir() failed: `%s`, %s\n", currentPath->data, strerror(errno));
        res = response_create_by_template(conn->arena, "500", "Internal Server Error");
        send_response(conn->arena, conn->fd, res);
        return;
    }
    else {
        res = response_create(conn->arena);

        str_add_cstr(conn->arena, res->version, "HTTP/1.1");
        str_add_cstr(conn->arena, res->code, "200");
        str_add_cstr(conn->arena, res->msg, "OK");

        str_add_cstr(conn->arena, res->body, "<html><head><h1>Http File Server</h1></head><body>");
        str_add_cstr(conn->arena, res->body, "<form id=\"uploadForm\" action=\"http://");
        str_add_str(conn->arena, res->body, server_ip_port);
        str_add_str(conn->arena, res->body, req->url);
        str_add_cstr(conn->arena, res->body, "\" method=\"POST\" enctype=\"multipart/form-data\">");
        str_add_cstr(conn->arena, res->body, "<input type=\"file\" id=\"fileInput\" name=\"fileInput\" />");
        str_add_cstr(conn->arena, res->body, "<button type=\"submit\">Upload</button></form><hr><ul>");        

        bodyEnd = str_create_by_cstr(conn->arena, "</ul><hr></body></html>");

        totalLength = build_file_list(conn->arena, dir, conn->path, req, list);
        closedir(dir);

        contentLength = res->body->length + totalLength + bodyEnd->length;

        headers_add(conn->arena, res->headers, str_create_by_cstr(conn->arena, "Content-Type"), str_create_by_cstr(conn->arena, "text/html; charset=utf-8"));
        headers_add(conn->arena, res->headers, str_create_by_cstr(conn->arena, "Content-Length"), str_create_by_long(conn->arena, contentLength));
        send_response(conn->arena, conn->fd, res);

        temp = str_create_ex(conn->arena, DEFAULT_BLOCK_SIZE);
        node = list->head;

        while (node != NULL) {
            str_add_str(conn->arena, temp, node->str);

            if (temp->length >= THRESHOLD_FILE_LIST_CONCAT_LEN) {
                (void)send_all(conn->fd, temp);
                str_reset(temp);
            }

            node = node->next;
        }

        if (temp->length > 0) {
            (void)send_all(conn->fd, temp);
            str_reset(temp);
        }

        (void)send_all(conn->fd, temp);
        (void)send_all(conn->fd, bodyEnd);
    }
}

void handle_files_page(Connection* conn, Request* req) {
    Response* res;
    String* currentPath = concat_path(conn->arena, conn->path, req->url);

    if (is_dir(currentPath->data)) {
        serve_file_list(conn, req, currentPath);
    }
    else if (is_regular_file(currentPath->data)) {
        serve_single_file(conn, currentPath);
    }
    else {
        res = response_create_by_template(conn->arena, "404", "Not Found");
        send_response(conn->arena, conn->fd, res);
    }
}

long str_to_long(String* str) {
    long num = 0;
    size_t i;

    for (i = 0; i < str->length; ++i) {
        num = 10 * num + str->data[i] - '0';
    }

    return num;
}

String* parse_boundary(ArenaAllocator* arena, String* contentTypeValue) {
    String* pattern = str_create_by_cstr(arena, "multipart/form-data; boundary=");
    char* pos = strstr(contentTypeValue->data, pattern->data);

    if (pos == NULL) {
        return NULL;
    }

    return str_create_by_cstr_ex(arena, pos + pattern->length, contentTypeValue->length - pattern->length);
}

void send_upload_success_page(ArenaAllocator* arena, int fd) {
    Response* res = response_create(arena);

    str_add_cstr(arena, res->version, "HTTP/1.1");
    str_add_cstr(arena, res->code, "200");
    str_add_cstr(arena, res->msg, "OK");

    str_add_cstr(arena, res->body, "<html><head><h1>");
    str_add_cstr(arena, res->body, "Http File Server");
    str_add_cstr(arena, res->body, "</h1></head><body>");
    str_add_cstr(arena, res->body, "Upload success");
    str_add_cstr(arena, res->body, "</body></html>");

    headers_add(arena, res->headers, str_create_by_cstr(arena, "Content-Type"), str_create_by_cstr(arena, "text/html"));
    headers_add(arena, res->headers, str_create_by_cstr(arena, "Content-Length"), str_create_by_long(arena, res->body->length));

    send_response(arena, fd, res);
}

int compare_min(int left, int right) {
    return (left < right) ? left : right;
}

void recv_file_parts(ArenaAllocator* arena, int fd, long contentLength, String* boundary, String* parentDir) {
    Response* res;
    String* fileName = str_create(arena);
    String* fileNamePattern = str_create_by_cstr(arena, "filename=\"");
    String* completePath;
    char* buf = (char*)arena_malloc(arena, DEFAULT_BUF_SIZE);
    char* pos = NULL;
    FILE* outFile;
    int len;

    /* first, get every line to find out the file name, and read until the final \r\n. */
    while (b_True) {
        /* we would be used strstr() later, so left one byte to store a end '\0'. */
        len = socket_read_line(fd, buf, DEFAULT_BUF_SIZE - 1);

        if (len == 0) {   /* meets the final \r\n */
            contentLength -= 2;   /* be careful here, subtract the length of the \r\n */
            break;
        }
        else if (len < 0) {
            res = response_create_by_template(arena, "500", "Internal Server Error");
            send_response(arena, fd, res);
            return;
        }
        else {
            contentLength -= (len + 2);   /* subtract the `len` and `\r\n`. */
            buf[len] = '\0';   /* here, because we have to use strstr(), so add a end '\0'. */
            pos = strstr(buf, fileNamePattern->data);
            
            if (pos != NULL) {
                pos += fileNamePattern->length;

                while (*pos != '"') {
                    str_add_char(arena, fileName, *pos);
                    ++pos;
                }
            }
        }
    }

    if (fileName->length == 0) {
        res = response_create_by_template(arena, "400", "Bad Request");
        send_response(arena, fd, res);
        return;
    }

    /* 
        second, parse the file data. 
        after the file data, the data remain: "\r\n, --boundary--\r\n", so if we have read
        all the file data, the length of the bytes left must be boundary's length + 8.
    */
    completePath = concat_path(arena, parentDir, fileName);
    outFile = fopen(completePath->data, "wb");

    while (contentLength > boundary->length + 8) {
        len = recv(fd, buf, compare_min(DEFAULT_BUF_SIZE, contentLength - boundary->length - 8), 0);
        fwrite(buf, sizeof(char), len, outFile);
        contentLength -= len;
    }

    fclose(outFile);

    /* read the final "\r\n, --boundary--\r\n". */
    socket_read_line(fd, buf, DEFAULT_BUF_SIZE);
    socket_read_line(fd, buf, DEFAULT_BUF_SIZE);

    send_upload_success_page(arena, fd);
    hfs_log(stdout, "upload file success: `%s`\n", completePath->data);
}

void handle_upload(Connection* conn, Request* req) {
    Response* res;
    long contentLength;
    String* boundary;
    String* contentTypeValue;
    String* contentLengthStr;

    contentLengthStr = headers_get(req->headers, str_create_by_cstr(conn->arena, "Content-Length"));
    if (contentLengthStr == NULL) {
        res = response_create_by_template(conn->arena, "411", "Length Required");
        send_response(conn->arena, conn->fd, res);
        return;
    }
    
    contentTypeValue = headers_get(req->headers, str_create_by_cstr(conn->arena, "Content-Type"));
    if (contentTypeValue == NULL) {
        res = response_create_by_template(conn->arena, "400", "Bad Request");
        send_response(conn->arena, conn->fd, res);
        return;
    }

    contentLength = str_to_long(contentLengthStr);
    boundary = parse_boundary(conn->arena, contentTypeValue);
    if (boundary == NULL) {
        res = response_create_by_template(conn->arena, "400", "Bad Request");
        send_response(conn->arena, conn->fd, res);
        return;
    }

    recv_file_parts(conn->arena, conn->fd, contentLength, boundary, concat_path(conn->arena, conn->path, req->url));
}

void conn_handle_http_routine(Connection* conn) {
    Request* req;
    Response* res;

    req = request_create(conn->arena);
    if (!parse_request(conn, req)) {
        hfs_log(stderr, "%s -- can't parse http request\n", conn->ip_port->data);
        return;
    }

    print_request_brief(conn, req);

    if (str_compare_ignore_case(str_create_by_cstr(conn->arena, "GET"), req->method)) {
        handle_files_page(conn, req);
    }
    else if (str_compare_ignore_case(str_create_by_cstr(conn->arena, "POST"), req->method)) {
        handle_upload(conn, req);
    }
    else {
        res = response_create_by_template(conn->arena, "405", "Method Not Allowed");
        send_response(conn->arena, conn->fd, res);
    }
}

void handle_connection(int fd, const char* rootDir) {
    Connection conn;
    if (!conn_init(&conn, fd, DEFAULT_BLOCK_SIZE, rootDir)) {
        goto finally;
    }

    if (!conn_set_recv_timeout(&conn)) {
        goto finally;
    }

    if (!conn_get_ip_port(&conn)) {
        goto finally;
    }

    conn_handle_http_routine(&conn);
    arena_seek_usage(conn.arena);

finally:
    conn_free(&conn);
}

void server_loop(Server* s) {
    int client;
    pid_t pid;
    
    while (running) {
        client = accept(s->fd, NULL, NULL);

        if (client < 0) {
            if (errno != EINTR) {
                hfs_log(stderr, "accept() failed, %s\n", strerror(errno));
            }

            return;
        }

        pid = fork();
        if (pid < 0) {
            hfs_log(stderr, "fork() failed, %s\n", strerror(errno));
        }
        else if (pid > 0) {  /* parent. */
            close(client);
        }
        else {  /* child. */
            close(s->fd);
            handle_connection(client, s->rootDir);
            exit(EXIT_SUCCESS);
        }
    }
}

void server_free(Server* s) {
    if (s->fd >= 0) {
        close(s->fd);
    }

    arena_free(s->arena);
}

Boolean server_init(Server* s, const char* ip, int port, const char* rootDir) {
    s->arena = arena_create(DEFAULT_BLOCK_SIZE);
    if (s->arena == NULL) {
        return b_False;
    }

    s->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->fd < 0) {
        hfs_log(stderr, "error socket(), %s\n", strerror(errno));
        goto tidy_up;
    }

    s->port = port;
    if (!server_bind_ip_port(s->fd, ip, &(s->port))) {
        goto tidy_up;
    }

    if (!mime_map_init(s->arena, "mime.txt")) {
        goto tidy_up;
    }

    if (!local_ip_port_init(s->arena, s->port)) {
        goto tidy_up;
    }

    s->rootDir = rootDir;
    return b_True;

tidy_up:
    server_free(s);
    return b_False;
}

void handle_signal_int(int sigum) {
	running = 0;
}

void handle_signal_child(int signum) {
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* do nothing. */    
    }
}

Boolean setting_signals(void) {
	struct sigaction actionSIGINT;
    struct sigaction actionSIGCHLD;

    actionSIGINT.sa_handler = handle_signal_int;
    actionSIGINT.sa_flags = 0;
    sigemptyset(&(actionSIGINT.sa_mask));

    actionSIGCHLD.sa_handler = handle_signal_child;
    actionSIGCHLD.sa_flags = SA_RESTART;
    sigemptyset(&(actionSIGCHLD.sa_mask));

    if (sigaction(SIGINT, &actionSIGINT, NULL) < 0) {
        hfs_log(stderr, "sigaction() on `SIGINT` failed, %s\n", strerror(errno));
		return b_False;
    }

    if (sigaction(SIGCHLD, &actionSIGCHLD, NULL) < 0) {
        hfs_log(stderr, "sigaction() on `SIGCHLD` failed, %s\n", strerror(errno));
        return b_False;
    }

	/* 
        if we cancel send() with large data, this would make send() return immediately, 
        otherwise the whole program would terminated, that should not be happend.
    */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        hfs_log(stderr, "signal() set SIG_IGN to `SIGPIPE` failed, %s\n", strerror(errno));
		return b_False;
	}

    return b_True;
}

int try_parse_port(const char* param) {
    int result = 0;

    while (*param != '\0') {
        if (isdigit(*param)) {
            result = 10 * result + (*param - '0');
        }
        else {
            return -1;
        }

        ++param;
    }

    if (result > 65535) {   /* port should between: 0 ~ 65535 */
        return -1;
    }

    return result;
}

int main(int argc, char* argv[]) {
    Server s;
    int port;
    
    if (argc != 3) {
        hfs_log(stderr, "usage: %s <port> <root_dir>\n", argv[0]);
        return 1;
    }

    if ((port = try_parse_port(argv[1])) < 0) {
        hfs_log(stderr, "`%s` is not a valid port\n", argv[1]);
        return 1;
    }

    if (!is_dir(argv[2])) {
        hfs_log(stderr, "`%s` is not a valid directory path\n", argv[2]);
        return 1;
    }

    if (!setting_signals()) {
        hfs_log(stderr, "can't setting signals\n");
        return 1;
    }

    if (!server_init(&s, "0.0.0.0", port, argv[2])) {
        hfs_log(stderr, "can't properly init server\n");
        return 1;
    }

    hfs_log(stdout, "server starts on port %d\n", s.port);
    server_loop(&s);
    server_free(&s);
    hfs_log(stdout, "server exits\n");
    return 0;
}
