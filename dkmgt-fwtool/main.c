#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <md5.h>

#include "dkmgt-firmware.h"

static void usage(int argc, char** argv, FILE* fp) {
    fprintf(fp, "Usage: %s [option] FILENAME\n\n", argv[0]);
    fprintf(fp, "Options:\n");

    fprintf(fp, "  --print, -p      Print firmware headers\n");
    fprintf(fp, "  --extract, -x    Extract firmware contents\n");
    fprintf(fp, "  --create, -c     Create firmware from FILENAME\n");
}

static void* map_file(const char* filename, size_t *length) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file: %s", strerror(errno));
        return MAP_FAILED;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Failed to get file status: %s", strerror(errno));
        close(fd);
        return MAP_FAILED;
    }
    void* firmware = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (firmware == MAP_FAILED) {
        fprintf(stderr, "Failed to map file: %s", strerror(errno));
        close(fd);
        return MAP_FAILED;
    }
    if (length) {
        *length = st.st_size;
    }
    close(fd);
    return firmware;
}

static const char* guess_ptn_extension(const void* data, size_t length) {
    uint32_t magic = htonl(*(const uint32_t*)data);
    if ((magic & 0xffffff00) == 0x1f8b0800) {
        // Looks and smells like gzip.
        return ".gz";
    }

    switch (magic) {
        case 0x73717368:
        case 0x68737173:
            return ".squashfs";

        case 0xd00dfeed:{
            // Flattened device tree - but we should check if a kernel image follows.
            uint32_t fdtlen = htonl(*(const uint32_t*)(data + 4));
            if (fdtlen >= length) {
                return ".dtb";
            }
            // There's more data here a kernel image probably follows
            return ".bin";
        }

        default:
            // If all else fails, just call it a binary file.
            return ".bin";
    }
}

static int str_has_suffix(const char* s, const char* suffix) {
    size_t slen = strlen(s);
    size_t xlen = strlen(suffix);
    if (slen < xlen) {
        return 0;
    }
    return strcmp(s + slen - xlen, suffix) == 0;
}

static int ptn_table_append(struct dkmgt_ptn_table* ptable, const char* filename) {
    struct stat st;
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Failed to read %s: %s\n", filename, strerror(errno));
        return -1;
    }

    // Recursively add directory contents.
    if (S_ISDIR(st.st_mode)) {
        // TODO: Recursively add directory contents.
        fprintf(stderr, "TODO recurse into %s\n", filename);
        return 0;
    }

    // Prepare to add a new partition
    if (ptable->count >= DKMGT_MAX_PARTITIONS) {
        fprintf(stderr, "Partition table overflow: too many files\n");
        return -1;
    }
    struct dkmgt_ptn_entry* entry = &ptable->partitions[ptable->count];
    memset(entry, 0, sizeof(struct dkmgt_ptn_entry));
    if (ptable->count > 0) {
        struct dkmgt_ptn_entry* prev = &ptable->partitions[ptable->count-1];
        entry->base = prev->base + prev->size;
    }

    // Use the file basename (without suffix) as the partiton name.
    const char* name = strrchr(filename, '/');
    name = name ? name + 1 : filename;
    size_t namelen = strlen(name);

    char* suffix = strchr(name, '.');
    if (suffix) {
        namelen = suffix - name;
    }
    if (namelen >= sizeof(entry->name)) {
        namelen = sizeof(entry->name) - 1;
    }
    memcpy(entry->name, name, namelen);
    entry->name[namelen] = '\0';

    // If the file contains JSON, wrap it with a partition header.
    if (suffix && strcmp(suffix, ".json") == 0) {
        struct dkmgt_ptn_header hdr;
        hdr.magic[0] = htonl(DKMGT_PTN_MAGIC_0);
        hdr.magic[1] = htonl(DKMGT_PTN_MAGIC_1);
        hdr.length = htonl(st.st_size);
        hdr.checksum = 0;
        
        uint8_t *buf = malloc(st.st_size + sizeof(struct dkmgt_ptn_header));
        if (!buf) {
            fprintf(stderr, "Failed to allocate %d bytes\n", st.st_size + sizeof(struct dkmgt_ptn_header));
            return -1;
        }

        FILE* rfp = fopen(filename, "rb");
        if (rfp == NULL) {
            free(buf);
            return -1;
        }
        memcpy(buf, &hdr, sizeof(hdr));
        if (fread(buf + sizeof(hdr), st.st_size, 1, rfp) <= 0) {
            fprintf(stderr, "Failed to read %s: %s\n", filename, strerror(errno));
            free(buf);
            fclose(rfp);
            return -1;
        }
        fclose(rfp);

        entry->data = buf;
        entry->size = st.st_size + sizeof(struct dkmgt_ptn_header);
        ptable->count++;
        return 0;
    }

    // Otherwise, append the raw file contents without a header.
    size_t length;
    entry->data = map_file(filename, &length);
    entry->size = length;
    ptable->count++;
    return 0;
}

uint8_t *ptn_table_encode(struct dkmgt_ptn_table* ptable) {
    char* buf = calloc(DKMGT_PTN_BLOCK_SIZE, 1);
    if (!buf) {
        fprintf(stderr, "Failed to allocate partition memory\n");
        return NULL;
    }

    size_t offset = snprintf(buf, DKMGT_PTN_BLOCK_SIZE, "{\n   \"up-ptn-table\": [");
    const char* eol = "\n";
    for (int i = 0; i < ptable->count; i++) {
        struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        int len = snprintf(buf + offset, DKMGT_PTN_BLOCK_SIZE - offset,
                           "%s      {\"name\": \"%s\", \"base\": \"0x%08x\", \"size\": \"0x%08x\"}",
                           eol, entry->name, entry->base, entry->size);
        if (offset + len > DKMGT_PTN_BLOCK_SIZE) {
            fprintf(stderr, "Partiton memory overflow\n");
            free(buf);
            return NULL;
        }
        eol = ",\n";
        offset += len;
    }
    int len = snprintf(buf + offset, DKMGT_PTN_BLOCK_SIZE - offset, "\n   ]\n}\n");
    if (offset + len > DKMGT_PTN_BLOCK_SIZE) {
        fprintf(stderr, "Partiton memory overflow\n");
        free(buf);
        return NULL;
    }

    return buf;
}

int do_print(int count, char** filenames) {
    if (!count) {
        fprintf(stderr, "Missing argument: FILENAME\n");
        return EXIT_FAILURE;
    }

    // Map the firmware into memory and begin parsing.
    size_t fwsize;
    void* fwdata = map_file(filenames[0], &fwsize);
    if (fwdata == MAP_FAILED) {
        return EXIT_FAILURE;
    }

    struct dkmgt_firmware* fw = dkmgt_firmware_parse(fwdata, fwsize);
    if (fw) {
        dkmgt_firmware_dump(fw, stdout);
        dkmgt_firmware_free(fw);
    }
    munmap(fwdata, fwsize);
    return (fw == NULL) ? EXIT_FAILURE : EXIT_SUCCESS;
}

int do_extract(int count, char** filenames) {
    if (!count) {
        fprintf(stderr, "Missing argument: FILENAME\n");
        return EXIT_FAILURE;
    }

    // Map the firmware into memory and begin parsing.
    size_t fwsize;
    void* fwdata = map_file(filenames[0], &fwsize);
    if (fwdata == MAP_FAILED) {
        return EXIT_FAILURE;
    }

    struct dkmgt_firmware* fw = dkmgt_firmware_parse(fwdata, fwsize);
    if (!fw) {
        munmap(fwdata, fwsize);
        return EXIT_FAILURE;
    }
    dkmgt_firmware_dump(fw, stderr);
    for (int i = 0; i < fw->ptable.count; i++) {
        struct dkmgt_ptn_entry *entry = &fw->ptable.partitions[i];

        // Use the partition name for the filename.
        char partfile[sizeof(entry->name) + 16];
        memcpy(partfile, entry->name, sizeof(entry->name));
        partfile[sizeof(entry->name)] = '\0';

        // Strip off the ".b" suffix, if present.
        size_t len = strlen(partfile);
        if ((len > 2) && (partfile[len-1] == 'b') && (partfile[len-2] == '.')) {
            partfile[len-2] = '\0';
        }

        // If a valid partition header exists - parse it as JSON.
        struct dkmgt_ptn_header header;
        const void* data = dkmgt_ptn_parse(entry, &header);
        if (data) {
            strcat(partfile, ".json");
        }
        else {
            header.length = entry->size;
            data = entry->data;
            strcat(partfile, guess_ptn_extension(entry->data, header.length));
        }

        // Write the file to disk.
        FILE* wfp = fopen(partfile, "w+b");
        if (!wfp) {
            fprintf(stderr, "Unable to create %s: %s\n", partfile, strerror(errno));
            continue;
        }
        if (fwrite(data, header.length, 1, wfp) <= 0) {
            fprintf(stderr, "Unable to create %s: %s\n", partfile, strerror(errno));
        }
        fclose(wfp);
    }

    dkmgt_firmware_free(fw);
    return EXIT_SUCCESS;
}

int do_create(int count, char** filenames) {
    if (!count) {
        fprintf(stderr, "No source files specified\n");
        return EXIT_FAILURE;
    }

    struct dkmgt_firmware fw;
    memset(&fw, 0, sizeof(fw));
    fw.header.magic[0] = htonl(DKMGT_MAGIC_0);
    fw.header.magic[1] = htonl(DKMGT_MAGIC_1);
    fw.header.magic[2] = htonl(DKMGT_MAGIC_2);
    fw.header.magic[3] = htonl(DKMGT_MAGIC_3);
    fw.header.magic[4] = htonl(DKMGT_MAGIC_4);
    fw.header.magic[5] = htonl(DKMGT_MAGIC_5);
    fw.header.version = htonl(1);
    fw.header.header_len = htonl(sizeof(struct dkmgt_fw_header));

    // Build the partition table.
    for (int i = 0; i < count; i++) {
        if (ptn_table_append(&fw.ptable, filenames[i]) < 0) {
            return EXIT_FAILURE;
        }
    }
    char* ptnbuf = ptn_table_encode(&fw.ptable);

    // Calculate the file size and checksum.
    size_t fwsize = sizeof(struct dkmgt_fw_header) + DKMGT_PTN_BLOCK_SIZE;
    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, ptnbuf, DKMGT_PTN_BLOCK_SIZE);
    for (int i = 0; i < count; i++) {
        struct dkmgt_ptn_entry* entry = &fw.ptable.partitions[i];
        MD5Update(&ctx, entry->data, entry->size);
        fwsize += entry->size;
    }
    MD5Final(fw.header.md5hash, &ctx);
    fw.header.total_len = htonl(fwsize);

    // Serialize the file
    fwrite(&fw.header, sizeof(fw.header), 1, stdout);
    fwrite(ptnbuf, DKMGT_PTN_BLOCK_SIZE, 1, stdout);
    for (int i = 0; i < count; i++) {
        struct dkmgt_ptn_entry* entry = &fw.ptable.partitions[i];
        fwrite(entry->data, entry->size, 1, stdout);
    }
    fclose(stdout);

    return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
    const char* shortopts = "pxch";
    const struct option longopts[] = {
        {"print", no_argument,   NULL, 'p'},
        {"extract", no_argument, NULL, 'x'},
        {"create", no_argument,  NULL, 'c'},
        {"help", no_argument,    NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    const char* filename;
    int (*action)(int, char**) = do_print;

    while (true) {
        int oindex;
        int c = getopt_long(argc, argv, shortopts, longopts, &oindex);
        if (c < 0) {
            break;
        }

        switch (c) {
            case 0:
            case 'p':
                action = do_print;
                break;

            case 'x':
                action = do_extract;
                break;
            
            case 'c':
                action = do_create;
                break;

            case 'h':
                usage(argc, argv, stdout);
                return 0;
        }
    }

    return action(argc - optind, &argv[optind]);
}
