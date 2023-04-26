#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>

#include <libusb-1.0/libusb.h>

/* Configuration variables */
#define CONFIG_SAVE_BLOCK_SIZE         0x8
#define CONFIG_FIRMWARE_BLOCK_SIZE     0x100
#define CONFIG_FIRMWARE_TOTAL_SIZE     0x40000
#define CONFIG_ROM_BLOCK_SIZE          0x1000
#define CONFIG_DUMP_BLOCK_SIZE         0x100
#define CONFIG_ROM_TOTAL_SIZE          0xa00000 /* needed for ROM dumping */

/* Device specific constants. Change only if you know what you are doing. */
#define VENDOR_ID               0x05fd
#define PRODUCT_ID              0xdaae

#define BULK_EP_OUT             0x02
#define BULK_EP_IN              0x81

#define CMD_READ_MEMORY         "CBW\x11"
#define CMD_READ_CHEAT_LIST     "CBW\x12"
#define CMD_WRITE_CHEAT_LIST    "CBW\x13"
#define CMD_GET_GAME_DETAILS    "CBW\x15"
#define CMD_READ_GAME_SAVE      "CBW\x17"
#define CMD_WRITE_GAME_SAVE     "CBW\x18"
#define CMD_GET_DEVICE_STORAGE  "CBW\x1b"
#define CMD_GET_DEVICE_VERSION  "CBW\x1c"
#define CMD_READ_MEMORY_WORLD   "CBW\x1d"
#define CMD_DISCONNECT          "CBW\x20"

#define TRANSFER_SIZE 8

#if TRANSFER_SIZE != 8
#error "TRANFER_SIZE set to a value != 8. Cannot proceed."
#endif

struct read_mem_info {
    unsigned int addr;
    unsigned int len;
};

struct read_mem_info_ex {
    uint32_t addr;
    uint16_t len;
    uint16_t world;
};

#define LEN_GAME_ID             0x04
#define LEN_GAME_NAME           0x10
struct game_id {
    char name[LEN_GAME_NAME + 1];
    char id[LEN_GAME_ID + 1];
};

struct version_info {
    unsigned char minor;
    unsigned char major;
};

struct code_stats {
    uint32_t num_games;
    uint32_t num_cheats;
};

struct data_record {
    uint32_t length:30;
    uint32_t flag1:1;
    uint32_t flag0:1;
    uint8_t name[0x14];
};
#include <assert.h>
static_assert(sizeof(struct data_record) == 0x18, "fuck");

struct code_record {
    uint32_t a;
    uint32_t b;
};

#define ACTION_READ_FIRMWARE  (1 << 0)
#define ACTION_READ_CHEATS    (1 << 1)
#define ACTION_READ_SAVE      (1 << 2)
#define ACTION_WRITE_SAVE     (1 << 3)
#define ACTION_WRITE_CHEATS   (1 << 4)
// Extended mode actions
#define ACTION_READ_MEM_WORLD (1 << (16 + 0))
#define ACTION_DISCONNECT     (1 << (16 + 1))

int cmd_action = 0;

#define MAKEPRINT(X) ((X >= 0x7f || X < 0x20) ? '.' : X)
void hexdump(const unsigned char *buf, size_t len)
{
	int i, j;
    printf("hexdump(%p, 0x%zx)\n", buf, len);

	for (i = 0; i < len / 16; i++) {
		fprintf(stdout, "%02x %02x %02x %02x " \
		       "%02x %02x %02x %02x " \
		       "%02x %02x %02x %02x " \
		       "%02x %02x %02x %02x " \
			"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
			buf[i * 16 + 0], buf[i * 16 + 1], buf[i * 16 + 2],
			buf[i * 16 + 3], buf[i * 16 + 4], buf[i * 16 + 5],
			buf[i * 16 + 6], buf[i * 16 + 7], buf[i * 16 + 8],
			buf[i * 16 + 9], buf[i * 16 + 10], buf[i * 16 + 11],
			buf[i * 16 + 12], buf[i * 16 + 13], buf[i * 16 + 14],
			buf[i * 16 + 15],
			MAKEPRINT(buf[i * 16 + 0]), MAKEPRINT(buf[i * 16 + 1]),
			MAKEPRINT(buf[i * 16 + 2]), MAKEPRINT(buf[i * 16 + 3]),
			MAKEPRINT(buf[i * 16 + 4]), MAKEPRINT(buf[i * 16 + 5]),
			MAKEPRINT(buf[i * 16 + 6]), MAKEPRINT(buf[i * 16 + 7]),
			MAKEPRINT(buf[i * 16 + 8]), MAKEPRINT(buf[i * 16 + 9]),
			MAKEPRINT(buf[i * 16 + 10]), MAKEPRINT(buf[i * 16 + 11]),
			MAKEPRINT(buf[i * 16 + 12]), MAKEPRINT(buf[i * 16 + 13]),
			MAKEPRINT(buf[i * 16 + 14]), MAKEPRINT(buf[i * 16 + 15])
			);
	}

	for (j = 0; j < len % 16; j++) {
		printf("%02x ", buf[i * 16 + j]);
        fflush(stdout);
	}
	for (; j < 16; j++) {
		printf("   ");
	}
	for (j = 0; j < len % 16; j++) {
		printf("%c", MAKEPRINT(buf[i * 16 + j]));
	}
	puts("");
}

static unsigned int comm(libusb_device_handle *dev, unsigned char *buf, unsigned int buflen, unsigned int dir)
{
    int actual = 0;
    int rc = 0;
    rc = libusb_bulk_transfer(dev, dir, buf, buflen, &actual, 0);
    if (rc != 0) {
        puts("Failed to communicate with device.");
        exit(0);
    }
    return actual;
}

static int do_one_send(libusb_device_handle *dev, unsigned char *buf)
{
    size_t sz;
    int res = 0;
    unsigned char tmp[TRANSFER_SIZE] = { 0 };

#ifdef DEBUG
    printf("> ");
    hexdump(buf, TRANSFER_SIZE);
#endif

    sz = comm(dev, buf, TRANSFER_SIZE, BULK_EP_OUT);
    if (sz != TRANSFER_SIZE)
        puts("send: Short write. Continuing ...");
    res = sz != TRANSFER_SIZE;

#ifdef DEBUG
    printf("< ");
    hexdump(tmp, TRANSFER_SIZE);
#endif

    sz = comm(dev, tmp, TRANSFER_SIZE, BULK_EP_IN);
    if (sz != TRANSFER_SIZE)
        puts("send: Short read. Continuing ...");

    if (memcmp(tmp, "\x00\x00\x00\x00\x00\x00\x00\x00", 8))
        return 1;

    return res || (sz != TRANSFER_SIZE);

}

static int do_one_recv(libusb_device_handle *dev, unsigned char *buf)
{
    size_t sz;
    unsigned char tmp[TRANSFER_SIZE] = { 0 };
    int res = 0;

#ifdef DEBUG
    printf("> ");
    hexdump(tmp, TRANSFER_SIZE);
#endif

    sz = comm(dev, tmp, TRANSFER_SIZE, BULK_EP_OUT);
    if (sz != TRANSFER_SIZE)
        puts("recv: Short write. Continuing ...");
    res = sz != TRANSFER_SIZE;

    memset(buf, 0x00, TRANSFER_SIZE);
    sz = comm(dev, buf, TRANSFER_SIZE, BULK_EP_IN);
    if (sz != TRANSFER_SIZE) {
        puts("recv: Short read. Continuing ...");
        memset(buf, 0x00, TRANSFER_SIZE - sz);
    }

#ifdef DEBUG
    printf("< ");
    hexdump(buf, TRANSFER_SIZE);
#endif

    return res || sz != TRANSFER_SIZE;

}

static size_t recv(libusb_device_handle *dev, unsigned char *buf, size_t len)
{
    size_t i;
    unsigned char tmp[TRANSFER_SIZE] = { 0 };
    unsigned int num = (len + TRANSFER_SIZE - 1) / TRANSFER_SIZE;

    if (len == 0) return 0;

    for (i = 0; i + 1 < num; i++) {
        if (do_one_recv(dev, tmp)) {
            return i * TRANSFER_SIZE;
        }
        memcpy(buf + i * TRANSFER_SIZE, tmp, TRANSFER_SIZE);
    }

    if (do_one_recv(dev, tmp)) {
        return i * TRANSFER_SIZE;
    }
    memcpy(buf + i * TRANSFER_SIZE, tmp, len - i * TRANSFER_SIZE);

    return len;
}

static size_t send(libusb_device_handle *dev, unsigned char *buf, size_t len)
{
    size_t i;
    unsigned char tmp[TRANSFER_SIZE] = { 0 };
    unsigned int num = (len + TRANSFER_SIZE - 1) / TRANSFER_SIZE;

    if (len == 0) return 0;

    for (i = 0; i + 1 < num; i++) {
        if (do_one_send(dev, buf + i * TRANSFER_SIZE)) {
            return i * TRANSFER_SIZE;
        }
    }

    memset(tmp, 0x00, sizeof(tmp));
    memcpy(tmp, buf + i * TRANSFER_SIZE, len - i * TRANSFER_SIZE);

    if (do_one_send(dev, tmp)) {
        return i * TRANSFER_SIZE;
    }

    return len;
}

static int send_cmd(libusb_device_handle *dev, const char *cmd)
{
    uint8_t data[TRANSFER_SIZE] = { 0 };

    memcpy(data, cmd, 4);
    return !(send(dev, data, sizeof(data)) == sizeof(data));
}

void cmd_get_device_storage(libusb_device_handle *dev, uint32_t *result)
{
    send_cmd(dev, CMD_GET_DEVICE_STORAGE);
    recv(dev, (unsigned char *)result, sizeof(int));
}

void cmd_get_device_version(libusb_device_handle *dev, struct version_info *result)
{
    if (send_cmd(dev, CMD_GET_DEVICE_VERSION)) {
        puts("Failed to send CMD_GET_DEVICE_VERSION command.\n");
        return;
    }

    recv(dev, (unsigned char *)result, sizeof(struct version_info));
}

void cmd_disconnect(libusb_device_handle *dev)
{
    if (send_cmd(dev, CMD_DISCONNECT)) {
        puts("Failed to send CMD_DISCONNECT command.\n");
        return;
    }
}

void cmd_get_game_details(libusb_device_handle *dev, struct game_id *result)
{
    if (send_cmd(dev, CMD_GET_GAME_DETAILS)) {
        puts("Failed to send CMD_GET_GAME_DETAILS command.\n");
        return;
    }

    recv(dev, (unsigned char *)result->name, LEN_GAME_NAME);
    recv(dev, (unsigned char *)result->id, LEN_GAME_ID);
}

void cmd_read_codes(libusb_device_handle *dev, FILE *f)
{
    struct code_stats stats = { 0 };
    struct data_record cur_game = { 0 };
    struct data_record cur_cheat = { 0 };
    struct code_record cur_code = { 0 };

    if (send_cmd(dev, CMD_READ_CHEAT_LIST)) {
        puts("Failed to send CMD_READ_CHEAT_LIST command.");
        return;
    }

    recv(dev, (unsigned char *)&stats, sizeof(stats));
    fwrite((unsigned char *)&stats, sizeof(stats), 1, f);

    printf("[+] Found %u cheats for %u games.\n", stats.num_cheats, stats.num_games);

    for (unsigned int i = 0; i < stats.num_games; i++) {
        memset(&cur_game, 0x00, sizeof(cur_game));
        recv(dev, (unsigned char *)&cur_game, sizeof(cur_game));
        printf("\r[+] Receiving cheat list %u / %u (%.20s)...", i + 1, stats.num_games, cur_game.name);
        fflush(stdout);

        fwrite((unsigned char *)&cur_game, sizeof(cur_game), 1, f);
        //fprintf(f, "%.20s (%u cheats):\n", cur_game.name, cur_game.length);

        for (unsigned int j = 0; j < cur_game.length; j++) {
            recv(dev, (unsigned char *)&cur_cheat, sizeof(cur_cheat));
            fwrite((unsigned char *)&cur_cheat, sizeof(cur_cheat), 1, f);
            //fprintf(f, "%.20s:\n", cur_cheat.name);

            for (unsigned int k = 0; k < cur_cheat.length / 2; k++) {
                recv(dev, (unsigned char *)&cur_code, sizeof(cur_code));
                fwrite((unsigned char *)&cur_code, sizeof(cur_code), 1, f);
                //fprintf(f, "%08x %08x\n", cur_code.a, cur_code.b);
            }
        }
    }
}

void cmd_write_codes(libusb_device_handle *dev, FILE *f)
{
    struct code_stats stats = { 0 };
    struct data_record cur_game = { 0 };
    struct data_record cur_cheat = { 0 };
    struct code_record cur_code = { 0 };

    if (send_cmd(dev, CMD_WRITE_CHEAT_LIST)) {
        puts("Failed to send CMD_WRITE_CHEAT_LIST command.");
        return;
    }

    if (fread((unsigned char *)&stats, sizeof(stats), 1, f) != 1) {
        puts("Malformed cheat database. (Missing header.)");
    }
    send(dev, (unsigned char *)&stats, sizeof(stats));

    printf("[+] Writing %u cheats for %u games.\n", stats.num_cheats, stats.num_games);

    for (unsigned int i = 0; i < stats.num_games; i++) {
        memset(&cur_game, 0x00, sizeof(cur_game));
        fread((unsigned char *)&cur_game, sizeof(cur_game), 1, f);
        send(dev, (unsigned char *)&cur_game, sizeof(cur_game));

        printf("\r[+] Writing cheat list %u / %u (%.20s)...", i + 1, stats.num_games, cur_game.name);
        fflush(stdout);

        for (unsigned int j = 0; j < cur_game.length; j++) {
            fread((unsigned char *)&cur_cheat, sizeof(cur_cheat), 1, f);
            send(dev, (unsigned char *)&cur_cheat, sizeof(cur_cheat));

            for (unsigned int k = 0; k < cur_cheat.length / 2; k++) {
                fread((unsigned char *)&cur_code, sizeof(cur_code), 1, f);
                send(dev, (unsigned char *)&cur_code, sizeof(cur_code));
            }
        }
    }
}

void cmd_write_save(libusb_device_handle *dev, FILE *save_file)
{
    unsigned char data[TRANSFER_SIZE] = { 0 };
    uint32_t len = 0;
    unsigned char buf[CONFIG_SAVE_BLOCK_SIZE];

    fseek(save_file, 0, SEEK_END);
    len = ftell(save_file);
    fseek(save_file, 0, SEEK_SET);

    if (len != 0x10000) {
        puts("cmd_write_save: only 64k (0x10000 bytes) save files are supported.");
        return;
    }

    if (send_cmd(dev, CMD_WRITE_GAME_SAVE)) {
        puts("Failed to send CMD_WRITE_GAME_SAVE command.\n");
        return;
    }

    memset(data, 0x00, sizeof(data));
    *(uint32_t *)(data) = htole32(len + TRANSFER_SIZE);
    send(dev, data, sizeof(data));

    memset(data, 0x00, sizeof(data));
    *(uint8_t *)(data) = 0x01;
    send(dev, data, sizeof(data));

    for (unsigned int i = 0; (i < len); i += CONFIG_SAVE_BLOCK_SIZE) {
        fread(buf, 1, CONFIG_SAVE_BLOCK_SIZE, save_file);
        if (send(dev, buf, CONFIG_SAVE_BLOCK_SIZE) != CONFIG_SAVE_BLOCK_SIZE) {
            printf("cmd_write_save: short write!\n");
            return;
        }
        printf("\r[+] Sending save game %5.2f %% ...", (double)i / len * 100.0);
        fflush(stdout);
    }

    return;

}

void cmd_read_save(libusb_device_handle *dev, FILE *save_file)
{
    uint32_t len = 0;
    unsigned char buf[CONFIG_SAVE_BLOCK_SIZE];

    if (send_cmd(dev, CMD_READ_GAME_SAVE)) {
        puts("Failed to send CMD_READ_GAME_SAVE command.\n");
        return;
    }

    recv(dev, (unsigned char *)&len, 4);

    if ((len & 0xf) != 8) {
        printf("Received unusual length %#x while reading save game. Check result.", len);
    } else {
        /* Skip junk header (always \x01 followed by 7 zeroes?) */
        unsigned char scratch[8];
        recv(dev, scratch, sizeof(scratch));
        len -= 8;
    }

    for (unsigned int i = 0; (i < len); i += CONFIG_SAVE_BLOCK_SIZE) {
        if (!(cmd_action & ACTION_READ_SAVE)) {
            puts("[.] Action cancelled by the user.");
            return;
        }
        if (recv(dev, buf, CONFIG_SAVE_BLOCK_SIZE) != CONFIG_SAVE_BLOCK_SIZE) {
            printf("cmd_read_save: short read!\n");
            return;
        }
        fwrite(buf, 1, CONFIG_SAVE_BLOCK_SIZE, save_file);
        printf("\r[+] Receiving save game %5.2f %% ...", (double)i / len * 100.0);
        fflush(stdout);
    }

    return;

}

void cmd_read_memory(libusb_device_handle *dev, unsigned int addr, size_t len, unsigned char *result)
{
    struct read_mem_info info = { 0 };

    if (send_cmd(dev, CMD_READ_MEMORY)) {
        puts("Failed to send CMD_READ_MEMORY command.\n");
        return;
    }

    info.addr = addr;
    if (len > UINT_MAX) {
        printf("cmd_read_memory: Truncating length to %#x bytes", (int)len);
    }
    info.len = (int)len;
    send(dev, (unsigned char *)&info, sizeof(info));

    recv(dev, result, len);

    return;

}

void cmd_read_memory_world(libusb_device_handle *dev, uint32_t addr, size_t len,
                                          uint16_t world, unsigned char *result)
{
    struct read_mem_info_ex info = { 0 };

    if (send_cmd(dev, CMD_READ_MEMORY_WORLD)) {
        puts("Failed to send CMD_READ_MEMORY_WORLD command.\n");
        return;
    }

    info.addr = addr;
    if (len > USHRT_MAX) {
        printf("cmd_read_memory_ext: Truncating length to %#x bytes", (int)len);
    }
    info.len = (uint16_t)len;
    info.world = world;

    send(dev, (unsigned char *)&info, sizeof(info));

    recv(dev, result, len);

    return;

}

void read_mem_world(libusb_device_handle *dev, uint32_t addr, size_t len,
                                          uint16_t world, FILE *dmp_file)
{
    size_t sz;
    unsigned char buf[CONFIG_DUMP_BLOCK_SIZE];

    for (sz = 0; sz < len; sz += sizeof(buf)) {
        if (!(cmd_action & ACTION_READ_MEM_WORLD)) {
            puts("[.] Action cancelled by the user.");
            return;
        }
        printf("\r[+] Dumping memory %#04x:%#08x (%7.4f %%) ...",
                world, (unsigned int)(addr + sz),
                ((double)sz / len) * 100.00);
        fflush(stdout);
        cmd_read_memory_world(dev, addr + sz, sizeof(buf), world, buf);
        fwrite(buf, 1, sizeof(buf), dmp_file);
        fflush(dmp_file);
    }
}

void read_firmware(libusb_device_handle *dev, FILE *firmware_file)
{
    size_t sz;
    unsigned char buf[CONFIG_FIRMWARE_BLOCK_SIZE];

    for (sz = 0; sz < CONFIG_FIRMWARE_TOTAL_SIZE; sz += sizeof(buf)) {
        if (!(cmd_action & ACTION_READ_FIRMWARE)) {
            puts("[.] Action cancelled by the user.");
            return;
        }
        printf("\r[+] Dumping firmware (%5.2f %%) ...",
                ((double)sz / CONFIG_FIRMWARE_TOTAL_SIZE) * 100.00);
        fflush(stdout);
        cmd_read_memory(dev, 0x08000000 + sz, sizeof(buf), buf);
        fwrite(buf, 1, sizeof(buf), firmware_file);
    }

}

void print_usage(void)
{
    printf("Usage: %s [-r <rom_file> ]             |\n", program_invocation_name);
    puts(  "          [-m <x>:<address>:<length>   |");
    puts(  "          [-c|-C <code_database_file>] |");
    puts(  "          [-f <firmware_file>]         |");
    puts(  "          [-s|-S <save_file>]");

    puts(  "  -c   Dump code database to file.");
    puts(  "  -f   Dump device firmware to file.");
    puts(  "  -s   Dump save game to file.");

    puts(  "  -C   Upload code database to device.");
    puts(  "  -S   Upload save game to device.");
    puts(  "  -d   Send disconnect.");

    puts(  "  -m   Dump memory from <x>:<address>:<length> (hex) to file.");
    printf("  -r   Dump current ROM to file. (short for -m 0x101:0x08000000:%#x)\n",
                                                             CONFIG_ROM_TOTAL_SIZE);
}

void cleanup()
{
    cmd_action = 0;
}

int main(int argc, char **argv)
{
    int rc = 0, opt = 0;
    char *target_file_name = NULL;
    FILE *target_file = NULL;

    uint32_t arg_mem_addr = 0;
    uint32_t arg_mem_len = 0;
    uint16_t arg_mem_world = 0;
    char     arg_mem_file[256] = { 0 };

    libusb_context *context = NULL;
    libusb_device_handle *dev = NULL;

    while ((opt = getopt(argc, argv, "f:dc:C:r:s:S:m:")) != -1) {
        switch (opt) {
            case 'f':
                cmd_action = ACTION_READ_FIRMWARE;
                target_file_name = optarg;
            break;
            case 'c':
                cmd_action = ACTION_READ_CHEATS;
                target_file_name = optarg;
            break;
            case 'C':
                cmd_action = ACTION_WRITE_CHEATS;
                target_file_name = optarg;
            break;
            case 's':
                cmd_action = ACTION_READ_SAVE;
                target_file_name = optarg;
            break;
            case 'S':
                cmd_action = ACTION_WRITE_SAVE;
                target_file_name = optarg;
            break;
            case 'r':
                cmd_action = ACTION_READ_MEM_WORLD;
                arg_mem_world = 0x101;
                arg_mem_addr = 0x08000000;
                arg_mem_len = CONFIG_ROM_TOTAL_SIZE;
                strncpy(arg_mem_file, optarg, sizeof(arg_mem_file) - 1);
                target_file_name = optarg;
            break;
            case 'm':
                cmd_action = ACTION_READ_MEM_WORLD;
                puts(optarg);
                if (sscanf(optarg, "%hx:%x:%x:%255s", &arg_mem_world,
                       &arg_mem_addr, &arg_mem_len, &arg_mem_file[0]) != 4) {
                    print_usage();
                    return -1;
                }
            break;
            case 'd':
                cmd_action = ACTION_DISCONNECT;
            break;
            default:
                print_usage();
                return -1;
        }
        if (cmd_action) {
            /* Only process one option */
            break;
        }
    }

    if (!cmd_action) {
        puts("[-] Nothing to do. Please specify a task via command line.");
        print_usage();
        return -1;
    }

    if (cmd_action & ACTION_READ_SAVE && cmd_action & ACTION_WRITE_SAVE) {
        puts("[-] Cannot simultaneously read and write save game.");
        return -2;
    }

    if (cmd_action & ACTION_READ_CHEATS && cmd_action & ACTION_WRITE_CHEATS) {
        puts("[-] Cannot simultaneously read and write cheat list.");
        return -2;
    }

    if ((cmd_action & ACTION_DISCONNECT) && (cmd_action & ~ACTION_DISCONNECT)) {
        puts("[-] Disconnect must be sent as a single command.");
        return -2;
    }

    rc = libusb_init(&context);
    if (rc != 0) {
         puts("[-] Failed to initialize USB library.");
         return -3;
    }
    puts("[+] Initialized USB library.");

    libusb_set_option(context, LIBUSB_OPTION_LOG_LEVEL, 3);

    dev = libusb_open_device_with_vid_pid(context,VENDOR_ID,PRODUCT_ID);
    if (!dev) {
        puts("[-] Failed to connect to Action Replay / GameShark device.");
        puts("[-] Make sure it is connected and you have sufficient privileges.");
        return -4;
    }
    puts("[+] Successfully connected to device.");

    if (libusb_kernel_driver_active(dev, 0))
    {
        puts("[+] Trying to detach active kernel driver ...");
        rc = libusb_detach_kernel_driver(dev, 0);
        if (rc != 0) {
            puts("[-] Failed to detach kernel driver. Fail.");
            return -5;
        }
    }

    rc = libusb_claim_interface(dev, 0);
    if (rc != 0) {
         puts("Failed to claim interface.");
         return -6;
    }

    struct version_info vinfo;
    cmd_get_device_version(dev, &vinfo);

    printf("[+] Device version is %d.%d.\n", vinfo.major, vinfo.minor);

    uint32_t storage = 0;
    cmd_get_device_storage(dev, &storage);
    printf("[+] Remaining device storage is %u bytes.\n", storage);

    struct game_id id = { 0 };
    cmd_get_game_details(dev, &id);
    printf("[+] Current game is %s (%s).\n", id.name, id.id);

    struct sigaction handler;

    handler.sa_handler = cleanup;
    sigemptyset(&handler.sa_mask);
    handler.sa_flags = 0;

    sigaction(SIGINT, &handler, NULL);


    switch (cmd_action) {
        case ACTION_DISCONNECT:
            cmd_disconnect(dev);
        break;
        case ACTION_READ_MEM_WORLD:
            target_file = fopen(arg_mem_file, "wb+");

            if (!target_file) {
                puts("[-] Failed to open memory dump location.");
                return -7;
            }
            read_mem_world(dev, arg_mem_addr, arg_mem_len, arg_mem_world, target_file);
            fclose(target_file);

            cmd_action &= ~ACTION_READ_MEM_WORLD;
        break;
        case ACTION_READ_FIRMWARE:
            target_file = fopen(target_file_name, "wb+");

            if (!target_file) {
                puts("[-] Failed to open firmware dump location.");
                return -7;
            }
            read_firmware(dev, target_file);
            fclose(target_file);

            cmd_action &= ~ACTION_READ_FIRMWARE;
        break;
        case ACTION_READ_CHEATS:
            target_file = fopen(target_file_name, "wb+");

            if (!target_file) {
                puts("[-] Failed to open cheat list location.");
                return -8;
            }
            cmd_read_codes(dev, target_file);
            fclose(target_file);
            cmd_action &= ~ACTION_READ_CHEATS;
        break;
        case ACTION_WRITE_CHEATS:
            target_file = fopen(target_file_name, "rb+");

            if (!target_file) {
                puts("[-] Failed to open cheat list location.");
                return -8;
            }
            cmd_write_codes(dev, target_file);
            fclose(target_file);
            cmd_action &= ~ACTION_WRITE_CHEATS;
        break;
        case ACTION_READ_SAVE:
            target_file = fopen(target_file_name, "wb+");

            if (!target_file) {
                puts("[-] Failed to open save game location.");
                return -9;
            }
            cmd_read_save(dev, target_file);
            fclose(target_file);
            cmd_action &= ~ACTION_READ_SAVE;
        break;
        case ACTION_WRITE_SAVE:
            target_file = fopen(target_file_name, "rb+");

            if (!target_file) {
                puts("[-] Failed to open save game location.");
                return -10;
            }
            cmd_write_save(dev, target_file);
            fclose(target_file);
            cmd_action &= ~ACTION_WRITE_SAVE;
        break;
    }


    rc = libusb_release_interface(dev, 0);
    if (rc != 0) {
         puts("Failed to release interface.");
         return -10;
    }

    libusb_close(dev);

    libusb_exit(context);

    return 0;
}
