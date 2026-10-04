#include <functional>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <cstdlib>
#include <cstdio>

#include "base_host.hpp"
#include "boot_crypto.hpp"
#include "bootimg.hpp"
#include "magiskboot.hpp"

using namespace std;

#define PADDING 15
#define SHA256_DIGEST_SIZE 32
#define SHA_DIGEST_SIZE 20

#define RETURN_OK 0

namespace {
/** When ZYSU_BOOT_INFO_STDOUT is set, boot info goes to stdout for user/manager; else stderr. */
FILE* boot_info_stream() {
    return (std::getenv("ZYSU_BOOT_INFO_STDOUT") != nullptr) ? stdout : stderr;
}
}  // namespace

#define RETURN_OK 0
#define RETURN_ERROR 1
#define RETURN_CHROMEOS 2
#define RETURN_VENDOR 3

static void decompress(FileFormat type, int fd, const void* in, size_t size) {
    decompress_bytes(type, byte_view{in, size}, fd);
}

static off_t compress_len(FileFormat type, byte_view in, int fd) {
    auto prev = lseek(fd, 0, SEEK_CUR);
    compress_bytes(type, in, fd);
    auto now = lseek(fd, 0, SEEK_CUR);
    return now - prev;
}

static void dump(const void* buf, size_t size, const char* filename) {
    if (size == 0)
        return;
    int fd = creat(filename, 0644);
    xwrite(fd, buf, size);
    close(fd);
}

static size_t restore(int fd, const char* filename) {
    int ifd = xopen(filename, O_RDONLY);
    size_t size = lseek(ifd, 0, SEEK_END);
    lseek(ifd, 0, SEEK_SET);
    xsendfile(fd, ifd, nullptr, size);
    close(ifd);
    return size;
}

static bool check_env(const char* name) {
    const char* val = getenv(name);
    return val != nullptr && string_view(val) == "true";
}

static bool guess_lzma(const uint8_t* buf, size_t len) {
    if (len <= 13)
        return false;
    if (memcmp(buf, "\x5d", 1) != 0)
        return false;
    uint32_t dict_sz = 0;
    memcpy(&dict_sz, buf + 1, sizeof(dict_sz));
    if (dict_sz == 0 || (dict_sz & (dict_sz - 1)) != 0)
        return false;
    if (memcmp(buf + 5, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) != 0)
        return false;
    return true;
}

FileFormat check_fmt(const void* buf, size_t len) {
    const uint8_t* b = static_cast<const uint8_t*>(buf);
    if (len >= (sizeof(CHROMEOS_MAGIC) - 1) && BUFFER_MATCH(b, CHROMEOS_MAGIC)) {
        return FileFormat::CHROMEOS;
    } else if (len >= (sizeof(BOOT_MAGIC) - 1) && BUFFER_MATCH(b, BOOT_MAGIC)) {
        return FileFormat::AOSP;
    } else if (len >= (sizeof(VENDOR_BOOT_MAGIC) - 1) && BUFFER_MATCH(b, VENDOR_BOOT_MAGIC)) {
        return FileFormat::AOSP_VENDOR;
    } else if ((len >= (sizeof(GZIP1_MAGIC) - 1) && BUFFER_MATCH(b, GZIP1_MAGIC)) ||
               (len >= (sizeof(GZIP2_MAGIC) - 1) && BUFFER_MATCH(b, GZIP2_MAGIC))) {
        return FileFormat::GZIP;
    } else if (len >= (sizeof(LZOP_MAGIC) - 1) && BUFFER_MATCH(b, LZOP_MAGIC)) {
        return FileFormat::LZOP;
    } else if (len >= (sizeof(XZ_MAGIC) - 1) && BUFFER_MATCH(b, XZ_MAGIC)) {
        return FileFormat::XZ;
    } else if (guess_lzma(b, len)) {
        return FileFormat::LZMA;
    } else if (len >= (sizeof(BZIP_MAGIC) - 1) && BUFFER_MATCH(b, BZIP_MAGIC)) {
        return FileFormat::BZIP2;
    } else if ((len >= (sizeof(LZ41_MAGIC) - 1) && BUFFER_MATCH(b, LZ41_MAGIC)) ||
               (len >= (sizeof(LZ42_MAGIC) - 1) && BUFFER_MATCH(b, LZ42_MAGIC))) {
        return FileFormat::LZ4;
    } else if (len >= (sizeof(LZ4_LEG_MAGIC) - 1) && BUFFER_MATCH(b, LZ4_LEG_MAGIC)) {
        return FileFormat::LZ4_LEGACY;
    } else if (len >= (sizeof(MTK_MAGIC) - 1) && BUFFER_MATCH(b, MTK_MAGIC)) {
        return FileFormat::MTK;
    } else if (len >= (sizeof(DTB_MAGIC) - 1) && BUFFER_MATCH(b, DTB_MAGIC)) {
        return FileFormat::DTB;
    } else if (len >= (sizeof(DHTB_MAGIC) - 1) && BUFFER_MATCH(b, DHTB_MAGIC)) {
        return FileFormat::DHTB;
    } else if (len >= (sizeof(TEGRABLOB_MAGIC) - 1) && BUFFER_MATCH(b, TEGRABLOB_MAGIC)) {
        return FileFormat::BLOB;
    } else if (len >= 0x28 &&
               memcmp(&(static_cast<const char*>(buf))[0x24], ZIMAGE_MAGIC, 4) == 0) {
        return FileFormat::ZIMAGE;
    } else {
        return FileFormat::UNKNOWN;
    }
}

void dyn_img_hdr::print() const {
    FILE* out = boot_info_stream();
    uint32_t ver = header_version();
    fprintf(out, "%-*s [%u]\n", PADDING, "HEADER_VER", ver);
    if (!is_vendor())
        fprintf(out, "%-*s [%u]\n", PADDING, "KERNEL_SZ", kernel_size());
    fprintf(out, "%-*s [%u]\n", PADDING, "RAMDISK_SZ", ramdisk_size());
    if (ver < 3)
        fprintf(out, "%-*s [%u]\n", PADDING, "SECOND_SZ", second_size());
    if (ver == 0)
        fprintf(out, "%-*s [%u]\n", PADDING, "EXTRA_SZ", extra_size());
    if (ver == 1 || ver == 2)
        fprintf(out, "%-*s [%u]\n", PADDING, "RECOV_DTBO_SZ", recovery_dtbo_size());
    if (ver == 2 || is_vendor())
        fprintf(out, "%-*s [%u]\n", PADDING, "DTB_SZ", dtb_size());
    if (ver == 4 && is_vendor())
        fprintf(out, "%-*s [%u]\n", PADDING, "BOOTCONFIG_SZ", bootconfig_size());

    if (uint32_t os_ver = os_version()) {
        int a, b, c, y, m = 0;
        int version = os_ver >> 11;
        int patch_level = os_ver & 0x7ff;

        a = (version >> 14) & 0x7f;
        b = (version >> 7) & 0x7f;
        c = version & 0x7f;
        fprintf(out, "%-*s [%d.%d.%d]\n", PADDING, "OS_VERSION", a, b, c);

        y = (patch_level >> 4) + 2000;
        m = patch_level & 0xf;
        fprintf(out, "%-*s [%d-%02d]\n", PADDING, "OS_PATCH_LEVEL", y, m);
    }

    fprintf(out, "%-*s [%u]\n", PADDING, "PAGESIZE", page_size());
    if (const char* n = name()) {
        fprintf(out, "%-*s [%s]\n", PADDING, "NAME", n);
    }
    fprintf(out, "%-*s [%.*s%.*s]\n", PADDING, "CMDLINE", static_cast<int>(BOOT_ARGS_SIZE),
            cmdline(), static_cast<int>(BOOT_EXTRA_ARGS_SIZE), extra_cmdline());
    if (const char* checksum = id()) {
        fprintf(out, "%-*s [", PADDING, "CHECKSUM");
        for (int i = 0; i < SHA256_DIGEST_SIZE; ++i)
            fprintf(out, "%02hhx", checksum[i]);
        fprintf(out, "]\n");
    }
}

void dyn_img_hdr::dump_hdr_file() const {
    FILE* fp = xfopen(HEADER_FILE, "w");
    if (name())
        fprintf(fp, "name=%s\n", name());
    fprintf(fp, "cmdline=%.*s%.*s\n", static_cast<int>(BOOT_ARGS_SIZE), cmdline(),
            static_cast<int>(BOOT_EXTRA_ARGS_SIZE), extra_cmdline());
    uint32_t ver = os_version();
    if (ver) {
        int a, b, c, y, m;
        int version, patch_level;
        version = ver >> 11;
        patch_level = ver & 0x7ff;

        a = (version >> 14) & 0x7f;
        b = (version >> 7) & 0x7f;
        c = version & 0x7f;
        fprintf(fp, "os_version=%d.%d.%d\n", a, b, c);

        y = (patch_level >> 4) + 2000;
        m = patch_level & 0xf;
        fprintf(fp, "os_patch_level=%d-%02d\n", y, m);
    }
    fclose(fp);
}

void dyn_img_hdr::load_hdr_file() {
    parse_prop_file(HEADER_FILE, [this](string_view key, string_view value) -> bool {
        if (key == "name" && name()) {
            memset(name(), 0, 16);
            memcpy(name(), value.data(), value.size() > 15 ? 15 : value.size());
        } else if (key == "cmdline") {
            memset(cmdline(), 0, BOOT_ARGS_SIZE);
            memset(extra_cmdline(), 0, BOOT_EXTRA_ARGS_SIZE);
            if (value.size() > BOOT_ARGS_SIZE) {
                memcpy(cmdline(), value.data(), BOOT_ARGS_SIZE);
                auto len =
                    min(value.size() - BOOT_ARGS_SIZE, static_cast<size_t>(BOOT_EXTRA_ARGS_SIZE));
                memcpy(extra_cmdline(), value.data() + BOOT_ARGS_SIZE, len);
            } else {
                memcpy(cmdline(), value.data(), value.size());
            }
        } else if (key == "os_version") {
            int patch_level = os_version() & 0x7ff;
            int a, b, c;
            sscanf(value.data(), "%d.%d.%d", &a, &b, &c);
            set_os_version((((a << 14) | (b << 7) | c) << 11) | patch_level);
        } else if (key == "os_patch_level") {
            int os_ver = os_version() >> 11;
            int y, m;
            sscanf(value.data(), "%d-%d", &y, &m);
            y -= 2000;
            set_os_version((os_ver << 11) | (y << 4) | m);
        }
        return true;
    });
}

boot_img::boot_img(const char* image)
    : map(image),
      k_fmt(FileFormat::UNKNOWN),
      r_fmt(FileFormat::UNKNOWN),
      e_fmt(FileFormat::UNKNOWN) {
    fprintf(stdout, "Parsing boot image: [%s]\n", image);
    for (const uint8_t* addr = map.data(); addr < map.data() + map.size(); ++addr) {
        FileFormat fmt = check_fmt(addr, map.size() - (addr - map.data()));
        switch (fmt) {
        case FileFormat::CHROMEOS:
            flags[CHROMEOS_FLAG] = true;
            addr += 65535;
            break;
        case FileFormat::DHTB:
            flags[DHTB_FLAG] = true;
            flags[SEANDROID_FLAG] = true;
            fprintf(stdout, "DHTB_HDR\n");
            addr += sizeof(dhtb_hdr) - 1;
            break;
        case FileFormat::BLOB:
            flags[BLOB_FLAG] = true;
            fprintf(stdout, "TEGRA_BLOB\n");
            addr += sizeof(blob_hdr) - 1;
            break;
        case FileFormat::AOSP:
        case FileFormat::AOSP_VENDOR:
            if (parse_image(addr, fmt))
                return;
            [[fallthrough]];
        default:
            break;
        }
    }
    throw std::runtime_error("unsupported or invalid boot image");
}

boot_img::~boot_img() {
    delete hdr;
}

struct __attribute__((packed)) fdt_header {
    struct fdt32_t {
        uint32_t byte0 : 8;
        uint32_t byte1 : 8;
        uint32_t byte2 : 8;
        uint32_t byte3 : 8;

        constexpr operator uint32_t() const {
            return (static_cast<uint32_t>(byte3) << 24) | (static_cast<uint32_t>(byte2) << 16) |
                   (static_cast<uint32_t>(byte1) << 8) | static_cast<uint32_t>(byte0);
        }
    };

    struct node_header {
        fdt32_t tag;
        char name[0];
    };

    fdt32_t magic;
    fdt32_t totalsize;
    fdt32_t off_dt_struct;
    fdt32_t off_dt_strings;
    fdt32_t off_mem_rsvmap;
    fdt32_t version;
    fdt32_t last_comp_version;
    fdt32_t boot_cpuid_phys;
    fdt32_t size_dt_strings;
    fdt32_t size_dt_struct;
};

static int find_dtb_offset(const uint8_t* buf, unsigned sz) {
    const uint8_t* const end = buf + sz;

    for (auto curr = buf; curr < end; curr += sizeof(fdt_header)) {
        curr =
            static_cast<uint8_t*>(memmem(curr, end - curr, DTB_MAGIC, sizeof(fdt_header::fdt32_t)));
        if (curr == nullptr)
            return -1;

        auto fdt_hdr = reinterpret_cast<const fdt_header*>(curr);

        uint32_t totalsize = fdt_hdr->totalsize;
        if (totalsize > end - curr || totalsize <= 0x48)
            continue;

        uint32_t off_dt_struct = fdt_hdr->off_dt_struct;
        if (off_dt_struct > end - curr)
            continue;

        auto fdt_node_hdr = reinterpret_cast<const fdt_header::node_header*>(curr + off_dt_struct);
        if (fdt_node_hdr->tag != 0x1u)
            continue;

        return curr - buf;
    }
    return -1;
}

FileFormat check_fmt_lg(const uint8_t* buf, unsigned sz) {
    FileFormat fmt = check_fmt(buf, sz);
    if (fmt == FileFormat::LZ4_LEGACY) {
        uint32_t off = 4;
        uint32_t block_sz;
        while (off + sizeof(block_sz) <= sz) {
            memcpy(&block_sz, buf + off, sizeof(block_sz));
            off += sizeof(block_sz);
            if (off + block_sz > sz)
                return FileFormat::LZ4_LG;
            off += block_sz;
        }
    }
    return fmt;
}

#define CMD_MATCH(s) BUFFER_MATCH((h)->cmdline.data(), (s))

const uint8_t* boot_img::parse_hdr(const uint8_t* addr, FileFormat type) {
    if (type == FileFormat::AOSP_VENDOR) {
        fprintf(stdout, "VENDOR_BOOT_HDR\n");
        auto h = reinterpret_cast<const boot_img_hdr_vnd_v3*>(addr);
        switch (h->header_version) {
        case 4:
            hdr = new dyn_img_vnd_v4(addr);
            break;
        default:
            hdr = new dyn_img_vnd_v3(addr);
            break;
        }
        return addr;
    }

    auto h = reinterpret_cast<const boot_img_hdr_v0*>(addr);

    if (h->page_size >= 0x02000000) {
        fprintf(stdout, "PXA_BOOT_HDR\n");
        hdr = new dyn_img_pxa(addr);
        return addr;
    }

    auto make_aosp_hdr = [](const uint8_t* ptr, ssize_t size = -1) -> dyn_img_hdr* {
        auto h0 = reinterpret_cast<const boot_img_hdr_v0*>(ptr);
        if (memcmp(h0->magic.data(), BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0)
            return nullptr;

        switch (h0->header_version) {
        case 1:
            return new dyn_img_v1(ptr, size);
        case 2:
            return new dyn_img_v2(ptr, size);
        case 3:
            return new dyn_img_v3(ptr, size);
        case 4:
            return new dyn_img_v4(ptr, size);
        default:
            return new dyn_img_v0(ptr, size);
        }
    };

    if (BUFFER_CONTAIN(addr, AMONET_MICROLOADER_SZ, AMONET_MICROLOADER_MAGIC) &&
        BUFFER_MATCH(addr + AMONET_MICROLOADER_SZ, BOOT_MAGIC)) {
        flags[AMONET_FLAG] = true;
        fprintf(stdout, "AMONET_MICROLOADER\n");

        h = reinterpret_cast<const boot_img_hdr_v0*>(addr + AMONET_MICROLOADER_SZ);
        auto real_hdr_sz = h->page_size - AMONET_MICROLOADER_SZ;
        hdr = make_aosp_hdr(addr + AMONET_MICROLOADER_SZ, real_hdr_sz);
        return addr;
    }

    if (CMD_MATCH(NOOKHD_RL_MAGIC) || CMD_MATCH(NOOKHD_GL_MAGIC) || CMD_MATCH(NOOKHD_GR_MAGIC) ||
        CMD_MATCH(NOOKHD_EB_MAGIC) || CMD_MATCH(NOOKHD_ER_MAGIC)) {
        flags[NOOKHD_FLAG] = true;
        fprintf(stdout, "NOOKHD_LOADER\n");
        addr += NOOKHD_PRE_HEADER_SZ;
    } else if (BUFFER_MATCH(h->name.data(), ACCLAIM_MAGIC)) {
        flags[ACCLAIM_FLAG] = true;
        fprintf(stdout, "ACCLAIM_LOADER\n");
        addr += ACCLAIM_PRE_HEADER_SZ;
    }

    hdr = make_aosp_hdr(addr);
    return addr;
}

void boot_img::parse_zimage() {
    z_info.hdr = reinterpret_cast<const zimage_hdr*>(kernel);

    const uint8_t* piggy = nullptr;
    for (const uint8_t* curr = kernel + 0x28; curr < kernel + hdr->kernel_size(); curr++) {
        if (check_fmt_lg(curr, hdr->kernel_size() - (curr - kernel)) != FileFormat::UNKNOWN) {
            piggy = curr;
            break;
        }
    }

    if (piggy != nullptr) {
        fprintf(stdout, "ZIMAGE_KERNEL\n");
        z_info.hdr_sz = piggy - kernel;

        uint32_t piggy_size = z_info.hdr->end - z_info.hdr->start;
        uint32_t piggy_end = piggy_size;
        uint32_t offsets[16];
        memcpy(offsets, kernel + piggy_size - sizeof(offsets), sizeof(offsets));
        for (int i = 15; i >= 0; --i) {
            if (offsets[i] > (piggy_size - 0xFF) && offsets[i] < piggy_size) {
                piggy_end = offsets[i];
                break;
            }
        }

        if (piggy_end == piggy_size) {
            fprintf(stdout, "! Could not find end of zImage piggy, keeping raw kernel\n");
        } else {
            flags[ZIMAGE_KERNEL] = true;
            z_info.tail = byte_view(kernel + piggy_end, hdr->kernel_size() - piggy_end);
            kernel += z_info.hdr_sz;
            hdr->set_kernel_size(piggy_end - z_info.hdr_sz);
            k_fmt = check_fmt_lg(kernel, hdr->kernel_size());
        }
    } else {
        fprintf(stdout, "! Could not find zImage piggy, keeping raw kernel\n");
    }
}

static const char* vendor_ramdisk_type(int type) {
    switch (type) {
    case VENDOR_RAMDISK_TYPE_PLATFORM:
        return "platform";
    case VENDOR_RAMDISK_TYPE_RECOVERY:
        return "recovery";
    case VENDOR_RAMDISK_TYPE_DLKM:
        return "dlkm";
    case VENDOR_RAMDISK_TYPE_NONE:
    default:
        return "none";
    }
}

boot_img::vendor_ramdisk_table_view boot_img::vendor_ramdisk_tbl() const {
    if (hdr->vendor_ramdisk_table_size() == 0) {
        return {};
    }

    using table_entry = const vendor_ramdisk_table_entry_v4;
    if (hdr->vendor_ramdisk_table_entry_size() != sizeof(table_entry)) {
        fprintf(stdout, "! Invalid vendor image: vendor_ramdisk_table_entry_size != %zu\n",
                sizeof(table_entry));
        throw std::runtime_error("invalid vendor ramdisk table");
    }
    return {
        reinterpret_cast<table_entry*>(const_cast<uint8_t*>(vendor_ramdisk_table)),
        static_cast<std::size_t>(hdr->vendor_ramdisk_table_entry_num()),
    };
}

bool boot_img::verify(const char *cert_pem_path) const {
    return avb_verify_boot_signature(tail, payload, cert_pem_path);
}

int verify_boot_image(const char *img_path, const char *cert_pem_path) {
    const boot_img boot(img_path);
    return boot.verify(cert_pem_path) ? 0 : 1;
}

int sign_boot_image_cmd(const char *img_path, const char *name,
                        const char *cert_pem_path, const char *key_pem_path) {
    if (!cert_pem_path || !key_pem_path) {
        fprintf(stderr, "sign requires x509.pem and pk8 key paths\n");
        return 1;
    }
    const boot_img boot(img_path);
    std::vector<std::uint8_t> sig =
        avb_sign_boot_image(boot.payload, name ? name : "/boot", cert_pem_path, key_pem_path);
    if (sig.empty()) {
        fprintf(stderr, "sign: failed to produce signature\n");
        return 1;
    }
    int fd = xopen(img_path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "sign: cannot open image for write\n");
        return 1;
    }
    off_t tail_off = static_cast<off_t>(boot.tail_off());
    if (lseek(fd, tail_off, SEEK_SET) != tail_off) {
        fprintf(stderr, "sign: seek failed\n");
        close(fd);
        return 1;
    }
    ssize_t nw = write(fd, sig.data(), sig.size());
    if (nw != static_cast<ssize_t>(sig.size())) {
        fprintf(stderr, "sign: write failed\n");
        close(fd);
        return 1;
    }
    off_t cur = lseek(fd, 0, SEEK_CUR);
    off_t eof = lseek(fd, 0, SEEK_END);
    if (eof > cur) {
        lseek(fd, cur, SEEK_SET);
        std::vector<char> zeros(4096, 0);
        for (off_t remain = eof - cur; remain > 0;) {
            size_t chunk = static_cast<size_t>(std::min(remain, static_cast<off_t>(zeros.size())));
            if (write(fd, zeros.data(), chunk) != static_cast<ssize_t>(chunk)) break;
            remain -= chunk;
        }
    }
    close(fd);
    return 0;
}

#define assert_off()                                \
    if ((addr + off) > (map.data() + map_end)) {    \
        fprintf(stdout, "Corrupted boot image!\n"); \
        return false;                               \
    }

#define get_block(name)                    \
    name = addr + off;                     \
    off += hdr->name##_size();             \
    off = align_to(off, hdr->page_size()); \
    assert_off()

bool boot_img::parse_image(const uint8_t* addr, FileFormat type) {
    addr = parse_hdr(addr, type);
    if (hdr == nullptr) {
        fprintf(stdout, "Invalid boot image header!\n");
        return false;
    }

    if (const char* id = hdr->id()) {
        for (int i = SHA_DIGEST_SIZE + 4; i < SHA256_DIGEST_SIZE; ++i) {
            if (id[i]) {
                flags[SHA256_FLAG] = true;
                break;
            }
        }
    }

    hdr->print();

    size_t map_end = align_to(map.size(), getpagesize());
    size_t off = hdr->hdr_space();
    get_block(kernel);
    get_block(ramdisk);
    get_block(second);
    get_block(extra);
    get_block(recovery_dtbo);
    get_block(dtb);
    get_block(signature);
    get_block(vendor_ramdisk_table);
    get_block(bootconfig);

    payload = byte_view(addr, off);
    auto tail_addr = addr + off;
    tail = byte_view(tail_addr, map.data() + map_end - tail_addr);

    if (auto size = hdr->kernel_size()) {
        if (int dtb_off = find_dtb_offset(kernel, size); dtb_off > 0) {
            kernel_dtb = byte_view(kernel + dtb_off, size - dtb_off);
            hdr->set_kernel_size(dtb_off);
            fprintf(stdout, "%-*s [%zu]\n", PADDING, "KERNEL_DTB_SZ", kernel_dtb.size());
        }

        k_fmt = check_fmt_lg(kernel, hdr->kernel_size());
        if (k_fmt == FileFormat::MTK) {
            fprintf(stdout, "MTK_KERNEL_HDR\n");
            flags[MTK_KERNEL] = true;
            k_hdr = reinterpret_cast<const mtk_hdr*>(kernel);
            fprintf(stdout, "%-*s [%u]\n", PADDING, "SIZE", k_hdr->size);
            fprintf(stdout, "%-*s [%s]\n", PADDING, "NAME", k_hdr->name.data());
            kernel += sizeof(mtk_hdr);
            hdr->set_kernel_size(hdr->kernel_size() - sizeof(mtk_hdr));
            k_fmt = check_fmt_lg(kernel, hdr->kernel_size());
        }
        if (k_fmt == FileFormat::ZIMAGE) {
            parse_zimage();
        }
        fprintf(stdout, "%-*s [%s]\n", PADDING, "KERNEL_FMT", fmt2name(k_fmt));
    }
    if (auto size = hdr->ramdisk_size()) {
        if (hdr->vendor_ramdisk_table_size()) {
            for (auto& it : vendor_ramdisk_tbl()) {
                FileFormat fmt = check_fmt_lg(ramdisk + it.ramdisk_offset, it.ramdisk_size);
                fprintf(stdout, "%-*s name=[%s] type=[%s] size=[%u] fmt=[%s]\n", PADDING,
                        "VND_RAMDISK", it.ramdisk_name.data(), vendor_ramdisk_type(it.ramdisk_type),
                        it.ramdisk_size, fmt2name(fmt));
            }
        } else {
            r_fmt = check_fmt_lg(ramdisk, size);
            if (r_fmt == FileFormat::MTK) {
                fprintf(stdout, "MTK_RAMDISK_HDR\n");
                flags[MTK_RAMDISK] = true;
                r_hdr = reinterpret_cast<const mtk_hdr*>(ramdisk);
                fprintf(stdout, "%-*s [%u]\n", PADDING, "SIZE", r_hdr->size);
                fprintf(stdout, "%-*s [%s]\n", PADDING, "NAME", r_hdr->name.data());
                ramdisk += sizeof(mtk_hdr);
                hdr->set_ramdisk_size(hdr->ramdisk_size() - sizeof(mtk_hdr));
                r_fmt = check_fmt_lg(ramdisk, hdr->ramdisk_size());
            }
            fprintf(stdout, "%-*s [%s]\n", PADDING, "RAMDISK_FMT", fmt2name(r_fmt));
        }
    }
    if (auto size = hdr->extra_size()) {
        e_fmt = check_fmt_lg(extra, size);
        fprintf(stdout, "%-*s [%s]\n", PADDING, "EXTRA_FMT", fmt2name(e_fmt));
    }

    if (tail.size()) {
        // Check special flags
        if (tail.size() >= 16 && BUFFER_MATCH(tail.data(), SEANDROID_MAGIC)) {
            fprintf(stdout, "SAMSUNG_SEANDROID\n");
            flags[SEANDROID_FLAG] = true;
        } else if (tail.size() >= 16 && BUFFER_MATCH(tail.data(), LG_BUMP_MAGIC)) {
            fprintf(stdout, "LG_BUMP_IMAGE\n");
            flags[LG_BUMP_FLAG] = true;
        } else if (verify()) {
            fprintf(stdout, "AVB1_SIGNED\n");
            flags[AVB1_SIGNED_FLAG] = true;
        }

        // Find an AVB footer at the real file end, then validate its
        // attacker-controlled metadata range before dereferencing it.
        if (map.size() >= sizeof(AvbFooter)) {
            const auto* footer = reinterpret_cast<const AvbFooter*>(
                map.data() + map.size() - sizeof(AvbFooter));
            if (BUFFER_MATCH(footer, AVB_FOOTER_MAGIC)) {
                const std::uint64_t meta_offset =
                    __builtin_bswap64(footer->vbmeta_offset);
                const std::uint64_t meta_size =
                    __builtin_bswap64(footer->vbmeta_size);
                const std::size_t payload_offset =
                    static_cast<std::size_t>(
                        payload.data() - map.data());
                if (payload_offset <= map.size() &&
                    meta_offset <= map.size() - payload_offset &&
                    meta_size >= sizeof(AvbVBMetaImageHeader) &&
                    meta_size <=
                        map.size() - payload_offset - meta_offset) {
                    const auto* meta =
                        payload.data() +
                        static_cast<std::size_t>(meta_offset);
                    if (BUFFER_MATCH(meta, AVB_MAGIC)) {
                        fprintf(stdout, "VBMETA\n");
                        flags[AVB_FLAG] = true;
                        avb_footer = footer;
                        vbmeta = reinterpret_cast<
                            const AvbVBMetaImageHeader*>(meta);
                    }
                }
            }
        }
    }

    return true;
}

int split_image_dtb(Utf8CStr filename, bool skip_decomp) {
    mmap_data img(filename.c_str());

    if (int offset = find_dtb_offset(img.data(), img.size()); offset > 0) {
        size_t off = (size_t)offset;

        FileFormat fmt = check_fmt_lg(img.data(), img.size());
        if (!skip_decomp && fmt_compressed(fmt)) {
            int fd = creat(KERNEL_FILE, 0644);
            decompress(fmt, fd, img.data(), off);
            close(fd);
        } else {
            dump(img.data(), off, KERNEL_FILE);
        }
        dump(img.data() + off, img.size() - off, KER_DTB_FILE);
        return 0;
    } else {
        fprintf(stdout, "Cannot find DTB in %s\n", filename.c_str());
        return 1;
    }
}

int unpack(Utf8CStr image, bool skip_decomp, bool hdr) {
    const boot_img boot(image.c_str());

    if (hdr)
        boot.hdr->dump_hdr_file();

    // Dump kernel
    if (!skip_decomp && fmt_compressed(boot.k_fmt)) {
        if (boot.hdr->kernel_size() != 0) {
            int fd = creat(KERNEL_FILE, 0644);
            decompress(boot.k_fmt, fd, boot.kernel, boot.hdr->kernel_size());
            close(fd);
        }
    } else {
        dump(boot.kernel, boot.hdr->kernel_size(), KERNEL_FILE);
    }

    // Dump kernel_dtb
    dump(boot.kernel_dtb.data(), boot.kernel_dtb.size(), KER_DTB_FILE);

    // Dump ramdisk
    if (boot.hdr->vendor_ramdisk_table_size()) {
        xmkdir(VND_RAMDISK_DIR, 0755);
        owned_fd dirfd = owned_fd(xopen(VND_RAMDISK_DIR, O_RDONLY | O_CLOEXEC));
        for (auto& it : boot.vendor_ramdisk_tbl()) {
            char file_name[40];
            if (it.ramdisk_name[0] == '\0') {
                strscpy(file_name, RAMDISK_FILE, sizeof(file_name));
            } else {
                ssprintf(file_name, sizeof(file_name), "%.*s.cpio",
                         static_cast<int>(it.ramdisk_name.size()), it.ramdisk_name.data());
            }
            owned_fd fd =
                owned_fd(xopenat(dirfd, file_name, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644));
            FileFormat fmt = check_fmt_lg(boot.ramdisk + it.ramdisk_offset, it.ramdisk_size);
            if (!skip_decomp && fmt_compressed(fmt)) {
                decompress(fmt, fd, boot.ramdisk + it.ramdisk_offset, it.ramdisk_size);
            } else {
                xwrite(fd, boot.ramdisk + it.ramdisk_offset, it.ramdisk_size);
            }
        }
    } else if (!skip_decomp && fmt_compressed(boot.r_fmt)) {
        if (boot.hdr->ramdisk_size() != 0) {
            int fd = creat(RAMDISK_FILE, 0644);
            decompress(boot.r_fmt, fd, boot.ramdisk, boot.hdr->ramdisk_size());
            close(fd);
        }
    } else {
        dump(boot.ramdisk, boot.hdr->ramdisk_size(), RAMDISK_FILE);
    }

    // Dump second
    dump(boot.second, boot.hdr->second_size(), SECOND_FILE);

    // Dump extra
    if (!skip_decomp && fmt_compressed(boot.e_fmt)) {
        if (boot.hdr->extra_size() != 0) {
            int fd = creat(EXTRA_FILE, 0644);
            decompress(boot.e_fmt, fd, boot.extra, boot.hdr->extra_size());
            close(fd);
        }
    } else {
        dump(boot.extra, boot.hdr->extra_size(), EXTRA_FILE);
    }

    // Dump recovery_dtbo
    dump(boot.recovery_dtbo, boot.hdr->recovery_dtbo_size(), RECV_DTBO_FILE);

    // Dump dtb
    dump(boot.dtb, boot.hdr->dtb_size(), DTB_FILE);

    // Dump bootconfig
    dump(boot.bootconfig, boot.hdr->bootconfig_size(), BOOTCONFIG_FILE);

    if (boot.flags[CHROMEOS_FLAG])
        return RETURN_CHROMEOS;
    if (boot.hdr->is_vendor())
        return RETURN_VENDOR;
    return RETURN_OK;
}

// Safe align: only pad when current >= header to avoid underflow (lseek error or bad offsets).
// When pre_allocated, skip write_zero and just lseek—the file is already the right size.
static void do_file_align_with(int fd, uint32_t header_off, int page_size, bool pre_allocated) {
    off_t cur = lseek(fd, 0, SEEK_CUR);
    if (cur < 0 || static_cast<uint64_t>(cur) < header_off)
        return;
    size_t pad = align_padding(static_cast<size_t>(cur - header_off), page_size);
    if (pad > 0) {
        if (pre_allocated) {
            lseek(fd, static_cast<off_t>(pad), SEEK_CUR);
        } else {
            write_zero(fd, pad);
        }
    }
}

#define file_align_with(page_size) do_file_align_with(fd, off.header, (page_size), pre_allocated)

#define file_align() file_align_with(boot.hdr->page_size())

// Boot images are typically 32-128MB; refuse if source is suspiciously large (corrupted/artifact)
constexpr size_t MAX_REASONABLE_BOOT_SIZE = 256 * 1024 * 1024;

void repack(Utf8CStr src_img, Utf8CStr out_img, bool skip_comp) {
    const boot_img boot(src_img.c_str());
    if (boot.map.size() > MAX_REASONABLE_BOOT_SIZE) {
        fprintf(stdout,
                "repack: source image size %zu exceeds %zu, refusing (possible corrupted "
                "or previous-run artifact)\n",
                boot.map.size(), MAX_REASONABLE_BOOT_SIZE);
        return;
    }
    fprintf(stdout, "Repack to boot image: [%s], src_size=%zu\n", out_img.c_str(), boot.map.size());
    fflush(stderr);

    struct {
        uint32_t header;
        uint32_t kernel;
        uint32_t ramdisk;
        uint32_t second;
        uint32_t extra;
        uint32_t dtb;
        uint32_t tail;
        uint32_t vbmeta;
    } off{};

    // Create a new boot header and reset sizes
    auto hdr = boot.hdr->clone();
    hdr->set_kernel_size(0);
    hdr->set_ramdisk_size(0);
    hdr->set_second_size(0);
    hdr->set_dtb_size(0);
    hdr->set_bootconfig_size(0);

    if (access(HEADER_FILE, R_OK) == 0)
        hdr->load_hdr_file();

    /***************
     * Write blocks
     ***************/

    // Create new image
    int fd = open(out_img.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);

    // Pre-allocate to original size (avoids pad subtraction and underflow entirely).
    // When pre_allocated, file_align uses lseek instead of write_zero.
    // ChromeOS requires post-processing, so skip pre-allocate there.
    bool pre_allocated = false;
    if (!boot.flags[CHROMEOS_FLAG] && boot.map.size() > 0) {
        if (ftruncate(fd, static_cast<off_t>(boot.map.size())) != 0) {
            fprintf(stdout, "repack: ftruncate to %zu failed: %s\n", boot.map.size(), strerror(errno));
            delete hdr;
            close(fd);
            return;
        }
        pre_allocated = true;
        off_t sz = lseek(fd, 0, SEEK_END);
        fprintf(stdout, "repack: pre-allocated %zu, lseek(END)=%lld\n", boot.map.size(),
                static_cast<long long>(sz));
        fflush(stderr);
        lseek(fd, 0, SEEK_SET);
    }

    // Copy non-standard headers
    if (boot.flags[DHTB_FLAG]) {
        xwrite(fd, boot.map.data(), sizeof(dhtb_hdr));
    } else if (boot.flags[BLOB_FLAG]) {
        xwrite(fd, boot.map.data(), sizeof(blob_hdr));
    } else if (boot.flags[NOOKHD_FLAG]) {
        xwrite(fd, boot.map.data(), NOOKHD_PRE_HEADER_SZ);
    } else if (boot.flags[ACCLAIM_FLAG]) {
        xwrite(fd, boot.map.data(), ACCLAIM_PRE_HEADER_SZ);
    }

    // Copy raw header
    off.header = lseek(fd, 0, SEEK_CUR);
    xwrite(fd, boot.payload.data(), hdr->hdr_space());

    // kernel
    off.kernel = lseek(fd, 0, SEEK_CUR);
    fprintf(stdout, "repack: writing kernel at %u\n", off.kernel);
    fflush(stderr);
    if (boot.flags[MTK_KERNEL]) {
        // Copy MTK headers
        xwrite(fd, boot.k_hdr, sizeof(mtk_hdr));
    }
    if (boot.flags[ZIMAGE_KERNEL]) {
        // Copy zImage headers
        xwrite(fd, boot.z_info.hdr, boot.z_info.hdr_sz);
    }
    if (access(KERNEL_FILE, R_OK) == 0) {
        mmap_data m(KERNEL_FILE);
        if (!skip_comp && !fmt_compressed_any(check_fmt(m.data(), m.size())) &&
            fmt_compressed(boot.k_fmt)) {
            auto fmt = (boot.flags[ZIMAGE_KERNEL] && boot.k_fmt == FileFormat::GZIP)
                           ? FileFormat::ZOPFLI
                           : boot.k_fmt;
            hdr->set_kernel_size(compress_len(fmt, byte_view(m.data(), m.size()), fd));
        } else {
            hdr->set_kernel_size(xwrite(fd, m.data(), m.size()));
        }

        if (boot.flags[ZIMAGE_KERNEL]) {
            if (hdr->kernel_size() > boot.hdr->kernel_size()) {
                fprintf(stdout, "! Recompressed kernel is too large, using original kernel\n");
                ftruncate(fd, lseek(fd, -static_cast<off_t>(hdr->kernel_size()), SEEK_CUR));
                xwrite(fd, boot.kernel, boot.hdr->kernel_size());
            } else if (!skip_comp) {
                // Pad zeros to make sure the zImage file size does not change
                // Also ensure the last 4 bytes are the uncompressed vmlinux size
                uint32_t sz = m.size();
                const uint32_t need = hdr->kernel_size() + sizeof(sz);
                if (boot.hdr->kernel_size() >= need) {
                    write_zero(fd, boot.hdr->kernel_size() - need);
                }
                xwrite(fd, &sz, sizeof(sz));
            }

            // zImage size shall remain the same
            hdr->set_kernel_size(boot.hdr->kernel_size());
        }
    } else if (boot.hdr->kernel_size() != 0) {
        xwrite(fd, boot.kernel, boot.hdr->kernel_size());
        hdr->set_kernel_size(boot.hdr->kernel_size());
    }
    if (boot.flags[ZIMAGE_KERNEL]) {
        // Copy zImage tail and adjust size accordingly
        hdr->set_kernel_size(hdr->kernel_size() + boot.z_info.hdr_sz);
        hdr->set_kernel_size(hdr->kernel_size() +
                             xwrite(fd, boot.z_info.tail.data(), boot.z_info.tail.size()));
    }

    // kernel dtb
    if (access(KER_DTB_FILE, R_OK) == 0)
        hdr->set_kernel_size(hdr->kernel_size() + restore(fd, KER_DTB_FILE));
    file_align();

    // ramdisk
    off.ramdisk = lseek(fd, 0, SEEK_CUR);
    fprintf(stdout, "repack: writing ramdisk at %u\n", off.ramdisk);
    fflush(stderr);
    if (boot.flags[MTK_RAMDISK]) {
        // Copy MTK headers
        xwrite(fd, boot.r_hdr, sizeof(mtk_hdr));
    }

    vector<vendor_ramdisk_table_entry_v4> ramdisk_table;

    if (boot.hdr->vendor_ramdisk_table_size()) {
        // Create a copy so we can modify it
        auto tbl = boot.vendor_ramdisk_tbl();
        ramdisk_table.assign(tbl.begin(), tbl.end());

        owned_fd dirfd = owned_fd(xopen(VND_RAMDISK_DIR, O_RDONLY | O_CLOEXEC));
        uint32_t ramdisk_offset = 0;
        for (auto& it : ramdisk_table) {
            char file_name[64];
            if (it.ramdisk_name[0] == '\0') {
                strscpy(file_name, RAMDISK_FILE, sizeof(file_name));
            } else {
                ssprintf(file_name, sizeof(file_name), "%.*s.cpio",
                         static_cast<int>(it.ramdisk_name.size()), it.ramdisk_name.data());
            }
            mmap_data m(dirfd, file_name);
            FileFormat fmt = check_fmt_lg(boot.ramdisk + it.ramdisk_offset, it.ramdisk_size);
            it.ramdisk_offset = ramdisk_offset;
            if (!skip_comp && !fmt_compressed_any(check_fmt(m.data(), m.size())) &&
                fmt_compressed(fmt)) {
                it.ramdisk_size = compress_len(fmt, byte_view(m.data(), m.size()), fd);
            } else {
                it.ramdisk_size = xwrite(fd, m.data(), m.size());
            }
            ramdisk_offset += it.ramdisk_size;
        }

        hdr->set_ramdisk_size(ramdisk_offset);
        file_align();
    } else if (access(RAMDISK_FILE, R_OK) == 0) {
        mmap_data m(RAMDISK_FILE);
        auto r_fmt = boot.r_fmt;
        if (!skip_comp && !hdr->is_vendor() && hdr->header_version() == 4 &&
            r_fmt != FileFormat::LZ4_LEGACY) {
            // A v4 boot image ramdisk will have to be merged with other vendor ramdisks,
            // and they have to use the exact same compression method. v4 GKIs are required to
            // use lz4 (legacy), so hardcode the format here.
            fprintf(stdout, "RAMDISK_FMT: [%s] -> [%s]\n", fmt2name(r_fmt),
                    fmt2name(FileFormat::LZ4_LEGACY));
            r_fmt = FileFormat::LZ4_LEGACY;
        }
        if (!skip_comp && !fmt_compressed_any(check_fmt(m.data(), m.size())) &&
            fmt_compressed(r_fmt)) {
            hdr->set_ramdisk_size(compress_len(r_fmt, byte_view(m.data(), m.size()), fd));
        } else {
            hdr->set_ramdisk_size(xwrite(fd, m.data(), m.size()));
        }
        file_align();
    }

    // second
    off.second = lseek(fd, 0, SEEK_CUR);
    fprintf(stdout, "repack: writing second at %u\n", off.second);
    fflush(stderr);
    if (access(SECOND_FILE, R_OK) == 0) {
        hdr->set_second_size(restore(fd, SECOND_FILE));
        file_align();
    }

    // extra
    off.extra = lseek(fd, 0, SEEK_CUR);
    fprintf(stdout, "repack: writing extra at %u\n", off.extra);
    fflush(stderr);
    if (access(EXTRA_FILE, R_OK) == 0) {
        mmap_data m(EXTRA_FILE);
        if (!skip_comp && !fmt_compressed_any(check_fmt(m.data(), m.size())) &&
            fmt_compressed(boot.e_fmt)) {
            hdr->set_extra_size(compress_len(boot.e_fmt, byte_view(m.data(), m.size()), fd));
        } else {
            hdr->set_extra_size(xwrite(fd, m.data(), m.size()));
        }
        file_align();
    }

    // recovery_dtbo
    fprintf(stdout, "repack: checking recovery_dtbo\n");
    fflush(stderr);
    if (access(RECV_DTBO_FILE, R_OK) == 0) {
        hdr->set_recovery_dtbo_offset(lseek(fd, 0, SEEK_CUR));
        hdr->set_recovery_dtbo_size(restore(fd, RECV_DTBO_FILE));
        file_align();
    }

    // dtb
    off.dtb = lseek(fd, 0, SEEK_CUR);
    fprintf(stdout, "repack: writing dtb at %u\n", off.dtb);
    fflush(stderr);
    if (access(DTB_FILE, R_OK) == 0) {
        hdr->set_dtb_size(restore(fd, DTB_FILE));
        file_align();
    }

    // Copy boot signature
    if (boot.hdr->signature_size()) {
        fprintf(stdout, "repack: writing signature\n");
        fflush(stderr);
        xwrite(fd, boot.signature, boot.hdr->signature_size());
        file_align();
    }

    // vendor ramdisk table
    if (!ramdisk_table.empty()) {
        fprintf(stdout, "repack: writing vendor ramdisk table\n");
        fflush(stderr);
        xwrite(fd, ramdisk_table.data(), sizeof(*ramdisk_table.data()) * ramdisk_table.size());
        file_align();
    }

    // bootconfig
    if (access(BOOTCONFIG_FILE, R_OK) == 0) {
        fprintf(stdout, "repack: writing bootconfig\n");
        fflush(stderr);
        hdr->set_bootconfig_size(restore(fd, BOOTCONFIG_FILE));
        file_align();
    }

    // Proprietary stuffs
    if (boot.flags[SEANDROID_FLAG]) {
        xwrite(fd, SEANDROID_MAGIC, 16);
        if (boot.flags[DHTB_FLAG]) {
            xwrite(fd, "\xFF\xFF\xFF\xFF", 4);
        }
    } else if (boot.flags[LG_BUMP_FLAG]) {
        xwrite(fd, LG_BUMP_MAGIC, 16);
    }

    off.tail = lseek(fd, 0, SEEK_CUR);
    fprintf(stdout, "repack: tail at %u\n", off.tail);
    fflush(stderr);
    file_align();

    // vbmeta
    if (boot.flags[AVB_FLAG]) {
        // According to avbtool.py, if the input is not an Android sparse image
        // (which boot images are not), the default block size is 4096
        file_align_with(4096);
        off.vbmeta = lseek(fd, 0, SEEK_CUR);
        fprintf(stdout, "repack: writing vbmeta at %u\n", off.vbmeta);
        fflush(stderr);
        uint64_t vbmeta_size = __builtin_bswap64(boot.avb_footer->vbmeta_size);
        xwrite(fd, boot.vbmeta, vbmeta_size);
    }

    // Pad step removed: we pre-allocate to boot.map.size() at open, so no write_zero needed.
    // This avoids pad subtraction underflow entirely.

    /******************
     * Patch the image
     ******************/

    off_t actual_sz = lseek(fd, 0, SEEK_END);
    fprintf(stdout, "repack: patch start tail=%u header=%u actual_file_sz=%lld map_sz=%zu\n",
            off.tail, off.header, static_cast<long long>(actual_sz), boot.map.size());
    fflush(stderr);
    if (static_cast<size_t>(actual_sz) > boot.map.size()) {
        fprintf(stdout, "repack: WARNING file grew past pre-alloc! actual=%lld expected=%zu\n",
                static_cast<long long>(actual_sz), boot.map.size());
        fflush(stderr);
    }

    if (off.tail < off.header) {
        fprintf(stdout, "repack: invalid layout tail=%u < header=%u\n", off.tail, off.header);
        delete hdr;
        close(fd);
        return;
    }
    uint32_t aosp_img_size = off.tail - off.header;

    off_t file_sz = lseek(fd, 0, SEEK_END);
    if (file_sz <= 0) {
        fprintf(stdout, "repack: output file size invalid (%lld)\n",
                static_cast<long long>(file_sz));
        delete hdr;
        close(fd);
        return;
    }
    const size_t out_sz = static_cast<size_t>(file_sz);

    // Patch image using pread/pwrite only (no mmap) to avoid SIGSEGV on some devices (e.g. v4 +
    // AVB). MTK headers
    if (boot.flags[MTK_KERNEL]) {
        mtk_hdr m_hdr;
        if (pread(fd, &m_hdr, sizeof(m_hdr), off.kernel) != static_cast<ssize_t>(sizeof(m_hdr))) {
            fprintf(stdout, "repack: MTK kernel header read failed\n");
            delete hdr;
            close(fd);
            return;
        }
        m_hdr.size = hdr->kernel_size();
        if (pwrite(fd, &m_hdr, sizeof(m_hdr), off.kernel) != static_cast<ssize_t>(sizeof(m_hdr))) {
            fprintf(stdout, "repack: MTK kernel header write failed\n");
            delete hdr;
            close(fd);
            return;
        }
        hdr->set_kernel_size(hdr->kernel_size() + sizeof(mtk_hdr));
    }
    if (boot.flags[MTK_RAMDISK]) {
        mtk_hdr m_hdr;
        if (pread(fd, &m_hdr, sizeof(m_hdr), off.ramdisk) != static_cast<ssize_t>(sizeof(m_hdr))) {
            fprintf(stdout, "repack: MTK ramdisk header read failed\n");
            delete hdr;
            close(fd);
            return;
        }
        m_hdr.size = hdr->ramdisk_size();
        if (pwrite(fd, &m_hdr, sizeof(m_hdr), off.ramdisk) != static_cast<ssize_t>(sizeof(m_hdr))) {
            fprintf(stdout, "repack: MTK ramdisk header write failed\n");
            delete hdr;
            close(fd);
            return;
        }
        hdr->set_ramdisk_size(hdr->ramdisk_size() + sizeof(mtk_hdr));
    }

    // Make sure header size matches
    hdr->set_header_size(hdr->hdr_size());

    // Update checksum
    if (char* id = hdr->id()) {
        auto ctx = get_sha(!boot.flags[SHA256_FLAG]);
        std::vector<char> buf;
        auto read_update = [fd, &buf](uint32_t off_val, uint32_t len) -> byte_view {
            if (len == 0)
                return byte_view(nullptr, 0);
            buf.resize(len);
            if (pread(fd, buf.data(), len, off_val) != static_cast<ssize_t>(len))
                return byte_view(nullptr, 0);
            return byte_view(buf.data(), len);
        };
        uint32_t size = hdr->kernel_size();
        ctx->update(read_update(off.kernel, size));
        ctx->update(byte_view(&size, sizeof(size)));
        size = hdr->ramdisk_size();
        ctx->update(read_update(off.ramdisk, size));
        ctx->update(byte_view(&size, sizeof(size)));
        size = hdr->second_size();
        ctx->update(read_update(off.second, size));
        ctx->update(byte_view(&size, sizeof(size)));
        size = hdr->extra_size();
        if (size) {
            ctx->update(read_update(off.extra, size));
            ctx->update(byte_view(&size, sizeof(size)));
        }
        uint32_t ver = hdr->header_version();
        if (ver == 1 || ver == 2) {
            size = hdr->recovery_dtbo_size();
            uint64_t ro_off = hdr->recovery_dtbo_offset();
            if (ro_off <= out_sz && size <= out_sz - static_cast<size_t>(ro_off))
                ctx->update(read_update(static_cast<uint32_t>(ro_off), size));
            ctx->update(byte_view(&size, sizeof(size)));
        }
        if (ver == 2) {
            size = hdr->dtb_size();
            ctx->update(read_update(off.dtb, size));
            ctx->update(byte_view(&size, sizeof(size)));
        }
        memset(id, 0, BOOT_ID_SIZE);
        ctx->finalize_into(byte_data(id, ctx->output_size()));
    }

    // Print new header info
    hdr->print();

    // Copy main header
    const size_t hdr_copy_sz = boot.flags[AMONET_FLAG]
                                   ? min(hdr->hdr_space() - AMONET_MICROLOADER_SZ, hdr->hdr_size())
                                   : hdr->hdr_size();
    const size_t hdr_off =
        boot.flags[AMONET_FLAG] ? off.header + AMONET_MICROLOADER_SZ : off.header;
    if (hdr_off + hdr_copy_sz > out_sz || !hdr->raw_hdr()) {
        fprintf(stdout, "repack: header write out of bounds\n");
        delete hdr;
        close(fd);
        return;
    }
    if (pwrite(fd, hdr->raw_hdr(), hdr_copy_sz, hdr_off) != static_cast<ssize_t>(hdr_copy_sz)) {
        fprintf(stdout, "repack: header write failed\n");
        delete hdr;
        close(fd);
        return;
    }

    if (boot.flags[AVB_FLAG]) {
        // Copy and patch AVB structures
        if (out_sz < sizeof(AvbFooter)) {
            fprintf(stdout, "repack: image too small for AVB footer\n");
            delete hdr;
            close(fd);
            return;
        }
        AvbFooter footer;
        memcpy(&footer, boot.avb_footer, sizeof(footer));
        footer.original_image_size = __builtin_bswap64(aosp_img_size);
        footer.vbmeta_offset = __builtin_bswap64(off.vbmeta);
        if (pwrite(fd, &footer, sizeof(footer), static_cast<off_t>(out_sz - sizeof(AvbFooter))) !=
            static_cast<ssize_t>(sizeof(footer))) {
            fprintf(stdout, "repack: AVB footer write failed\n");
            delete hdr;
            close(fd);
            return;
        }
        if (check_env("PATCHVBMETAFLAG")) {
            AvbVBMetaImageHeader vbmeta;
            if (pread(fd, &vbmeta, sizeof(vbmeta), off.vbmeta) ==
                static_cast<ssize_t>(sizeof(vbmeta))) {
                vbmeta.flags = __builtin_bswap32(3);
                pwrite(fd, &vbmeta, sizeof(vbmeta), off.vbmeta);
            }
        }
    }

    if (boot.flags[DHTB_FLAG]) {
        std::vector<char> dhtb_payload(aosp_img_size + 16 + 4);
        ssize_t nr = pread(fd, dhtb_payload.data(), dhtb_payload.size(),
                           static_cast<off_t>(sizeof(dhtb_hdr)));
        if (nr == static_cast<ssize_t>(dhtb_payload.size())) {
            dhtb_hdr d_hdr;
            memcpy(&d_hdr, boot.map.data(), sizeof(d_hdr));
            d_hdr.size = aosp_img_size + 16 + 4;
            sha256_hash(byte_view(dhtb_payload.data(), d_hdr.size),
                        byte_data(d_hdr.checksum.data(), SHA256_DIGEST_SIZE));
            if (pwrite(fd, &d_hdr, sizeof(d_hdr), 0) != static_cast<ssize_t>(sizeof(d_hdr))) {
                fprintf(stdout, "repack: DHTB header write failed\n");
            }
        }
    } else if (boot.flags[BLOB_FLAG]) {
        blob_hdr b_hdr;
        if (pread(fd, &b_hdr, sizeof(b_hdr), 0) == static_cast<ssize_t>(sizeof(b_hdr))) {
            b_hdr.size = aosp_img_size;
            pwrite(fd, &b_hdr, sizeof(b_hdr), 0);
        }
    }

    if (boot.flags[AVB1_SIGNED_FLAG]) {
        std::vector<char> payload_buf(aosp_img_size);
        if (pread(fd, payload_buf.data(), payload_buf.size(), off.header) ==
            static_cast<ssize_t>(payload_buf.size())) {
            auto sig = sign_payload(byte_view(payload_buf.data(), payload_buf.size()));
            if (!sig.empty()) {
                lseek(fd, off.tail, SEEK_SET);
                xwrite(fd, sig.data(), sig.size());
            }
        }
    }

    delete hdr;
    close(fd);
}

void cleanup() {
    unlink(HEADER_FILE);
    unlink(KERNEL_FILE);
    unlink(RAMDISK_FILE);
    unlink(SECOND_FILE);
    unlink(KER_DTB_FILE);
    unlink(EXTRA_FILE);
    unlink(RECV_DTBO_FILE);
    unlink(DTB_FILE);
    unlink(BOOTCONFIG_FILE);
    rm_rf(VND_RAMDISK_DIR);
}
