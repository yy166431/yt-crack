// YouTube 内核授权 —— 动态探针 dylib（多巴胺 opainject 注入用）
//
// 目的: 回答核心问题 —— guard 区(0x1095D0310/318/320)的数据是
//   [A] 服务器 payload 下发的死数据，还是 [B] 本地引擎运行时算出来的。
//
// 手段:
//   1. 注入即 dump 主二进制 slide + 三个 guard 全局的当前值/区间内存。
//   2. hook -[AppViewController primaryButtonTapped]，在 exit(0) 门之前再 dump 一次。
//   3. （阶段二再加）强行绕过 exit(0)，闯进内核引擎，观察 guard 区是否被本地填充。
//
// 日志落盘 /tmp/ytprobe.log，SSH 取回分析。
//
// 主二进制静态地址(imagebase 0x100000000):
//   guard: 0x1095D0310 / 0x1095D0318 / 0x1095D0320
//   primaryButtonTapped @ 0x1001b7adc
//   kernel engine sub_10026A438 @ 0x10026a438

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdarg.h>

#define GUARD_310 0x1095D0310ULL
#define GUARD_318 0x1095D0318ULL
#define GUARD_320 0x1095D0320ULL
#define STATIC_BASE 0x100000000ULL

static const char *LOGP = "/tmp/ytprobe.log";

static void plog(const char *fmt, ...) {
    char buf[2048];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    int fd = open(LOGP, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { write(fd, buf, (size_t)n); write(fd, "\n", 1); close(fd); }
    // 同时打印到 syslog 方便实时看
    NSLog(@"[YTProbe] %s", buf);
}

// 找到主可执行镜像的 ASLR slide
static intptr_t mainSlide(const char **outName) {
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (mh && mh->filetype == MH_EXECUTE) {
            if (outName) *outName = _dyld_get_image_name(i);
            return _dyld_get_image_vmaddr_slide(i);
        }
    }
    return 0;
}

// 安全读一个 8 字节（先探测可读性）
static BOOL safeRead64(uint64_t addr, uint64_t *out) {
    // 用 dlsym 无关；直接尝试读，交给上层 vm 保护。这里简单解引用。
    // 注入进程内地址有效即可读；guard 区在 __data，映射存在。
    *out = *(volatile uint64_t *)addr;
    return YES;
}

static void dumpGuard(const char *tag, intptr_t slide) {
    uint64_t a310 = GUARD_310 + slide;
    uint64_t a318 = GUARD_318 + slide;
    uint64_t a320 = GUARD_320 + slide;
    uint64_t v310 = 0, v318 = 0, v320 = 0;
    safeRead64(a310, &v310);
    safeRead64(a318, &v318);
    safeRead64(a320, &v320);
    plog("---- guard dump [%s] ----", tag);
    plog("  slide=0x%lx", (unsigned long)slide);
    plog("  [0x%llx] 310 = 0x%016llx", a310, v310);
    plog("  [0x%llx] 318 = 0x%016llx", a318, v318);
    plog("  [0x%llx] 320 = 0x%016llx", a320, v320);
    plog("  region: 318^320 = 0x%016llx  (len if ptrs = %lld)",
         v318 ^ v320, (long long)(v320 - v318));
    // 如果 318/320 看着像有效指针(区间)，dump 区间头部字节
    if (v318 && v320 && v320 > v318 && (v320 - v318) < 0x200000) {
        uint64_t len = v320 - v318;
        plog("  region looks valid, base=0x%llx len=0x%llx, first bytes:", v318, len);
        const unsigned char *p = (const unsigned char *)v318;
        char hex[16 * 3 + 1];
        uint64_t show = len < 64 ? len : 64;
        for (uint64_t i = 0; i < show; i += 16) {
            int m = 0;
            for (uint64_t j = i; j < i + 16 && j < show; j++)
                m += snprintf(hex + m, sizeof(hex) - m, "%02x ", p[j]);
            plog("    +%04llx: %s", i, hex);
        }
    } else {
        plog("  region NOT a valid buffer (likely zero/uninitialized -> gate would exit(0))");
    }
}

// hook primaryButtonTapped：进门前 dump 一次
static void (*orig_primaryTapped)(id, SEL);
static void my_primaryTapped(id self, SEL _cmd) {
    const char *nm = NULL;
    intptr_t slide = mainSlide(&nm);
    plog("==== primaryButtonTapped ENTER (before gate) ====");
    dumpGuard("pre-gate", slide);
    plog("  -> calling original (may exit(0) if guard empty)");
    orig_primaryTapped(self, _cmd);
    plog("  <- original returned WITHOUT exit (guard was valid!)");
    dumpGuard("post-original", slide);
}

__attribute__((constructor))
static void probe_init(void) {
    // 清空旧日志
    int fd = open(LOGP, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) close(fd);

    const char *nm = NULL;
    intptr_t slide = mainSlide(&nm);
    plog("========================================");
    plog("[YTProbe] injected. main=%s", nm ? nm : "?");
    dumpGuard("ctor", slide);

    Class avc = objc_getClass("AppViewController");
    if (!avc) {
        plog("AppViewController not found at ctor; will retry in 3s");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            Class c = objc_getClass("AppViewController");
            plog("retry: AppViewController = %p", c);
            if (c) {
                Method m = class_getInstanceMethod(c, @selector(primaryButtonTapped));
                if (m) {
                    orig_primaryTapped = (void(*)(id,SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)my_primaryTapped);
                    plog("hooked primaryButtonTapped (deferred)");
                } else plog("no primaryButtonTapped method");
            }
        });
        return;
    }
    Method m = class_getInstanceMethod(avc, @selector(primaryButtonTapped));
    if (m) {
        orig_primaryTapped = (void(*)(id,SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)my_primaryTapped);
        plog("hooked primaryButtonTapped");
    } else {
        plog("no primaryButtonTapped method on AppViewController");
    }
}
