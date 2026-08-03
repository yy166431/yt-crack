// YouTube (亚马逊/TrollStore 版) 去授权 hook + 远程崩溃日志
//
// 授权逻辑(逆向): 启动时 rootVC = 注入的 LoginViewController(卡密界面)，
//   验证通过后 [self onAuthorized]() (ivar _onAuthorized, @?, +0x10) 才进真正的 YouTube。
// 去授权: 在 viewDidAppear: 之后取出 _onAuthorized block 直接执行放行；短路 submitTapped。
//
// 崩溃诊断(设备"分析与数据"看不到崩溃日志时用):
//   - 全程日志落盘到 App 沙盒 tmp/ytunlock.log
//   - %ctor 首先安装 NSUncaughtExceptionHandler + signal handler(SIGSEGV/ABRT/BUS/ILL/TRAP)
//     崩溃时把信号+backtrace 追加到日志
//   - 每次启动先把"上一会话"的完整日志(含上次崩溃栈) POST 到远程服务器
//     这样即使每次一开就崩，重开时也能把上次崩溃原因发出来

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <execinfo.h>
#import <signal.h>
#import <pthread.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>

// ====== 配置: 崩溃日志上报地址(改成你的服务器) ======
#define REPORT_URL @"http://159.75.14.193:8099/report"

// ====== 日志文件路径 ======
static NSString *logPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"ytunlock.log"];
}
static NSString *prevLogPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"ytunlock.prev.log"];
}

// 低层追加写(信号处理里也可用: 只用 write/open，不用 OC)
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
    NSString *line = [NSString stringWithFormat:@"[YTUnlock] %@", s];
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
        NSLog(@"[YTUnlock] reportFile exception %@", e);
    }
}

// 启动时: 轮转日志(上次的存 prev)，并把上次的发出去
static void rotateAndReportPrevious(void) {
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *cur = logPath(), *prev = prevLogPath();
        if ([fm fileExistsAtPath:cur]) {
            [fm removeItemAtPath:prev error:nil];
            [fm moveItemAtPath:cur toPath:prev error:nil];
        }
        // 新会话开始
        rawAppend("");
        YLOG(@"==== new session %@ ====", [NSDate date]);
        // 把上次会话(可能含崩溃栈)发出去
        if ([fm fileExistsAtPath:prev]) reportFile(prev, @"prev-session");
    } @catch (__unused id e) {}
}

// ====== 去授权 ======
typedef void (^AuthBlock)(void);

static BOOL claimFireOnce(id vc) {
    static const void *KEY = &KEY;
    if (objc_getAssociatedObject(vc, KEY)) return NO;
    objc_setAssociatedObject(vc, KEY, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return YES;
}

// 从 LoginVC 上找到当前 window（优先 self.view.window，退回 scene/app keyWindow）
static UIWindow *findWindow(id vc) {
    @try {
        UIView *v = [vc valueForKey:@"view"];
        UIWindow *w = v ? v.window : nil;
        if (w) return w;
    } @catch (__unused id e) {}
    // 退回：遍历所有 window，取第一个 keyWindow / 可见的
    @try {
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) return w;
        }
        UIWindow *any = [UIApplication sharedApplication].windows.firstObject;
        if (any) return any;
    } @catch (__unused id e) {}
    return nil;
}

// 不再调用 onAuthorized block（其头部有完整性 guard，直接调会被系统打掉）。
// 改为：从 block 对象里把它捕获的"真·YouTube 根 VC"(偏移 +0x28) 抠出来，
// 自己做 setRootViewController，完全绕开那段 guard。
static void fireUnlock(id vc) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ fireUnlock(vc); });
        return;
    }
    @try {
        if (!vc) return;
        Ivar iv = class_getInstanceVariable(object_getClass(vc), "_onAuthorized");
        id blockObj = iv ? object_getIvar(vc, iv) : nil;
        if (!blockObj) { @try { blockObj = [vc valueForKey:@"onAuthorized"]; } @catch (__unused id e) {} }
        if (!blockObj) { YLOG(@"onAuthorized not ready"); return; }

        // block 内存布局: +0x00 isa | +0x08 flags | +0x10 invoke | +0x18 desc
        //                +0x20 弱引用 window | +0x28 强引用 rootVC
        void * const *layout = (void * const *)(__bridge const void *)blockObj;
        id cap20 = (__bridge id)layout[4];   // +0x20
        id cap28 = (__bridge id)layout[5];   // +0x28

        YLOG(@"block caps: +0x20=%@  +0x28=%@",
             cap20 ? NSStringFromClass(object_getClass(cap20)) : @"nil",
             cap28 ? NSStringFromClass(object_getClass(cap28)) : @"nil");

        // 找出哪个捕获是 UIViewController（要装的根 VC），哪个是 UIWindow
        UIViewController *rootVC = nil;
        UIWindow *capWin = nil;
        for (id c in @[ cap20 ?: [NSNull null], cap28 ?: [NSNull null] ]) {
            if (c == [NSNull null]) continue;
            if ([c isKindOfClass:[UIWindow class]]) capWin = c;
            else if ([c isKindOfClass:[UIViewController class]]) rootVC = c;
        }
        if (!rootVC) {
            // 兜底：+0x28 按约定就是 rootVC
            if (cap28 && [cap28 isKindOfClass:[UIViewController class]]) rootVC = cap28;
        }
        if (!rootVC) { YLOG(@"rootVC not found in block caps, abort"); return; }

        UIWindow *win = capWin ?: findWindow(vc);
        if (!win) { YLOG(@"window not found, abort"); return; }

        YLOG(@"manual unlock: setRootViewController:%@ on %@",
             NSStringFromClass(object_getClass(rootVC)), NSStringFromClass(object_getClass(win)));
        [UIView transitionWithView:win
                          duration:0.3
                           options:UIViewAnimationOptionTransitionCrossDissolve
                        animations:^{ win.rootViewController = rootVC; }
                        completion:^(BOOL fin){ YLOG(@"manual unlock done fin=%d", fin); }];
        YLOG(@"manual unlock issued OK");
    } @catch (id e) {
        YLOG(@"fireUnlock exception: %@", e);
    }
}

static void patchClass(Class cls) {
    if (!cls) return;
    YLOG(@"patching %s", class_getName(cls));
    {
        SEL sel = @selector(viewDidAppear:);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            IMP repl = imp_implementationWithBlock(^(id self_, BOOL animated) {
                ((void(*)(id, SEL, BOOL))orig)(self_, sel, animated);
                if (claimFireOnce(self_)) {
                    YLOG(@"LoginVC appeared, will unlock after settle");
                    // 等 viewDidAppear 转场动画彻底结束再触发，避免转场重入导致栈破坏
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{
                        YLOG(@"settle done, firing unlock now");
                        fireUnlock(self_);
                    });
                }
            });
            method_setImplementation(m, repl);
            YLOG(@"hooked viewDidAppear:");
        } else {
            YLOG(@"no viewDidAppear:");
        }
    }
    {
        SEL sel = @selector(submitTapped);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP repl = imp_implementationWithBlock(^(id self_) {
                YLOG(@"submitTapped -> direct unlock");
                fireUnlock(self_);
            });
            method_setImplementation(m, repl);
            YLOG(@"hooked submitTapped");
        }
    }
}

%ctor {
    // 崩溃捕获必须最先装(才能抓到后续任何崩溃)
    installCrashHandlers();
    rotateAndReportPrevious();
    @try {
        YLOG(@"ctor start");
        Class c = objc_getClass("LoginViewController");
        if (c) { patchClass(c); YLOG(@"ctor done (direct)"); return; }

        YLOG(@"LoginViewController missing at ctor, defer to main queue");
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                Class c2 = objc_getClass("LoginViewController");
                if (c2) patchClass(c2);
                else YLOG(@"LoginViewController still missing");
            } @catch (id e) { YLOG(@"deferred exception: %@", e); }
        });
        YLOG(@"ctor done (deferred)");
    } @catch (id e) {
        YLOG(@"ctor exception: %@", e);
    }
}
