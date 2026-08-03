// YouTube (亚马逊/TrollStore 版) 去授权 hook
//
// 逆向结论：
//   启动时 AppSceneDelegate 把 rootVC 设为注入的 LoginViewController(卡密登录界面)，
//   挂了一个 void(^)(void) 回调存在 ivar _onAuthorized (@?, 偏移 +0x10)。
//   点击验证 -> submitTapped -> HTTP POST 校验卡密 -> 成功后 [self onAuthorized]() 才切到真正的 YouTube。
//   viewDidLoad 里若已存卡密会自动尝试验证(didAutoAttempt)。
//
// 去授权思路（不碰那个控制流平坦化的验证函数，纯运行时放行）：
//   1. viewDidLoad 完成后，直接取出 _onAuthorized block 并执行 -> 等同验证通过，进入 YouTube。
//   2. 把 submitTapped / verify 相关网络逻辑短路，避免作者服务器限制卡密导致失败。
//   3. 兼容作者可能改类名：优先 hook LoginViewController，找不到就按 setOnAuthorized: 特征兜底。

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ---- 日志 ----
#define YLOG(fmt, ...) NSLog(@"[YTUnlock] " fmt, ##__VA_ARGS__)

typedef void (^AuthBlock)(void);

// 反射取 _onAuthorized ivar（block），并在主线程执行
static BOOL fireOnAuthorized(id vc) {
    if (!vc) return NO;
    Ivar iv = class_getInstanceVariable([vc class], "_onAuthorized");
    if (!iv) {
        // 有的编译会把 ivar 名字改掉，退而用 KVC / 属性
        @try {
            id b = [vc valueForKey:@"onAuthorized"];
            if (b) {
                AuthBlock blk = (AuthBlock)b;
                dispatch_async(dispatch_get_main_queue(), ^{ @try { blk(); } @catch (__unused id e) {} });
                YLOG(@"fired onAuthorized via KVC");
                return YES;
            }
        } @catch (__unused id e) {}
        return NO;
    }
    id blockObj = object_getIvar(vc, iv);
    if (!blockObj) {
        YLOG(@"_onAuthorized is nil, retry later");
        return NO;
    }
    AuthBlock blk = (AuthBlock)blockObj;
    dispatch_async(dispatch_get_main_queue(), ^{
        @try { blk(); YLOG(@"onAuthorized() invoked -> unlocked"); }
        @catch (__unused id e) { YLOG(@"onAuthorized threw, ignored"); }
    });
    return YES;
}

// 反复尝试触发（block 可能在 viewDidLoad 之后才被 setOnAuthorized: 赋值）
static void scheduleUnlock(id vc, int attempt) {
    if (attempt > 40) { YLOG(@"give up after 40 attempts"); return; }
    if (fireOnAuthorized(vc)) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        scheduleUnlock(vc, attempt + 1);
    });
}

static Class gLoginClass = nil;

// 把某个类的 viewDidLoad / submitTapped 换掉
static void patchLoginClass(Class cls) {
    if (!cls) return;
    gLoginClass = cls;
    YLOG(@"patching class: %s", class_getName(cls));

    // 1) viewDidLoad 之后触发放行
    {
        SEL sel = @selector(viewDidLoad);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            IMP repl = imp_implementationWithBlock(^(id self_) {
                ((void(*)(id, SEL))orig)(self_, sel);
                YLOG(@"LoginVC viewDidLoad done, scheduling unlock");
                scheduleUnlock(self_, 0);
            });
            method_setImplementation(m, repl);
        }
    }

    // 2) submitTapped 直接放行，不发网络请求（服务器已限制卡密）
    {
        SEL sel = @selector(submitTapped);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP repl = imp_implementationWithBlock(^(id self_) {
                YLOG(@"submitTapped intercepted -> unlock directly");
                scheduleUnlock(self_, 0);
            });
            method_setImplementation(m, repl);
        }
    }
}

%ctor {
    @autoreleasepool {
        YLOG(@"loaded");

        // 优先按已知类名
        Class c = objc_getClass("LoginViewController");
        if (c) {
            patchLoginClass(c);
            return;
        }

        // 兜底：作者若改了类名，遍历所有实现了 setOnAuthorized: 的类
        YLOG(@"LoginViewController not found, scanning for setOnAuthorized:");
        unsigned int n = 0;
        Class *all = objc_copyClassList(&n);
        for (unsigned int i = 0; i < n; i++) {
            Class k = all[i];
            if (class_getInstanceMethod(k, @selector(setOnAuthorized:)) &&
                class_getInstanceMethod(k, @selector(submitTapped))) {
                patchLoginClass(k);
                break;
            }
        }
        free(all);
        if (!gLoginClass) YLOG(@"no candidate class found; author may have restructured the gate");
    }
}
