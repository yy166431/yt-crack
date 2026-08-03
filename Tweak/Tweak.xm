// YouTube (亚马逊/TrollStore 版) 去授权 hook
//
// 逆向结论：
//   启动时 AppSceneDelegate 把 rootVC 设为注入的 LoginViewController(卡密登录界面)，
//   挂了一个 void(^)(void) 回调存在 ivar _onAuthorized (@?, 偏移 +0x10)。
//   验证通过后 [self onAuthorized]() 才切到真正的 YouTube。
//   LoginViewController 自身实现了 viewDidLoad / viewDidAppear: / submitTapped。
//
// 去授权(纯运行时放行，不碰控制流平坦化的验证函数)：
//   在 LoginViewController -viewDidAppear: 之后(界面已上屏、window 就绪，转场安全)
//   直接取出 _onAuthorized block 执行 -> 等同验证通过进入 YouTube。
//   同时短路 submitTapped，避免连作者已限卡的服务器。
//
// 关键安全措施(上一版加载即崩的教训)：
//   - 不做 objc_copyClassList 全类扫描(早期加载遍历巨型App所有类极易崩)。
//   - 不在 viewDidLoad 阶段 fire(太早，window 未就绪，转场会崩)。
//   - 全程 @try/@catch，onAuthorized 只触发一次。

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#define YLOG(fmt, ...) NSLog(@"[YTUnlock] " fmt, ##__VA_ARGS__)
typedef void (^AuthBlock)(void);

// 保证每个实例只触发一次
static BOOL claimFireOnce(id vc) {
    static const void *KEY = &KEY;
    if (objc_getAssociatedObject(vc, KEY)) return NO;
    objc_setAssociatedObject(vc, KEY, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return YES;
}

// 取 _onAuthorized block 并执行(主线程调用)
static void fireUnlock(id vc) {
    @try {
        if (!vc) return;
        Ivar iv = class_getInstanceVariable(object_getClass(vc), "_onAuthorized");
        id blockObj = iv ? object_getIvar(vc, iv) : nil;
        if (!blockObj) {
            @try { blockObj = [vc valueForKey:@"onAuthorized"]; } @catch (__unused id e) {}
        }
        if (!blockObj) { YLOG(@"onAuthorized not ready yet"); return; }
        AuthBlock blk = (AuthBlock)blockObj;
        YLOG(@"invoking onAuthorized -> unlock");
        blk();
    } @catch (id e) {
        YLOG(@"fireUnlock exception: %@", e);
    }
}

static void patchClass(Class cls) {
    if (!cls) return;
    YLOG(@"patching %s", class_getName(cls));

    // 1) viewDidAppear: 之后放行(界面已上屏，转场安全)
    {
        SEL sel = @selector(viewDidAppear:);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP orig = method_getImplementation(m);
            IMP repl = imp_implementationWithBlock(^(id self_, BOOL animated) {
                ((void(*)(id, SEL, BOOL))orig)(self_, sel, animated);
                if (claimFireOnce(self_)) {
                    YLOG(@"LoginVC did appear, unlocking shortly");
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ fireUnlock(self_); });
                }
            });
            method_setImplementation(m, repl);
            YLOG(@"hooked viewDidAppear:");
        } else {
            YLOG(@"no viewDidAppear: on class");
        }
    }

    // 2) submitTapped 直接放行，不发网络验证
    {
        SEL sel = @selector(submitTapped);
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP repl = imp_implementationWithBlock(^(id self_) {
                YLOG(@"submitTapped intercepted -> direct unlock");
                fireUnlock(self_);
            });
            method_setImplementation(m, repl);
            YLOG(@"hooked submitTapped");
        }
    }
}

%ctor {
    @try {
        YLOG(@"loaded");
        Class c = objc_getClass("LoginViewController");
        if (c) { patchClass(c); return; }

        // 类此刻还没注册：不扫描全类(危险)，只延迟到主线程再取一次
        YLOG(@"LoginViewController missing at ctor, deferring to main queue");
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                Class c2 = objc_getClass("LoginViewController");
                if (c2) patchClass(c2);
                else YLOG(@"LoginViewController still missing (author may have renamed the gate)");
            } @catch (id e) { YLOG(@"deferred patch exception: %@", e); }
        });
    } @catch (id e) {
        YLOG(@"ctor exception: %@", e);
    }
}
