TARGET := iphone:clang:latest:14.0
# 主程序 YouTube 是纯 arm64（非 arm64e），只编 arm64 瘦二进制，避免 ldid 拒绝胖/arm64e
ARCHS := arm64

# 生成独立 dylib（不做 deb 打包），供 TrollStore/巨魔 注入
THEOS_PACKAGE_SCHEME := rootless

include $(THEOS)/makefiles/common.mk

# ===== 去授权 tweak（成品，MobileSubstrate 注入）=====
TWEAK_NAME := YTUnlock
YTUnlock_FILES := Tweak/Tweak.xm
YTUnlock_CFLAGS := -fobjc-arc -Wno-deprecated-declarations
YTUnlock_FRAMEWORKS := UIKit Foundation
YTUnlock_LDFLAGS := -Wl,-no_warn_inits -Wl,-no_fixup_chains -Wl,-no_exported_symbols

include $(THEOS_MAKE_PATH)/tweak.mk

# ===== 动态探针（opainject 手动注入，不走 substrate）=====
LIBRARY_NAME := YTProbe
YTProbe_FILES := probe/probe.m
YTProbe_CFLAGS := -fobjc-arc -Wno-deprecated-declarations
YTProbe_FRAMEWORKS := Foundation
YTProbe_LDFLAGS := -Wl,-no_warn_inits -Wl,-no_fixup_chains -Wl,-no_exported_symbols

include $(THEOS_MAKE_PATH)/library.mk
