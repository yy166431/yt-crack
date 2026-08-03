TARGET := iphone:clang:latest:14.0
ARCHS := arm64 arm64e

# 生成独立 dylib（不做 deb 打包），供 TrollStore/巨魔 注入
THEOS_PACKAGE_SCHEME := rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := YTUnlock

YTUnlock_FILES := Tweak/Tweak.xm
YTUnlock_CFLAGS := -fobjc-arc -Wno-deprecated-declarations
YTUnlock_FRAMEWORKS := UIKit Foundation
# 只用 objc runtime + %ctor，不依赖 CydiaSubstrate
YTUnlock_LDFLAGS := -Wl,-no_warn_inits

include $(THEOS_MAKE_PATH)/tweak.mk
