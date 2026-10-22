TARGET := iphone:clang:latest:15.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TOOL_NAME = trustctl

trustctl_FILES = main.m
trustctl_CFLAGS = -fobjc-arc
trustctl_FRAMEWORKS = Security
trustctl_CODESIGN_FLAGS = -Sentitlements.plist
trustctl_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk
