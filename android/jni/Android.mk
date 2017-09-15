LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := Execute
LOCAL_SRC_FILES := Execute.c
# BUILD_EXECUTABLE指明生成可执行的二进制文件
include $(BUILD_EXECUTABLE)
