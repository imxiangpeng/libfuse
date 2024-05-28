/*
 * Copyright (C) 2024 Inspur Group Co., Ltd. Unpublished
 *
 * Inspur Group Co., Ltd.
 * Proprietary & Confidential
 *
 * This source code and the algorithms implemented therein constitute
 * confidential information and may comprise trade secrets of Inspur
 * or its associates, and any use thereof is subject to the terms and
 * conditions of the Non-Disclosure Agreement pursuant to which this
 * source code was originally received.
 */
#ifndef _HR_LOG_
#define _HR_LOG_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LOG_TAG
#define LOG_TAG NULL
#endif

typedef enum {
  HR_LOG_VERBOSE = 0,
  HR_LOG_DEBUG,
  HR_LOG_WARN,
  HR_LOG_ERROR
} hr_log_priority;

int _hr_log_printf(int prio, const char* tag, const char *fmt, ...);
#ifndef LOG_NDEBUG
#define HR_LOGV(...) ((void)HR_LOG(VERBOSE, LOG_TAG, __VA_ARGS__))
#else
#define HR_LOGV(...) ((void)0)
#endif


#ifndef LOG_NDEBUG
#define HR_LOGD(...) ((void)HR_LOG(DEBUG, LOG_TAG, __VA_ARGS__))
#else
#define HR_LOGD(...) ((void)0)
#endif

#define HR_LOGW(...) ((void)HR_LOG(WARN, LOG_TAG, __VA_ARGS__))
#define HR_LOGE(...) ((void)HR_LOG(ERROR, LOG_TAG, __VA_ARGS__))

#define HR_LOG(priority, tag, ...) \
  _hr_log_printf(HR_LOG_##priority, tag, __VA_ARGS__)
#ifdef __cplusplus
}
#endif

#endif // _HR_LOG_