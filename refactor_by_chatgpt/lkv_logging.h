// lkv_logging.h
#ifndef LKV_LOGGING_H
#define LKV_LOGGING_H

void log_ioctl_call(long request);
void log_prctl_call(int option, long arg);

#endif
