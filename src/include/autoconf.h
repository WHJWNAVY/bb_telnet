#ifndef __AUTOCONFIG_H__
#define __AUTOCONFIG_H__

#define CONFIG_FEATURE_TELNET_TTYPE 1
#define ENABLE_FEATURE_TELNET_TTYPE 1

#undef CONFIG_FEATURE_TELNET_AUTOLOGIN
#define ENABLE_FEATURE_TELNET_AUTOLOGIN 0

#undef CONFIG_FEATURE_TELNET_WIDTH
#define ENABLE_FEATURE_TELNET_WIDTH 0

#define CONFIG_FEATURE_IPV6 1
#define ENABLE_FEATURE_IPV6 1
#define IF_FEATURE_IPV6(...) __VA_ARGS__
#define IF_NOT_FEATURE_IPV6(...)

#undef CONFIG_FEATURE_UNIX_LOCAL
#define ENABLE_FEATURE_UNIX_LOCAL 0
#define IF_FEATURE_UNIX_LOCAL(...)
#define IF_NOT_FEATURE_UNIX_LOCAL(...) __VA_ARGS__

#define CONFIG_FEATURE_PREFER_IPV4_ADDRESS 1
#define ENABLE_FEATURE_PREFER_IPV4_ADDRESS 1
#define IF_FEATURE_PREFER_IPV4_ADDRESS(...) __VA_ARGS__
#define IF_NOT_FEATURE_PREFER_IPV4_ADDRESS(...)

#endif