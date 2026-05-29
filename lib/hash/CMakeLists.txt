# Copyright (c) 2026 Vilhelm Engström
#
# SPDX-License-Identifier: Apache-2.0

zephyr_library()
zephyr_library_property(ALLOW_EMPTY TRUE)
zephyr_library_sources_ifdef(CONFIG_SYS_HASH_FUNC_MURMUR128 murmur128-x86.c)
