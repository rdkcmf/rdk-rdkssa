##########################################################################
#  Copyright 2020 Comcast Cable Communications Management, LLC
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  SPDX-License-Identifier: Apache-2.0
#
##########################################################################

## 
# RDKSSA Common-layer code 
#
# build in -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common
# but all paths are relative to ssa_common
#
# /ssa_top/ssa_oss/ssa_common/providers/Mount/generic
# Explanation of paths. Starting in Mount/generic
# -I.  					ssa_oss/ssa_common =	source directory for OSS common code *used by all SSA implementations not just OSS*  (implicit - not included in compile options)
# -I./private			ssa_oss/ssa_common		sources private  only to the ssa_common code
# -I./protected
#
# This makefile does not build the providers. Selected providers are built at the ssa_oss later.
##

SUBDIRS = providers
if !RDKSSA_UT_ENABLED

#For creating rdkssa libraries

AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/private -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/protected -DDONT_USE_ANY_SYSTEM_CMD -DRDKSSA_ERROR_ENABLED -DRDKSSA_LOG_FILE -Werror -Wall -Os
OBJCOPY = objcopy

SSA_COMMON_SOURCE = ssaCommon.c 

lib_LTLIBRARIES = libssa.la
libssa_la_SOURCES = ${SSA_COMMON_SOURCE}
libssa_la_LIBADD  = $(top_builddir)/ssa_top/ssa_oss/ssa_common/providers/Mount/generic/libssa_mount.la
libssa_la_CFLAGS = $(AM_CFLAGS) -fPIC -shared
else
AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/private -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/protected  -DUNIT_TESTS -Wfatal-errors -DRDKSSA_ERROR_ENABLED -Werror -Wall -Wno-unused-function
AM_CFLAGS += -DRDKSSA_INFO_ENABLED -DRDKSSA_DEBUG_ENABLED
OBJCOPY = objcopy
bin_PROGRAMS = ut_ssahelp
ut_ssahelp_SOURCES = ssaCommon.c
ut_ssahelp_CFLAGS = $(AM_CFLAGS)
endif
