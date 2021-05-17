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

# RDKSSA secure Mount Provider 
#
# build in -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/providers/Mount/generic
#
# /ssa_top/ssa_oss/ssa_common/providers/Mount/generic
# Explanation of paths. Starting in Mount/generic
# -I.  					Mount/generic =			source directory for generic variant of Mount Provider (implicit - not included in compile options)
# -I./private			Mount/generic/private	sources private  only to the generic Mount provider
# -I.. \            	Mount =					common sources (.c and .h) shared by all Mount Provider variants and other ssa code, above and below (e.g. class "public")
# -I../protected    	Mount/protected = 		common sources available only to descendant Mount Provider variants
# -I../.. \         	providers =				common sources available to all Providers and above, "public"
# -I../../protected		providers/protected =	common sources available only to Providers
# -I../../.. \			ssa_common =			common sources available to the ssa framework, public
# -I../../../protected	ssa_common/protected = 	common sources available to descendents of ssa_common
##

if !RDKSSA_UT_ENABLED
AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/protected -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/providers/Mount/private -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/providers/Mount/generic/private  -DDONT_USE_ANY_SYSTEM_CMD -DRDKSSA_ERROR_ENABLED -DRDKSSA_LOG_FILE -Werror -Wall -Os

OBJCOPY = objcopy

MOUNT_PROVIDER_SOURCE = rdkssaMountProvider.c  

noinst_LTLIBRARIES = libssa_mount.la
libssa_mount_la_SOURCES = $(MOUNT_PROVIDER_SOURCE)
libssa_mount_la_CFLAGS = $(AM_CFLAGS) -fPIC -shared
else
AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/protected -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/providers/Mount/private -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common/providers/Mount/generic/private -DUNIT_TESTS -Wfatal-errors -DRDKSSA_ERROR_ENABLED -Werror -Wall -Wno-unused-function
AM_CFLAGS += -DRDKSSA_INFO_ENABLED -DRDKSSA_DEBUG_ENABLED
OBJCOPY = objcopy

bin_PROGRAMS = ut_ssamount
ut_ssamount_SOURCES = rdkssaMountProvider.c
ut_ssamount_CFLAGS = $(AM_CFLAGS)
endif
