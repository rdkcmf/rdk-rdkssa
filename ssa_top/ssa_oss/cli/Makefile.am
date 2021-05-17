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

## RDKSSA Support

if !RDKSSA_UT_ENABLED
AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -DRDKSSA_ERROR_ENABLED -DRDKSSA_LOG_FILE $(CFLAGS) -Werror -Wall -Os
#AM_CFLAGS += -DRDKSSA_INFO_ENABLED -DRDKSSA_DEBUG_ENABLED
OBJCOPY = objcopy
bin_PROGRAMS = ssacli
ssacli_SOURCES = ssacli.c
ssacli_LDADD = $(top_builddir)/ssa_top/ssa_oss/ssa_common/libssa.la
ssacli_CFLAGS = $(AM_CFLAGS)
else
AM_CFLAGS = -I$(top_srcdir)/ssa_top/ssa_oss/ssa_common -DUNIT_TESTS -Wfatal-errors -DRDKSSA_ERROR_ENABLED -Werror -Wall -Wno-unused-function
AM_CFLAGS += -DRDKSSA_INFO_ENABLED -DRDKSSA_DEBUG_ENABLED
OBJCOPY = objcopy
bin_PROGRAMS = ut_ssacli
ut_ssacli_SOURCES = ssacli.c
ut_ssacli_CFLAGS = $(AM_CFLAGS)
endif
