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

## RDK-OSS-SSA Makefile Support for non-yocto builds

top_srcdir = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
provider_dir = $(top_srcdir)ssa_top/ssa_oss/ssa_common/providers
common_dir = $(top_srcdir)ssa_top/ssa_oss/ssa_common
cli_dir = $(top_srcdir)ssa_top/ssa_oss/cli

utflag = -DUNIT_TESTS -DUSE_COLORS -Wfatal-errors -DRDKSSA_ERROR_ENABLED
#ptflag = -DPLTFORM_TEST -Wfatal-errors
#utflag += -DRDKSSA_INFO_ENABLED
#utflag += -DRDKSSA_DEBUG_ENABLED
SSA_INFO  = -DRDKSSA_INFO_ENABLED
SSA_ERROR  = -DRDKSSA_ERROR_ENABLED
SSA_DEBUG = -DRDKSSA_DEBUG_ENABLED

SSA_CFLAGS = -I$(common_dir) -I$(cli_dir) -Werror -Wall -Wno-unused-function -O0 -std=gnu99 
SSA_CFLAGS_MOUNT = -I${provider_dir}/Mount/generic/private -I${provider_dir}/Mount/private 
SSA_CFLAGS_HELP = -I${common_dir}/private -I${common_dir}/protected
SSA_CFLAGS_UT = $(utflag) $(SSA_CFLAGS)
#SSA_CFLAGS_PT = $(ptflag) $(SSA_CFLAGS)

OBJCOPY = objcopy
CLEANFILES = *.OBJ *.LST *.o *.gch *.out *.so *.map *.a *.$(OBJEXT) *.la ut_* ssacli

#Sources
SSACLI_SOURCES = $(cli_dir)/ssacli.c $(common_dir)/rdkssa.h $(common_dir)/protected/rdkssaCommonProtected.h
SSAHELP_SOURCES = $(common_dir)/ssaCommon.c $(common_dir)/rdkssa.h $(common_dir)/protected/rdkssaCommonProtected.h $(common_dir)/private/rdkssaCommonPrivate.h
SSAMOUNT_SOURCES   = $(provider_dir)/Mount/generic/rdkssaMountProvider.c $(provider_dir)/Mount/private/rdkssaMountProvider.h $(common_dir)/rdkssa.h $(common_dir)/protected/rdkssaCommonProtected.h $(provider_dir)/Mount/generic/private/rdkssaMountProviderPrivate.h
SSA_API_SOURCES = $(SSAMOUNT_SOURCES) 
SSA_API_CFLAGS = $(SSA_CFLAGS_MOUNT) $(SSA_CFLAGS_HELP)
SSA_API_CFLAGS += $(SSA_DEBUG) $(SSA_INFO) ${SSA_ERROR}

.PHONY: clean utssahelp utssacli utssamount

ssacli: $(SSACLI_SOURCES) $(SSAHELP_SOURCES) $(SSA_API_SOURCES) $(SSA_API_CFLAGS )
	gcc -o ssacli $(SSA_CFLAGS) $(SSA_API_CFLAGS) $(SSACLI_SOURCES) $(SSAHELP_SOURCES) $(SSA_API_SOURCES) 

# UNIT TESTS

ut:
	@echo BEGIN ALL UNIT TESTS
	make utssahelp
	make utssacli
	make utssamount
	@echo ALL UNIT TESTS SUCCESS

ut_ssacli: $(SSACLI_SOURCES)
	gcc -o ./ut_ssacli $(SSA_CFLAGS_UT) $(SSACLI_SOURCES)

utssacli: ./ut_ssacli
	./ut_ssacli

ut_ssahelp: $(SSAHELP_SOURCES)
	gcc -o ./ut_ssahelp $(SSA_CFLAGS_UT) $(SSA_CFLAGS_HELP) $(SSAHELP_SOURCES)

utssahelp: ./ut_ssahelp
	./ut_ssahelp

ut_ssamount: $(SSAMOUNT_SOURCES) 
	gcc -o ./ut_ssamount $(SSA_CFLAGS_UT) $(SSA_CFLAGS_MOUNT) $(SSA_CFLAGS_HELP) $(SSAMOUNT_SOURCES)

utssamount: ./ut_ssamount
	./ut_ssamount

clean:
	rm -rf $(CLEANFILES)

