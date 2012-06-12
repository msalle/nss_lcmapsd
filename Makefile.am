# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
#     Mischa Sall\'e <msalle@nikhef.nl>
#

AM_CPPFLAGS = -DNSS_LCMAPSD_CONF=\"@CONFIG_FILE@\"
AM_CFLAGS = \
    -Wall \
    -Wuninitialized -Wbad-function-cast -Wcast-align -Wcast-qual \
    -Wmissing-prototypes -Wpointer-arith -Wredundant-decls \
    -Wshadow -Wstrict-prototypes -Wpointer-arith -Wno-long-long -Wundef

EXTRA_DIST = LICENSE \
	     bootstrap

# Library
lib_LTLIBRARIES = libnss_lcmapsd.la
libnss_lcmapsd_la_LDFLAGS = -module -version-info 2:0:0
libnss_lcmapsd_la_SOURCES = nss_lcmapsd.c nss_lcmapsd.h nss_lcmapsd_conf.c

# Test program
sbin_PROGRAMS = nss_lcmapsd_test
nss_lcmapsd_test_CFLAGS = -DMAKE_A_OUT
nss_lcmapsd_test_SOURCES = nss_lcmapsd.c nss_lcmapsd.h nss_lcmapsd_conf.c
