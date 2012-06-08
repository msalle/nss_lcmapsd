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

# Library
nssmoddir = @NSSMODDIR@
nssmod_LTLIBRARIES = libnss_lcmapsd.la
libnss_lcmapsd_la_LDFLAGS = -version-info 2
libnss_lcmapsd_la_SOURCES = nss_lcmapsd.c

# Test program
bin_PROGRAMS = nss_lcmapsd_test
nss_lcmapsd_test_CFLAGS = -DMAKE_A_OUT
nss_lcmapsd_test_SOURCES = nss_lcmapsd.c
