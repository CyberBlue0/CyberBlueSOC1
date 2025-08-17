# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703896");
  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679");
  script_tag(name:"creation_date", value:"2017-06-21 22:00:00 +0000 (Wed, 21 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-3896)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3896");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3896");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-3896 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2017-3167

Emmanuel Dreyfus reported that the use of ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may lead to authentication requirements being bypassed.

CVE-2017-3169

Vasileios Panopoulos of AdNovum Informatik AG discovered that mod_ssl may dereference a NULL pointer when third-party modules call ap_hook_process_connection() during an HTTP request to an HTTPS port leading to a denial of service.

CVE-2017-7659

Robert Swiecki reported that a specially crafted HTTP/2 request could cause mod_http2 to dereference a NULL pointer and crash the server process.

CVE-2017-7668

Javier Jimenez reported that the HTTP strict parsing contains a flaw leading to a buffer overread in ap_find_token(). A remote attacker can take advantage of this flaw by carefully crafting a sequence of request headers to cause a segmentation fault, or to force ap_find_token() to return an incorrect value.

CVE-2017-7679

ChenQin and Hanno Boeck reported that mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.

For the oldstable distribution (jessie), these problems have been fixed in version 2.4.10-10+deb8u9. The oldstable distribution (jessie) is not affected by CVE-2017-7659.

For the stable distribution (stretch), these problems have been fixed in version 2.4.25-3+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 2.4.25-4.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);