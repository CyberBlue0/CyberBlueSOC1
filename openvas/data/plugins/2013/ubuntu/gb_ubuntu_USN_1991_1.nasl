# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841605");
  script_cve_id("CVE-2012-4412", "CVE-2012-4424", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332");
  script_tag(name:"creation_date", value:"2013-10-29 11:20:28 +0000 (Tue, 29 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1991-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1991-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc' package(s) announced via the USN-1991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GNU C Library incorrectly handled the strcoll()
function. An attacker could use this issue to cause a denial of service, or
possibly execute arbitrary code. (CVE-2012-4412, CVE-2012-4424)

It was discovered that the GNU C Library incorrectly handled multibyte
characters in the regular expression matcher. An attacker could use this
issue to cause a denial of service. (CVE-2013-0242)

It was discovered that the GNU C Library incorrectly handled large numbers
of domain conversion results in the getaddrinfo() function. An attacker
could use this issue to cause a denial of service. (CVE-2013-1914)

It was discovered that the GNU C Library readdir_r() function incorrectly
handled crafted NTFS or CIFS images. An attacker could use this issue to
cause a denial of service, or possibly execute arbitrary code.
(CVE-2013-4237)

It was discovered that the GNU C Library incorrectly handled memory
allocation. An attacker could use this issue to cause a denial of service.
(CVE-2013-4332)");

  script_tag(name:"affected", value:"'eglibc' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
