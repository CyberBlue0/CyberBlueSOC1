# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841347");
  script_cve_id("CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0777", "CVE-2013-0778", "CVE-2013-0779", "CVE-2013-0780", "CVE-2013-0781", "CVE-2013-0782", "CVE-2013-0783", "CVE-2013-0784");
  script_tag(name:"creation_date", value:"2013-03-05 04:15:31 +0000 (Tue, 05 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1729-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1729-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1729-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1134409");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1729-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1729-1 fixed vulnerabilities in Firefox. This update introduced a
regression which sometimes resulted in freezes and crashes when using
multiple tabs with images displayed. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Olli Pettay, Christoph Diehl, Gary Kwong, Jesse Ruderman, Andrew McCreight,
 Joe Drew, Wayne Mery, Alon Zakai, Christian Holler, Gary Kwong, Luke
 Wagner, Terrence Cole, Timothy Nikkel, Bill McCloskey, and Nicolas Pierron
 discovered multiple memory safety issues affecting Firefox. If the user
 were tricked into opening a specially crafted page, an attacker could
 possibly exploit these to cause a denial of service via application crash.
 (CVE-2013-0783, CVE-2013-0784)

 Atte Kettunen discovered that Firefox could perform an out-of-bounds read
 while rendering GIF format images. An attacker could exploit this to crash
 Firefox. (CVE-2013-0772)

 Boris Zbarsky discovered that Firefox did not properly handle some wrapped
 WebIDL objects. If the user were tricked into opening a specially crafted
 page, an attacker could possibly exploit this to cause a denial of service
 via application crash, or potentially execute code with the privileges of
 the user invoking Firefox. (CVE-2013-0765)

 Bobby Holley discovered vulnerabilities in Chrome Object Wrappers (COW) and
 System Only Wrappers (SOW). If a user were tricked into opening a specially
 crafted page, a remote attacker could exploit this to bypass security
 protections to obtain sensitive information or potentially execute code
 with the privileges of the user invoking Firefox. (CVE-2013-0773)

 Frederik Braun discovered that Firefox made the location of the active
 browser profile available to JavaScript workers. (CVE-2013-0774)

 A use-after-free vulnerability was discovered in Firefox. An attacker could
 potentially exploit this to execute code with the privileges of the user
 invoking Firefox. (CVE-2013-0775)

 Michal Zalewski discovered that Firefox would not always show the correct
 address when cancelling a proxy authentication prompt. A remote attacker
 could exploit this to conduct URL spoofing and phishing attacks.
 (CVE-2013-0776)

 Abhishek Arya discovered several problems related to memory handling. If
 the user were tricked into opening a specially crafted page, an attacker
 could possibly exploit these to cause a denial of service via application
 crash, or potentially execute code with the privileges of the user invoking
 Firefox. (CVE-2013-0777, CVE-2013-0778, CVE-2013-0779, CVE-2013-0780,
 CVE-2013-0781, CVE-2013-0782)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
