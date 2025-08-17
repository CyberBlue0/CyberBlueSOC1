# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844978");
  script_cve_id("CVE-2017-8872", "CVE-2019-20388", "CVE-2020-24977", "CVE-2021-3516", "CVE-2021-3517", "CVE-2021-3518", "CVE-2021-3537", "CVE-2021-3541");
  script_tag(name:"creation_date", value:"2021-06-18 03:00:27 +0000 (Fri, 18 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 11:15:00 +0000 (Thu, 08 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4991-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4991-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-4991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yunho Kim discovered that libxml2 incorrectly handled certain error
conditions. A remote attacker could exploit this with a crafted XML file to
cause a denial of service, or possibly cause libxml2 to expose sensitive
information. This issue only affected Ubuntu 14.04 ESM, and Ubuntu 16.04
ESM. (CVE-2017-8872)

Zhipeng Xie discovered that libxml2 incorrectly handled certain XML
schemas. A remote attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM,
and Ubuntu 18.04 LTS. (CVE-2019-20388)

It was discovered that libxml2 incorrectly handled invalid UTF-8 input. A
remote attacker could possibly exploit this with a crafted XML file to
cause libxml2 to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM, Ubuntu 18.04 LTS, Ubuntu 20.04
LTS and Ubuntu 20.10. (CVE-2020-24977)

It was discovered that libxml2 incorrectly handled invalid UTF-8 input. A
remote attacker could possibly exploit this with a crafted XML file to
cause libxml2 to crash, resulting in a denial of service. (CVE-2021-3517)

It was discovered that libxml2 did not properly handle certain crafted XML
files. A local attacker could exploit this with a crafted input to cause
libxml2 to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2021-3516, CVE-2021-3518)

It was discovered that libxml2 incorrectly handled error states. A remote
attacker could exploit this with a crafted XML file to cause libxml2 to
crash, resulting in a denial of service. (CVE-2021-3537)

Sebastian Pipping discovered that libxml2 did not properly handle certain
crafted XML files. A remote attacker could exploit this with a crafted XML
file to cause libxml2 to crash, resulting in a denial of service. This
issue only affected Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04.
(CVE-2021-3541)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
