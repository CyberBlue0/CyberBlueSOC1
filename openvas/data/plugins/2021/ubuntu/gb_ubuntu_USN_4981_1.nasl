# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844967");
  script_cve_id("CVE-2021-28651", "CVE-2021-28652", "CVE-2021-28662", "CVE-2021-31806", "CVE-2021-31807", "CVE-2021-31808", "CVE-2021-33620");
  script_tag(name:"creation_date", value:"2021-06-04 03:00:37 +0000 (Fri, 04 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4981-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4981-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4981-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid, squid3' package(s) announced via the USN-4981-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joshua Rogers discovered that Squid incorrectly handled requests with the
urn: scheme. A remote attacker could possibly use this issue to cause
Squid to consume resources, leading to a denial of service.
(CVE-2021-28651)

Joshua Rogers discovered that Squid incorrectly handled requests to the
Cache Manager API. A remote attacker with access privileges could possibly
use this issue to cause Squid to consume resources, leading to a denial of
service. This issue was only addressed in Ubuntu 20.04 LTS, Ubuntu 20.10,
and Ubuntu 21.04. (CVE-2021-28652)

Joshua Rogers discovered that Squid incorrectly handled certain response
headers. A remote attacker could possibly use this issue to cause Squid to
crash, resulting in a denial of service. This issue was only affected
Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04. (CVE-2021-28662)

Joshua Rogers discovered that Squid incorrectly handled range request
processing. A remote attacker could possibly use this issue to cause Squid
to crash, resulting in a denial of service. (CVE-2021-31806,
CVE-2021-31807, CVE-2021-31808)

Joshua Rogers discovered that Squid incorrectly handled certain HTTP
responses. A remote attacker could possibly use this issue to cause Squid
to crash, resulting in a denial of service. (CVE-2021-33620)");

  script_tag(name:"affected", value:"'squid, squid3' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
