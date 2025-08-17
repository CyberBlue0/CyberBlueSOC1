# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844417");
  script_cve_id("CVE-2018-12178", "CVE-2018-12180", "CVE-2018-12181", "CVE-2019-14558", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575", "CVE-2019-14586", "CVE-2019-14587");
  script_tag(name:"creation_date", value:"2020-05-01 03:00:46 +0000 (Fri, 01 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4349-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4349-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4349-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the USN-4349-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in the network stack. An unprivileged user
could potentially enable escalation of privilege and/or denial of service.
This issue was already fixed in a previous release for 18.04 LTS and 19.10.
(CVE-2018-12178)

A buffer overflow was discovered in BlockIo service. An unauthenticated user
could potentially enable escalation of privilege, information disclosure and/or
denial of service. This issue was already fixed in a previous release for 18.04
LTS and 19.10. (CVE-2018-12180)

A stack overflow was discovered in bmp. An unprivileged user
could potentially enable denial of service or elevation of privilege via
local access. This issue was already fixed in a previous release for 18.04
LTS and 19.10. (CVE-2018-12181)

It was discovered that memory was not cleared before free that could lead
to potential password leak. (CVE-2019-14558)

A memory leak was discovered in ArpOnFrameRcvdDpc. An attacker could
possibly use this issue to cause a denial of service or other unspecified
impact. (CVE-2019-14559)

An integer overflow was discovered in MdeModulePkg/PiDxeS3BootScriptLib.
An attacker could possibly use this issue to cause a denial of service or
other unspecified impact. (CVE-2019-14563)

It was discovered that the affected version doesn't properly check whether an
unsigned EFI file should be allowed or not. An attacker could possibly load
unsafe content by bypassing the verification. (CVE-2019-14575)

It was discovered that original configuration runtime memory is freed, but it
is still exposed to the OS runtime. (CVE-2019-14586)

A double-unmap was discovered in TRB creation. An attacker could use it to
cause a denial of service or other unspecified impact. (CVE-2019-14587)");

  script_tag(name:"affected", value:"'edk2' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
