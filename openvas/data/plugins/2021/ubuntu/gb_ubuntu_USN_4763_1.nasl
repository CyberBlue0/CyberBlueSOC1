# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844863");
  script_cve_id("CVE-2021-25289", "CVE-2021-25290", "CVE-2021-25291", "CVE-2021-25292", "CVE-2021-25293", "CVE-2021-27921", "CVE-2021-27922", "CVE-2021-27923");
  script_tag(name:"creation_date", value:"2021-03-12 04:00:20 +0000 (Fri, 12 Mar 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-15 07:15:00 +0000 (Thu, 15 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4763-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4763-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4763-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pillow' package(s) announced via the USN-4763-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Pillow incorrectly handled certain Tiff image files.
If a user or automated system were tricked into opening a specially-crafted
Tiff file, a remote attacker could cause Pillow to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 20.04 LTS and Ubuntu 20.10. (CVE-2021-25289,
CVE-2021-25291)

It was discovered that Pillow incorrectly handled certain Tiff image files.
If a user or automated system were tricked into opening a specially-crafted
Tiff file, a remote attacker could cause Pillow to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2021-25290)

It was discovered that Pillow incorrectly handled certain PDF files. If a
user or automated system were tricked into opening a specially-crafted
PDF file, a remote attacker could cause Pillow to hang, resulting in a
denial of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04
LTS, and Ubuntu 20.10. (CVE-2021-25292)

It was discovered that Pillow incorrectly handled certain SGI image files.
If a user or automated system were tricked into opening a specially-crafted
SGI file, a remote attacker could possibly cause Pillow to crash,
resulting in a denial of service. This issue only affected Ubuntu 18.04
LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10. (CVE-2021-25293)

Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that
Pillow incorrectly handled certain BLP files. If a user or automated system
were tricked into opening a specially-crafted BLP file, a remote attacker
could possibly cause Pillow to consume resources, resulting in a denial of
service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
Ubuntu 20.10. (CVE-2021-27921)

Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that
Pillow incorrectly handled certain ICNS files. If a user or automated
system were tricked into opening a specially-crafted ICNS file, a remote
attacker could possibly cause Pillow to consume resources, resulting in a
denial of service. (CVE-2021-27922)

Jiayi Lin, Luke Shaffer, Xinran Xie, and Akshay Ajayan discovered that
Pillow incorrectly handled certain ICO files. If a user or automated
system were tricked into opening a specially-crafted ICO file, a remote
attacker could possibly cause Pillow to consume resources, resulting in a
denial of service. (CVE-2021-27922)");

  script_tag(name:"affected", value:"'pillow' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
