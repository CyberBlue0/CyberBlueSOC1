# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841722");
  script_cve_id("CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1489");
  script_tag(name:"creation_date", value:"2014-02-20 09:49:03 +0000 (Thu, 20 Feb 2014)");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2102-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2102-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2102-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1274468");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2102-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2102-1 fixed vulnerabilities in Firefox. The update introduced a
regression which could make Firefox crash under some circumstances. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Christian Holler, Terrence Cole, Jesse Ruderman, Gary Kwong, Eric
 Rescorla, Jonathan Kew, Dan Gohman, Ryan VanderMeulen, Carsten Book,
 Andrew Sutherland, Byron Campen, Nicholas Nethercote, Paul Adenot, David
 Baron, Julian Seward and Sotaro Ikeda discovered multiple memory safety
 issues in Firefox. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit these to cause a
 denial of service via application crash, or execute arbitrary code with
 the privileges of the user invoking Firefox. (CVE-2014-1477,
 CVE-2014-1478)

 Cody Crews discovered a method to bypass System Only Wrappers. An attacker
 could potentially exploit this to steal confidential data or execute code
 with the privileges of the user invoking Firefox. (CVE-2014-1479)

 Jordi Chancel discovered that the downloads dialog did not implement a
 security timeout before button presses are processed. An attacker could
 potentially exploit this to conduct clickjacking attacks. (CVE-2014-1480)

 Fredrik Lonnqvist discovered a use-after-free in Firefox. An attacker
 could potentially exploit this to cause a denial of service via
 application crash, or execute arbitrary code with the privileges of the
 user invoking Firefox. (CVE-2014-1482)

 Jordan Milne discovered a timing flaw when using document.elementFromPoint
 and document.caretPositionFromPoint on cross-origin iframes. An attacker
 could potentially exploit this to steal confidential information.
 (CVE-2014-1483)

 Frederik Braun discovered that the CSP implementation in Firefox did not
 handle XSLT stylesheets in accordance with the specification, potentially
 resulting in unexpected script execution in some circumstances
 (CVE-2014-1485)

 Arthur Gerkis discovered a use-after-free in Firefox. An attacker could
 potentially exploit this to cause a denial of service via application
 crash, or execute arbitrary code with the privileges of the user invoking
 Firefox. (CVE-2014-1486)

 Masato Kinugawa discovered a cross-origin information leak in web worker
 error messages. An attacker could potentially exploit this to steal
 confidential information. (CVE-2014-1487)

 Yazan Tommalieh discovered that web pages could activate buttons on the
 default Firefox startpage (about:home) in some circumstances. An attacker
 could potentially exploit this to cause data loss by triggering a session
 restore. (CVE-2014-1489)

 Soeren Balko discovered a crash in Firefox when terminating web workers
 running asm.js code in some circumstances. An attacker could potentially
 exploit this to execute arbitrary code with the privileges of the user
 invoking Firefox. (CVE-2014-1488)

 Several issues ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
