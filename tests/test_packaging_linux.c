/*
 * tests/test_packaging_linux.c
 *
 * Validates that packaging files exist and contain the expected fields.
 *
 * Checks:
 *   packaging/debian/control  — Debian source + binary package metadata
 *   packaging/debian/rules    — Build script
 *   packaging/debian/changelog— Changelog
 *   packaging/debian/rufus.install — Install file list
 *   packaging/flatpak/ie.akeo.rufus.yaml — Flatpak manifest
 *   packaging/arch/PKGBUILD   — Arch Linux package build script
 *   packaging/rpm/rufus.spec  — RPM spec file
 */
#define RUFUS_TEST 1

#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/* Resolve a path relative to the packaging/ directory.
 * Searches ../packaging/ and ../../packaging/ (when run from tests/ or repo root). */
static const char *pkg_path(const char *rel)
{
    static char buf[512];
    snprintf(buf, sizeof(buf), "packaging/%s", rel);
    if (access(buf, R_OK) == 0) return buf;
    snprintf(buf, sizeof(buf), "../packaging/%s", rel);
    if (access(buf, R_OK) == 0) return buf;
    return NULL;
}

/* Read entire file into malloc'd NUL-terminated buffer. Returns NULL on error. */
static char *slurp(const char *path)
{
    if (!path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* ------------------------------------------------------------------ */
/* Debian control                                                       */
/* ------------------------------------------------------------------ */

TEST(debian_control_exists) {
    const char *p = pkg_path("debian/control");
    CHECK(p != NULL);
    CHECK(access(p, R_OK) == 0);
}

TEST(debian_control_has_source) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "Source: rufus") != NULL);
    free(c);
}

TEST(debian_control_has_package) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "Package: rufus") != NULL);
    free(c);
}

TEST(debian_control_has_architecture) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "Architecture:") != NULL);
    free(c);
}

TEST(debian_control_has_depends) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "Depends:") != NULL);
    free(c);
}

TEST(debian_control_has_build_depends) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "Build-Depends:") != NULL);
    free(c);
}

TEST(debian_control_has_description) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "Description:") != NULL);
    free(c);
}

TEST(debian_control_lists_gtk) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "gtk") != NULL || strstr(c, "GTK") != NULL);
    free(c);
}

TEST(debian_control_lists_polkit) {
    char *c = slurp(pkg_path("debian/control"));
    if (!c) return;
    CHECK(strstr(c, "polkit") != NULL || strstr(c, "policykit") != NULL);
    free(c);
}

/* ------------------------------------------------------------------ */
/* Debian rules                                                         */
/* ------------------------------------------------------------------ */

TEST(debian_rules_exists) {
    const char *p = pkg_path("debian/rules");
    CHECK(p != NULL);
    CHECK(access(p, R_OK) == 0);
}

TEST(debian_rules_invokes_configure_with_os_linux) {
    char *c = slurp(pkg_path("debian/rules"));
    if (!c) return;
    CHECK(strstr(c, "--with-os=linux") != NULL);
    free(c);
}

TEST(debian_rules_uses_debhelper) {
    char *c = slurp(pkg_path("debian/rules"));
    if (!c) return;
    CHECK(strstr(c, "dh ") != NULL || strstr(c, "dh_") != NULL);
    free(c);
}

/* ------------------------------------------------------------------ */
/* Debian changelog                                                     */
/* ------------------------------------------------------------------ */

TEST(debian_changelog_exists) {
    const char *p = pkg_path("debian/changelog");
    CHECK(p != NULL);
    CHECK(access(p, R_OK) == 0);
}

TEST(debian_changelog_has_rufus_entry) {
    char *c = slurp(pkg_path("debian/changelog"));
    if (!c) return;
    CHECK(strstr(c, "rufus") != NULL);
    free(c);
}

/* ------------------------------------------------------------------ */
/* Debian rufus.install                                                 */
/* ------------------------------------------------------------------ */

TEST(debian_install_exists) {
    const char *p = pkg_path("debian/rufus.install");
    CHECK(p != NULL);
    CHECK(access(p, R_OK) == 0);
}

TEST(debian_install_lists_binary) {
    char *c = slurp(pkg_path("debian/rufus.install"));
    if (!c) return;
    CHECK(strstr(c, "usr/bin/rufus") != NULL);
    free(c);
}

TEST(debian_install_lists_desktop_file) {
    char *c = slurp(pkg_path("debian/rufus.install"));
    if (!c) return;
    CHECK(strstr(c, ".desktop") != NULL);
    free(c);
}

TEST(debian_install_lists_polkit_policy) {
    char *c = slurp(pkg_path("debian/rufus.install"));
    if (!c) return;
    CHECK(strstr(c, "polkit") != NULL || strstr(c, ".policy") != NULL);
    free(c);
}

TEST(debian_install_lists_man_page) {
    char *c = slurp(pkg_path("debian/rufus.install"));
    if (!c) return;
    CHECK(strstr(c, "rufus.1") != NULL);
    free(c);
}

/* ------------------------------------------------------------------ */
/* Flatpak manifest                                                     */
/* ------------------------------------------------------------------ */

TEST(flatpak_manifest_exists) {
    const char *p = pkg_path("flatpak/ie.akeo.rufus.yaml");
    CHECK(p != NULL);
    CHECK(access(p, R_OK) == 0);
}

TEST(flatpak_manifest_has_app_id) {
    char *c = slurp(pkg_path("flatpak/ie.akeo.rufus.yaml"));
    if (!c) return;
    CHECK(strstr(c, "ie.akeo.rufus") != NULL);
    free(c);
}

TEST(flatpak_manifest_has_device_block_permission) {
    char *c = slurp(pkg_path("flatpak/ie.akeo.rufus.yaml"));
    if (!c) return;
    CHECK(strstr(c, "--device=block") != NULL || strstr(c, "device=block") != NULL);
    free(c);
}

TEST(flatpak_manifest_has_network_permission) {
    char *c = slurp(pkg_path("flatpak/ie.akeo.rufus.yaml"));
    if (!c) return;
    CHECK(strstr(c, "--share=network") != NULL || strstr(c, "share=network") != NULL);
    free(c);
}

TEST(flatpak_manifest_has_download_filesystem) {
    char *c = slurp(pkg_path("flatpak/ie.akeo.rufus.yaml"));
    if (!c) return;
    CHECK(strstr(c, "xdg-download") != NULL);
    free(c);
}

TEST(flatpak_manifest_has_runtime) {
    char *c = slurp(pkg_path("flatpak/ie.akeo.rufus.yaml"));
    if (!c) return;
    CHECK(strstr(c, "runtime:") != NULL);
    free(c);
}

TEST(flatpak_manifest_has_rufus_module) {
    char *c = slurp(pkg_path("flatpak/ie.akeo.rufus.yaml"));
    if (!c) return;
    CHECK(strstr(c, "rufus") != NULL);
    free(c);
}

/* ------------------------------------------------------------------ */
/* Arch PKGBUILD                                                        */
/* ------------------------------------------------------------------ */

TEST(arch_pkgbuild_exists) {
    const char *p = pkg_path("arch/PKGBUILD");
    CHECK(p != NULL);
    CHECK(access(p, R_OK) == 0);
}

TEST(arch_pkgbuild_has_pkgname) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "pkgname=rufus") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_pkgver) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "pkgver=") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_depends_gtk) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "gtk") != NULL || strstr(c, "GTK") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_depends_polkit) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "polkit") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_configure_with_os_linux) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "--with-os=linux") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_build_function) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "build()") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_package_function) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "package()") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_license) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "license=") != NULL);
    free(c);
}

TEST(arch_pkgbuild_has_url) {
    char *c = slurp(pkg_path("arch/PKGBUILD"));
    if (!c) return;
    CHECK(strstr(c, "url=") != NULL && strstr(c, "github") != NULL);
    free(c);
}

/* ------------------------------------------------------------------ */
/* RPM spec                                                             */
/* ------------------------------------------------------------------ */

TEST(rpm_spec_exists) {
    const char *p = pkg_path("rpm/rufus.spec");
    CHECK(p != NULL);
    CHECK(access(p, R_OK) == 0);
}

TEST(rpm_spec_has_name) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "Name:") != NULL && strstr(c, "rufus") != NULL);
    free(c);
}

TEST(rpm_spec_has_version) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "Version:") != NULL);
    free(c);
}

TEST(rpm_spec_has_build_requires_gtk) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "BuildRequires:") != NULL && strstr(c, "gtk") != NULL);
    free(c);
}

TEST(rpm_spec_has_requires_polkit) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "Requires:") != NULL && strstr(c, "polkit") != NULL);
    free(c);
}

TEST(rpm_spec_has_configure_with_os_linux) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "--with-os=linux") != NULL);
    free(c);
}

TEST(rpm_spec_has_files_section) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "%files") != NULL);
    free(c);
}

TEST(rpm_spec_has_changelog) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "%changelog") != NULL);
    free(c);
}

TEST(rpm_spec_has_license) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "License:") != NULL && strstr(c, "GPL") != NULL);
    free(c);
}

TEST(rpm_spec_lists_binary) {
    char *c = slurp(pkg_path("rpm/rufus.spec"));
    if (!c) return;
    CHECK(strstr(c, "%{_bindir}/rufus") != NULL);
    free(c);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== Debian package tests ===\n");
    RUN(debian_control_exists);
    RUN(debian_control_has_source);
    RUN(debian_control_has_package);
    RUN(debian_control_has_architecture);
    RUN(debian_control_has_depends);
    RUN(debian_control_has_build_depends);
    RUN(debian_control_has_description);
    RUN(debian_control_lists_gtk);
    RUN(debian_control_lists_polkit);
    RUN(debian_rules_exists);
    RUN(debian_rules_invokes_configure_with_os_linux);
    RUN(debian_rules_uses_debhelper);
    RUN(debian_changelog_exists);
    RUN(debian_changelog_has_rufus_entry);
    RUN(debian_install_exists);
    RUN(debian_install_lists_binary);
    RUN(debian_install_lists_desktop_file);
    RUN(debian_install_lists_polkit_policy);
    RUN(debian_install_lists_man_page);

    printf("\n=== Flatpak manifest tests ===\n");
    RUN(flatpak_manifest_exists);
    RUN(flatpak_manifest_has_app_id);
    RUN(flatpak_manifest_has_device_block_permission);
    RUN(flatpak_manifest_has_network_permission);
    RUN(flatpak_manifest_has_download_filesystem);
    RUN(flatpak_manifest_has_runtime);
    RUN(flatpak_manifest_has_rufus_module);

    printf("\n=== Arch PKGBUILD tests ===\n");
    RUN(arch_pkgbuild_exists);
    RUN(arch_pkgbuild_has_pkgname);
    RUN(arch_pkgbuild_has_pkgver);
    RUN(arch_pkgbuild_has_depends_gtk);
    RUN(arch_pkgbuild_has_depends_polkit);
    RUN(arch_pkgbuild_has_configure_with_os_linux);
    RUN(arch_pkgbuild_has_build_function);
    RUN(arch_pkgbuild_has_package_function);
    RUN(arch_pkgbuild_has_license);
    RUN(arch_pkgbuild_has_url);

    printf("\n=== RPM spec tests ===\n");
    RUN(rpm_spec_exists);
    RUN(rpm_spec_has_name);
    RUN(rpm_spec_has_version);
    RUN(rpm_spec_has_build_requires_gtk);
    RUN(rpm_spec_has_requires_polkit);
    RUN(rpm_spec_has_configure_with_os_linux);
    RUN(rpm_spec_has_files_section);
    RUN(rpm_spec_has_changelog);
    RUN(rpm_spec_has_license);
    RUN(rpm_spec_lists_binary);

    TEST_RESULTS();
}
