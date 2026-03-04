/*
 * Rufus: The Reliable USB Formatting Utility
 * Linux implementation: dos_locale.c — DOS locale data
 * Copyright © 2011-2024 Pete Batard <pete@akeo.ie>
 * Copyright © 2025 PsychedelicPalimpsest
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Linux implementation: dos_locale.c
 * SetDOSLocale — create AUTOEXEC.BAT and FDCONFIG.SYS for FreeDOS,
 * using the system XKB keyboard layout when available.
 *
 * The XKB layout is read from /etc/default/keyboard (XKBLAYOUT= line).
 * It is mapped to the 2-letter FreeDOS keyboard code and the corresponding
 * OEM codepage.  When no matching layout is found, US/CP437 is used.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "rufus.h"
#include "dos.h"

/* ----------------------------------------------------------------
 * XKB layout -> (DOS keyboard code, OEM codepage) mapping
 * ----------------------------------------------------------------
 * FreeDOS keyboard codes from keyboard.sys / keybrd2.sys:
 *   keyboard.sys  : be br cf co cz dk dv fr gr hu it jp la lh nl no
 *                   pl po rh sf sg sk sp su sv uk us yu
 *   keybrd2.sys   : bg ce gk is ro ru rx tr tt yc
 * ---------------------------------------------------------------- */
typedef struct {
    const char* xkb;    /* XKB layout short name (lower-case) */
    const char* dos_kb; /* FreeDOS 2-letter keyboard code     */
    int         cp;     /* default OEM code page              */
} xkb_to_dos_t;

/* Sorted by XKB name for readability; lookup is linear (table is small). */
static const xkb_to_dos_t xkb_dos_table[] = {
    { "al",  "sq",  852 },  /* Albanian */
    { "am",  "hy",  899 },  /* Armenian */
    { "az",  "az",  850 },  /* Azerbaijani */
    { "ba",  "yu",  852 },  /* Bosnian */
    { "be",  "be",  850 },  /* Belgian French */
    { "bg",  "bg",  855 },  /* Bulgarian */
    { "br",  "br",  850 },  /* Brazilian ABNT */
    { "by",  "bl",  855 },  /* Belarusian */
    { "ca",  "cf",  850 },  /* Canadian French */
    { "ch",  "sg",  850 },  /* Swiss German */
    { "cz",  "cz",  852 },  /* Czech */
    { "de",  "gr",  850 },  /* German */
    { "dk",  "dk",  850 },  /* Danish */
    { "ee",  "et",  775 },  /* Estonian */
    { "es",  "sp",  850 },  /* Spanish */
    { "fi",  "su",  850 },  /* Finnish */
    { "fo",  "fo",  850 },  /* Faroese */
    { "fr",  "fr",  850 },  /* French */
    { "gb",  "uk",  850 },  /* British English */
    { "ge",  "ka",  850 },  /* Georgian */
    { "gk",  "gk",  737 },  /* Greek (alternate name) */
    { "gr",  "gk",  737 },  /* Greek */
    { "hr",  "yu",  852 },  /* Croatian */
    { "hu",  "hu",  852 },  /* Hungarian */
    { "il",  "il",  862 },  /* Hebrew */
    { "ir",  "ar",  864 },  /* Persian/Farsi */
    { "is",  "is",  850 },  /* Icelandic */
    { "it",  "it",  850 },  /* Italian */
    { "jp",  "jp",  932 },  /* Japanese */
    { "kk",  "kk",  850 },  /* Kazakh */
    { "ko",  "us",  949 },  /* Korean (no FreeDOS kb) */
    { "kr",  "us",  949 },  /* Korean alternate */
    { "ky",  "ky",  850 },  /* Kyrgyz */
    { "la",  "la",  850 },  /* Latin American Spanish */
    { "lt",  "lt",  775 },  /* Lithuanian */
    { "lv",  "lv",  775 },  /* Latvian */
    { "mk",  "mk",  855 },  /* Macedonian */
    { "mn",  "mn",  850 },  /* Mongolian */
    { "mt",  "mt",  850 },  /* Maltese */
    { "nl",  "nl",  850 },  /* Dutch */
    { "no",  "no",  850 },  /* Norwegian */
    { "ph",  "ph",  850 },  /* Filipino */
    { "pl",  "pl",  852 },  /* Polish */
    { "pt",  "po",  850 },  /* Portuguese */
    { "ro",  "ro",  852 },  /* Romanian */
    { "rs",  "yu",  855 },  /* Serbian */
    { "ru",  "ru",  866 },  /* Russian */
    { "se",  "sv",  850 },  /* Swedish */
    { "si",  "sl",  852 },  /* Slovenian */
    { "sk",  "sk",  852 },  /* Slovak */
    { "sq",  "sq",  852 },  /* Albanian (alternate) */
    { "sr",  "ru",  855 },  /* Serbian Cyrillic */
    { "sv",  "sv",  850 },  /* Swedish (alternate) */
    { "th",  "us",  874 },  /* Thai (no FreeDOS kb) */
    { "tj",  "tj",  850 },  /* Tajik */
    { "tm",  "tm",  850 },  /* Turkmen */
    { "tr",  "tr",  857 },  /* Turkish */
    { "ua",  "ur",  866 },  /* Ukrainian */
    { "uk",  "uk",  850 },  /* British (alternate key) */
    { "us",  "us",  437 },  /* US English */
    { "uz",  "uz",  850 },  /* Uzbek */
    { "vn",  "vi",  850 },  /* Vietnamese */
    { "yu",  "yu",  855 },  /* Yugoslav */
    { "zh",  "us",  936 },  /* Chinese (no FreeDOS kb) */
};

/*
 * FreeDOS keyboard driver file lists, mirroring the Windows implementation.
 * kb_driver_for() returns the correct *.SYS filename for a given DOS code.
 *
 * fd_kb1 -> KEYBOARD.SYS (main set)
 * fd_kb2 -> KEYBRD2.SYS  (Cyrillic, Greek, Turkish, Icelandic, Romanian)
 * fd_kb3 -> KEYBRD3.SYS  (Baltic, Armenian, Georgian, Middle-Eastern, etc.)
 * fd_kb4 -> KEYBRD4.SYS  (extended / special)
 */
static const char* const fd_kb1[] = {
    "be","br","cf","co","cz","dk","dv","fr","gr","hu",
    "it","jp","la","lh","nl","no","pl","po","rh","sf",
    "sg","sk","sp","su","sv","uk","us","yu", NULL
};
static const char* const fd_kb2[] = {
    "bg","ce","gk","is","ro","ru","rx","tr","tt","yc", NULL
};
static const char* const fd_kb3[] = {
    "az","bl","et","fo","hy","il","ka","kk","ky","lt",
    "lv","mk","mn","mt","ph","sq","tj","tm","ur","uz","vi", NULL
};
static const char* const fd_kb4[] = {
    "ar","bn","bx","fx","ix","kx","ne","ng","px","sx","ux", NULL
};
static const char* const* const fd_kb_lists[] = { fd_kb1, fd_kb2, fd_kb3, fd_kb4 };
static const char* const fd_kb_files[] = {
    "KEYBOARD.SYS", "KEYBRD2.SYS", "KEYBRD3.SYS", "KEYBRD4.SYS"
};

/* Return the FreeDOS keyboard driver filename for the given 2-letter DOS code. */
static const char* kb_driver_for(const char* dos_kb)
{
    for (size_t list = 0; list < ARRAYSIZE(fd_kb_lists); list++) {
        for (size_t i = 0; fd_kb_lists[list][i] != NULL; i++) {
            if (strcmp(fd_kb_lists[list][i], dos_kb) == 0)
                return fd_kb_files[list];
        }
    }
    return fd_kb_files[0]; /* default: KEYBOARD.SYS */
}

/*
 * Return the FreeDOS EGA/CPX font file for a given OEM codepage.
 * Mirrors the Windows fd_get_ega() function.
 */
static const char* ega_driver_for(int cp)
{
    switch (cp) {
    case  437: case  850: case  852: case  853:
    case  857: case  858:
        return "ega.cpx";
    case  775: case  859: case 1116: case 1117:
    case 1118: case 1119:
        return "ega2.cpx";
    case  771: case  772: case  808: case  855:
    case  866: case  872:
        return "ega3.cpx";
    case  848: case  849: case 1125: case 1131:
    case 3012:
        return "ega4.cpx";
    case  113: case  737: case  851: case  869:
        return "ega5.cpx";
    case  899:
        return "ega6.cpx";
    case  770: case  773: case  774: case  777:
    case  778:
        return "ega8.cpx";
    case  860: case  861: case  863: case  865:
    case  867:
        return "ega9.cpx";
    case  667: case  668: case  790: case  991:
    case 3845:
        return "ega10.cpx";
    default:
        return "ega.cpx"; /* safe fallback */
    }
}

/* ----------------------------------------------------------------
 * Injection support for unit testing
 * ---------------------------------------------------------------- */
#ifdef RUFUS_TEST
static const char* s_injected_xkb       = NULL;
static const char* s_etc_default_kb_path = NULL;
static const char* s_vconsole_path       = NULL;

void dos_locale_set_xkb_layout(const char* layout)          { s_injected_xkb       = layout; }
void dos_locale_set_etc_default_keyboard_path(const char* p) { s_etc_default_kb_path = p; }
void dos_locale_set_vconsole_path(const char* p)             { s_vconsole_path       = p; }
#endif /* RUFUS_TEST */

/* ----------------------------------------------------------------
 * get_xkb_layout() - returns a pointer to a static buffer holding
 * the detected XKB layout (e.g. "de", "fr", "us").
 * Falls back to "us" on any error.
 *
 * Sources tried in order:
 *   1. /etc/default/keyboard XKBLAYOUT=  (Debian/Ubuntu)
 *   2. /etc/vconsole.conf    XKBLAYOUT=  (Arch with X11 config)
 *   3. /etc/vconsole.conf    KEYMAP=     (Fedora/RHEL/Arch console)
 * ---------------------------------------------------------------- */
static const char* get_xkb_layout(void)
{
    static char buf[32];
    strncpy(buf, "us", sizeof(buf));

#ifdef RUFUS_TEST
    if (s_injected_xkb != NULL) {
        strncpy(buf, s_injected_xkb, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        return buf;
    }
#endif

    typedef struct { const char* file; const char* key; } kb_src_t;
#ifdef RUFUS_TEST
    /* When test paths are injected, use them instead of the system paths */
    const char* etc_default_kb = s_etc_default_kb_path ? s_etc_default_kb_path : "/etc/default/keyboard";
    const char* vconsole        = s_vconsole_path       ? s_vconsole_path       : "/etc/vconsole.conf";
#else
    const char* etc_default_kb = "/etc/default/keyboard";
    const char* vconsole        = "/etc/vconsole.conf";
#endif
    const kb_src_t sources[] = {
        { etc_default_kb, "XKBLAYOUT=" },  /* Debian / Ubuntu */
        { vconsole,       "XKBLAYOUT=" },  /* Arch (X11 config) */
        { vconsole,       "KEYMAP="    },  /* Fedora / RHEL / Arch */
    };

    for (size_t src = 0; src < ARRAYSIZE(sources); src++) {
        FILE* f = fopen(sources[src].file, "r");
        if (!f) continue;
        size_t keylen = strlen(sources[src].key);
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), f)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, sources[src].key, keylen) != 0) continue;
            p += keylen;
            if (*p == '"' || *p == '\'') p++;
            size_t i = 0;
            /* Strip variant suffixes (e.g. "de-latin1" -> "de") */
            while (*p && *p != ',' && *p != '"' && *p != '\'' &&
                   *p != '\n' && *p != '\r' && *p != '_' && *p != '-' &&
                   !isspace((unsigned char)*p) &&
                   i < sizeof(buf) - 1) {
                buf[i++] = (char)tolower((unsigned char)*p);
                p++;
            }
            buf[i] = '\0';
            found = 1;
            break;
        }
        fclose(f);
        if (found && buf[0] != '\0')
            return buf;
    }
    return buf;
}

/* ----------------------------------------------------------------
 * xkb_to_dos() - look up a DOS keyboard code for the given XKB
 * layout name (lower-case).  Returns "us" / CP437 if not found.
 * ---------------------------------------------------------------- */
static const char* xkb_to_dos(const char* xkb, int* cp)
{
    for (size_t i = 0; i < ARRAYSIZE(xkb_dos_table); i++) {
        if (strcmp(xkb_dos_table[i].xkb, xkb) == 0) {
            if (cp) *cp = xkb_dos_table[i].cp;
            return xkb_dos_table[i].dos_kb;
        }
    }
    if (cp) *cp = 437;
    return "us";
}

/* ----------------------------------------------------------------
 * SetDOSLocale() - public API
 * ---------------------------------------------------------------- */
BOOL SetDOSLocale(const char* path, BOOL bFreeDOS)
{
    (void)bFreeDOS;  /* always treat as FreeDOS on Linux */

    if (path == NULL) {
        uprintf("SetDOSLocale: NULL path");
        return FALSE;
    }

    const char* xkb = get_xkb_layout();
    int cp = 437;
    const char* kb = xkb_to_dos(xkb, &cp);
    const char* kbdrv = kb_driver_for(kb);

    /* FreeDOS upgrade: CP850 (Latin-1) -> CP858 (Latin-1 with Euro symbol) */
    if (cp == 850)
        cp = 858;

    const char* egadrv = ega_driver_for(cp);

    /* Upper-case DOS keyboard code for display / KEYB.EXE */
    char KB_UPPER[8];
    size_t kblen = strlen(kb);
    for (size_t i = 0; i < kblen && i < sizeof(KB_UPPER) - 1; i++)
        KB_UPPER[i] = (char)toupper((unsigned char)kb[i]);
    KB_UPPER[kblen < sizeof(KB_UPPER) - 1 ? kblen : sizeof(KB_UPPER) - 2] = '\0';

    char filename[MAX_PATH];

    /* For US keyboard with CP437: simple single-language AUTOEXEC.BAT */
    if (strcmp(kb, "us") == 0 && cp == 437) {
        snprintf(filename, sizeof(filename), "%sAUTOEXEC.BAT", path);
        FILE* fd = fopen(filename, "w");
        if (fd == NULL) {
            uprintf_errno("SetDOSLocale: cannot create AUTOEXEC.BAT");
            return FALSE;
        }
        fprintf(fd, "@echo off\r\n");
        fprintf(fd, "set PATH=.;\\;\\LOCALE\r\n");
        fprintf(fd, "echo Using US keyboard with CP437 codepage\r\n");
        fclose(fd);

        snprintf(filename, sizeof(filename), "%sFDCONFIG.SYS", path);
        fd = fopen(filename, "w");
        if (fd != NULL) {
            fprintf(fd, "!DEVICE=\\LOCALE\\DISPLAY.EXE CON=(EGA,,1)\r\n");
            fprintf(fd, "!DEVICE=\\LOCALE\\KEYB.EXE US,437,\\LOCALE\\%s\r\n", kbdrv);
            fclose(fd);
        }
        uprintf("SetDOSLocale: US locale -- created AUTOEXEC.BAT and FDCONFIG.SYS");
        return TRUE;
    }

    /* Non-US keyboard: FDCONFIG.SYS with a language selection menu
     * (native keyboard + US English fallback), matching Windows behaviour. */
    snprintf(filename, sizeof(filename), "%sFDCONFIG.SYS", path);
    FILE* fd = fopen(filename, "w");
    if (fd == NULL) {
        uprintf_errno("SetDOSLocale: cannot create FDCONFIG.SYS");
        return FALSE;
    }
    fprintf(fd, "!MENUCOLOR=7,0\r\nMENU\r\n");
    fprintf(fd, "MENU   FreeDOS Language Selection Menu\r\n");
    fprintf(fd, "MENU   ==================================\r\nMENU\r\n");
    fprintf(fd, "MENUDEFAULT=1,5\r\n");
    fprintf(fd, "MENU 1) Use %s keyboard with CP%d codepage\r\n", KB_UPPER, cp);
    fprintf(fd, "MENU 2) Use US keyboard with CP437 codepage\r\n");
    fprintf(fd, "MENU\r\n");
    fprintf(fd, "12?\r\n");
    fprintf(fd, "!DEVICE=\\LOCALE\\DISPLAY.EXE CON=(EGA,,1)\r\n");
    fprintf(fd, "1 !DEVICE=\\LOCALE\\KEYB.EXE %s,%d,\\LOCALE\\%s\r\n", KB_UPPER, cp, kbdrv);
    fprintf(fd, "2 !DEVICE=\\LOCALE\\KEYB.EXE US,437,\\LOCALE\\%s\r\n", kbdrv);
    fclose(fd);

    /* AUTOEXEC.BAT: use GOTO %%CONFIG%% structure to activate codepage/keyboard
     * for the selected menu option, mirroring Windows SetDOSLocale() exactly. */
    snprintf(filename, sizeof(filename), "%sAUTOEXEC.BAT", path);
    fd = fopen(filename, "w");
    if (fd == NULL) {
        uprintf_errno("SetDOSLocale: cannot create AUTOEXEC.BAT");
        return TRUE;  /* FDCONFIG.SYS already written -- non-fatal */
    }
    fprintf(fd, "@echo off\r\n");
    fprintf(fd, "set PATH=.;\\;\\LOCALE\r\n");
    fprintf(fd, "display con=(ega,,1)\r\n");
    fprintf(fd, "GOTO %%CONFIG%%\r\n");
    fprintf(fd, ":1\r\n");
    fprintf(fd, "mode con codepage prepare=((%d) \\LOCALE\\%s) > NUL\r\n", cp, egadrv);
    fprintf(fd, "mode con codepage select=%d > NUL\r\n", cp);
    fprintf(fd, "keyb %s,,\\LOCALE\\%s\r\n", KB_UPPER, kbdrv);
    fprintf(fd, ":2\r\n");
    fclose(fd);

    uprintf("SetDOSLocale: %s locale (CP%d, %s) -- created AUTOEXEC.BAT and FDCONFIG.SYS", KB_UPPER, cp, egadrv);
    return TRUE;
}
