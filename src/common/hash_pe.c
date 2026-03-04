/*
 * common/hash_pe.c — Portable PE image region collection and PE256 hash
 *
 * This file is designed to be #included by platform-specific hash.c files,
 * after common/hash_algos.c has been included (sha256_init/write/final
 * are required).
 *
 * Provides:
 *   struct image_region
 *   struct efi_image_regions
 *   efi_image_region_add()     (static)
 *   cmp_pe_section()           (static)
 *   efi_image_parse()
 *   PE256Buffer()
 *
 * Extracted from windows/hash.c and linux/hash.c — same logic on both
 * platforms; no Windows API calls in this file.
 *
 * Copyright © 2015-2025 Pete Batard <pete@akeo.ie>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* A part of an image, used for hashing */
struct image_region {
	const uint8_t *data;
	uint32_t       size;
};

/**
 * struct efi_image_regions - A list of memory regions
 * @max:  Maximum number of regions
 * @num:  Number of regions
 * @reg:  Array of regions (flexible array member)
 */
struct efi_image_regions {
	int                 max;
	int                 num;
	struct image_region reg[];
};

/**
 * efi_image_region_add() - add an entry of region
 * @regs:    Pointer to array of regions
 * @start:   Start address of region (included)
 * @end:     End address of region (excluded)
 * @nocheck: If nonzero, allow overlapping regions (insertion order)
 *
 * Returns TRUE on success, FALSE on error.
 */
static BOOL efi_image_region_add(struct efi_image_regions *regs,
	const void *start, const void *end, int nocheck)
{
	struct image_region *reg;
	int i, j;

	if (regs->num >= regs->max) {
		uprintf("%s: no more room for regions", __func__);
		return FALSE;
	}

	if (end < start)
		return FALSE;

	for (i = 0; i < regs->num; i++) {
		reg = &regs->reg[i];
		if (nocheck)
			continue;

		/* new data after registered region */
		if ((uint8_t *)start >= reg->data + reg->size)
			continue;

		/* new data preceding registered region */
		if ((uint8_t *)end <= reg->data) {
			for (j = regs->num - 1; j >= i; j--)
				memcpy(&regs->reg[j + 1], &regs->reg[j], sizeof(*reg));
			break;
		}

		/* new data overlapping registered region */
		uprintf("%s: new region already part of another", __func__);
		return FALSE;
	}

	reg = &regs->reg[i];
	reg->data = start;
	reg->size = (uint32_t)((uintptr_t)end - (uintptr_t)start);
	regs->num++;

	return TRUE;
}

/**
 * cmp_pe_section() - compare virtual addresses of two PE image sections
 *
 * Used as comparator for qsort(); args are (IMAGE_SECTION_HEADER **).
 */
static int cmp_pe_section(const void *arg1, const void *arg2)
{
	const IMAGE_SECTION_HEADER *s1 = *((const IMAGE_SECTION_HEADER **)arg1);
	const IMAGE_SECTION_HEADER *s2 = *((const IMAGE_SECTION_HEADER **)arg2);

	if (s1->VirtualAddress < s2->VirtualAddress) return -1;
	if (s1->VirtualAddress == s2->VirtualAddress) return 0;
	return 1;
}

/**
 * efi_image_parse() - parse a PE image and collect regions for Authenticode hashing
 * @efi:   Pointer to image
 * @len:   Size of @efi in bytes
 * @regp:  Out: allocated list of regions (caller must free(*regp))
 *
 * Parses a PE32 or PE32+ binary.  Returns TRUE on success, FALSE on error.
 */
BOOL efi_image_parse(uint8_t *efi, size_t len, struct efi_image_regions **regp)
{
	struct efi_image_regions *regs;
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS32 *nt;
	IMAGE_SECTION_HEADER *sections, **sorted;
	int num_regions, num_sections, i;
	DWORD ctidx = IMAGE_DIRECTORY_ENTRY_SECURITY;
	uint32_t align, size, authsz;
	size_t bytes_hashed;

	if (len < 0x80)
		return FALSE;
	dos = (void *)efi;
	if (dos->e_lfanew > (LONG)len - 0x40)
		return FALSE;
	nt = (void *)(efi + dos->e_lfanew);
	authsz = 0;

	/* Count max regions: header fields + sections + optional trailing */
	num_regions = 3 + nt->FileHeader.NumberOfSections + 1;
	regs = calloc(sizeof(*regs) + sizeof(struct image_region) * num_regions, 1);
	if (!regs)
		return FALSE;
	regs->max = num_regions;

	if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		IMAGE_NT_HEADERS64 *nt64 = (void *)nt;
		IMAGE_OPTIONAL_HEADER64 *opt = &nt64->OptionalHeader;

		efi_image_region_add(regs, efi, &opt->CheckSum, 0);
		if (nt64->OptionalHeader.NumberOfRvaAndSizes <= ctidx) {
			efi_image_region_add(regs, &opt->Subsystem, efi + opt->SizeOfHeaders, 0);
		} else {
			efi_image_region_add(regs, &opt->Subsystem, &opt->DataDirectory[ctidx], 0);
			efi_image_region_add(regs, &opt->DataDirectory[ctidx] + 1, efi + opt->SizeOfHeaders, 0);
			authsz = opt->DataDirectory[ctidx].Size;
		}
		bytes_hashed = opt->SizeOfHeaders;
		align = opt->FileAlignment;
	} else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		IMAGE_OPTIONAL_HEADER32 *opt = &nt->OptionalHeader;

		efi_image_region_add(regs, efi, &opt->CheckSum, 0);
		if (nt->OptionalHeader.NumberOfRvaAndSizes <= ctidx) {
			efi_image_region_add(regs, &opt->Subsystem, efi + opt->SizeOfHeaders, 0);
		} else {
			efi_image_region_add(regs, &opt->Subsystem, &opt->DataDirectory[ctidx], 0);
			efi_image_region_add(regs, &opt->DataDirectory[ctidx] + 1, efi + opt->SizeOfHeaders, 0);
			authsz = opt->DataDirectory[ctidx].Size;
		}
		bytes_hashed = opt->SizeOfHeaders;
		align = opt->FileAlignment;
	} else {
		uprintf("%s: invalid optional header magic %x", __func__,
		        nt->OptionalHeader.Magic);
		free(regs);
		return FALSE;
	}

	num_sections = nt->FileHeader.NumberOfSections;
	sections = (void *)((uint8_t *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
	sorted = calloc(num_sections, sizeof(IMAGE_SECTION_HEADER *));
	if (!sorted) {
		free(regs);
		return FALSE;
	}
	for (i = 0; i < num_sections; i++)
		sorted[i] = &sections[i];
	qsort(sorted, num_sections, sizeof(sorted[0]), cmp_pe_section);
	for (i = 0; i < num_sections; i++) {
		if (!sorted[i]->SizeOfRawData)
			continue;
		size = (sorted[i]->SizeOfRawData + align - 1) & ~(align - 1);
		efi_image_region_add(regs,
			efi + sorted[i]->PointerToRawData,
			efi + sorted[i]->PointerToRawData + size, 0);
		bytes_hashed += size;
	}
	free(sorted);

	if (bytes_hashed + authsz < len)
		efi_image_region_add(regs, efi + bytes_hashed, efi + len - authsz, 0);

	*regp = regs;
	return TRUE;
}

/**
 * PE256Buffer() - compute the PE256 (Authenticode SHA-256) hash of a PE image buffer
 * @buf:  Pointer to PE binary
 * @len:  Size in bytes
 * @hash: Output buffer (SHA256_HASHSIZE bytes)
 *
 * Returns TRUE on success, FALSE on error.
 */
BOOL PE256Buffer(uint8_t *buf, uint32_t len, uint8_t *hash)
{
	BOOL r = FALSE;
	HASH_CONTEXT hash_ctx = { {0} };
	int i;
	struct efi_image_regions *regs = NULL;

	if (buf == NULL || len == 0 || len < 1 * KB || len > 64 * MB || hash == NULL)
		goto out;
	if (!efi_image_parse(buf, len, &regs))
		goto out;

	sha256_init(&hash_ctx);
	for (i = 0; i < regs->num; i++)
		sha256_write(&hash_ctx, regs->reg[i].data, regs->reg[i].size);
	sha256_final(&hash_ctx);
	memcpy(hash, hash_ctx.buf, SHA256_HASHSIZE);
	r = TRUE;

out:
	free(regs);
	return r;
}
