#pragma once

#include <windows.h>
#include <filesystem>
#include <expected>
#include <format>

namespace fs = std::filesystem;

typedef struct _LOAD_ERROR {
	const std::string message;
	const DWORD code;
} PE_LOAD_ERROR;

template <class T>
using pe_load_result_t = std::expected<T, PE_LOAD_ERROR>;

template <class ...Ts>
std::unexpected<PE_LOAD_ERROR> generic_error(const std::format_string<Ts...> fmt, Ts&&...args) noexcept {
	return std::unexpected(PE_LOAD_ERROR{
		.message = std::format(fmt, std::forward<Ts>(args)...),
		.code = GetLastError()
	});
}

typedef struct _PE_IMAGE {
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS nt;
} PE_IMAGE;

// Load PE structures from a file. 
pe_load_result_t<PE_IMAGE> load_pe_image(const char* path) noexcept {
	FILE* handle;
	if (fopen_s(&handle, path, "r") != 0) {
		return generic_error("Could not open the file {}", path);
	}
	
	if (handle == NULL) {
		return generic_error("Could not open the file {}", path);
	}

	const auto file_size = fs::file_size(path);
	std::uint8_t* buffer = new std::uint8_t[file_size];
	auto total_bytes_read = std::size_t(0);
	if ((total_bytes_read = fread_s(
		buffer,
		file_size,
		sizeof std::uint8_t,
		file_size,
		handle)) != file_size) 
	{
		if (!feof(handle)) {
			return generic_error("Failed to read the entire file. ({} <= {})", total_bytes_read, file_size);
		}
	}

	PE_IMAGE image = {};
	image.dos = *(IMAGE_DOS_HEADER*)buffer;

	// NOTE: This check happens here to avoid the below pointer arithmetic with garbage values.
	if (image.dos.e_magic != IMAGE_DOS_SIGNATURE) {
		delete[] buffer;
		return generic_error("That is not a valid PE file. (The magic value does not match ({} != {}))", IMAGE_DOS_SIGNATURE, image.dos.e_magic);
	}

	image.nt = *(IMAGE_NT_HEADERS*)(buffer + image.dos.e_lfanew);

	delete[] buffer;

	return image;
}

typedef struct _PTR_TO_PE_IMAGE {
	IMAGE_DOS_HEADER* dos;
	IMAGE_NT_HEADERS* nt;
} PPE_IMAGE;

struct pe_struct_adapter {
private:
	IMAGE_DOS_HEADER* _Dos;
	IMAGE_NT_HEADERS* _Nt;
public:
	pe_struct_adapter() = delete;
	pe_struct_adapter(PE_IMAGE& image) noexcept
		: _Dos(&image.dos)
		, _Nt(&image.nt)
	{}
	pe_struct_adapter(PPE_IMAGE& image) noexcept
		: _Dos(image.dos)
		, _Nt(image.nt)
	{}

	IMAGE_DOS_HEADER* dos() noexcept { return _Dos; }
	IMAGE_NT_HEADERS* nt() noexcept { return _Nt; }
};

// Load PE structures from bytes.
// NOTE: The returned structure's pointer pointer directly into bImage.
pe_load_result_t<PPE_IMAGE> load_pe_image_mem(PBYTE bImage) {
	IMAGE_DOS_HEADER* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(bImage);

	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		return generic_error("Those are not correct PE file bytes. (e_magic is not correct)");
	}

	IMAGE_NT_HEADERS* nt_offset = 
		reinterpret_cast<PIMAGE_NT_HEADERS>(bImage + dos->e_lfanew);

	if (nt_offset->Signature != IMAGE_NT_SIGNATURE) {
		return generic_error("Those are not correct PE/NT file bytes. (signature is incorrect)");
	}

	return PPE_IMAGE {
		.dos = dos,
		.nt = nt_offset
	};
}

PIMAGE_DATA_DIRECTORY get_nt_data_directory(pe_struct_adapter pe, DWORD idx) {
	return &pe.nt()->OptionalHeader.DataDirectory[idx];
}

// Hook the IAT of executable base. The module sModule's sFunction will be replaced with pTarget
LPVOID hook_iat(PBYTE base, LPCSTR sModule, LPCSTR sFunction, LPCVOID pTarget) {
	// IGNORE: this warning is retarded, also the two values are 16 bytes in total, fuck a reference
	auto [pe, nt] = load_pe_image_mem(base).value();

	PIMAGE_DATA_DIRECTORY importsDirectory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory->VirtualAddress + (DWORD_PTR)base);

	LPCSTR libName = NULL;
	HMODULE libHandle = NULL;
	PIMAGE_IMPORT_BY_NAME funcName = NULL;

	LPVOID originalFunc = NULL;

	while (descriptor->Name != NULL) {
		libName = reinterpret_cast<DWORD_PTR>(base) 
			+ reinterpret_cast<LPCSTR>(descriptor->Name);
		libHandle = LoadLibraryA(libName);

		if (libHandle) {
			PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
			originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)base + descriptor->OriginalFirstThunk);
			firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)base + descriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData != NULL)
			{
				funcName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)base + originalFirstThunk->u1.AddressOfData);

				// Does the current function name match the requested one?
				if (std::string(funcName->Name).compare(sFunction) == 0)
				{
					SIZE_T bytesWritten = 0;
					DWORD oldProtect = 0;
					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);

					originalFunc = (LPVOID)firstThunk->u1.Function;
					std::println(" [!] {}!{} original address 0x{:x}", sModule, sFunction, (std::uintptr_t)originalFunc);
					firstThunk->u1.Function = (DWORD_PTR)pTarget;
					std::println(" [!] {}!{} patched to 0x{:x}", sModule, sFunction, (std::uintptr_t)pTarget);
				}
				++originalFirstThunk;
				++firstThunk;
			}
		}

		descriptor++;
	}

	return originalFunc;
}